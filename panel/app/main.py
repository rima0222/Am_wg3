import asyncio
import ipaddress
import qrcode
import io
import time
import psutil
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Body, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from . import config, database, awg, auth

app = FastAPI(title="AmneziaWG Panel")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# brute-force protection for login endpoints (in-memory, per-IP)
# ============================================================
_login_attempts: dict = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300    # 5 minutes to accumulate failures
LOGIN_BLOCK_SECONDS = 900     # 15 minute lockout once tripped


def _client_key(prefix: str, request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{prefix}:{ip}"


def _check_rate_limit(key: str):
    now = time.time()
    entry = _login_attempts.get(key)
    if entry and entry.get("blocked_until", 0) > now:
        retry_after = int(entry["blocked_until"] - now)
        raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {retry_after}s.")


def _record_failure(key: str):
    now = time.time()
    entry = _login_attempts.get(key)
    if not entry or now - entry["first"] > LOGIN_WINDOW_SECONDS:
        entry = {"count": 0, "first": now}
    entry["count"] += 1
    if entry["count"] >= LOGIN_MAX_ATTEMPTS:
        entry["blocked_until"] = now + LOGIN_BLOCK_SECONDS
    _login_attempts[key] = entry


def _record_success(key: str):
    _login_attempts.pop(key, None)


def _cleanup_rate_limits():
    now = time.time()
    stale = [
        k
        for k, v in _login_attempts.items()
        if now - v["first"] > LOGIN_WINDOW_SECONDS and v.get("blocked_until", 0) < now
    ]
    for k in stale:
        _login_attempts.pop(k, None)


# ============================================================
# schemas
# ============================================================
class LoginRequest(BaseModel):
    username: str
    password: str


class PortalLoginRequest(BaseModel):
    username: str
    password: str


class CreatePeerRequest(BaseModel):
    name: str
    note: Optional[str] = ""
    expires_at: Optional[int] = None       # unix timestamp, or None
    data_limit_gb: Optional[float] = None  # None = unlimited
    duration_days: Optional[int] = None    # used by "reset" to recompute expiry


class UpdatePeerRequest(BaseModel):
    enabled: Optional[bool] = None
    note: Optional[str] = None
    expires_at: Optional[int] = None
    data_limit_gb: Optional[float] = None


class AdjustPeerRequest(BaseModel):
    add_gb: Optional[float] = None   # can be negative to subtract
    add_days: Optional[int] = None   # can be negative to subtract


class AdminCredentialsRequest(BaseModel):
    current_password: str
    new_username: Optional[str] = None
    new_password: Optional[str] = None


# ============================================================
# startup
# ============================================================
@app.on_event("startup")
async def startup():
    database.init_db()
    asyncio.create_task(stats_loop())
    asyncio.create_task(enforcement_loop())


def _subnet_base() -> str:
    net = ipaddress.ip_network(config.SERVER_SUBNET, strict=False)
    parts = str(net.network_address).split(".")
    return ".".join(parts[:3])


def _derive_ipv6(ipv4_address: str) -> Optional[str]:
    """Derives a matching IPv6 address in the server's ULA range from the
    IPv4 host octet, e.g. 10.29.29.42 -> fd42:29:29::2a. Returns None if
    IPv6 wasn't enabled at install time (no native uplink detected)."""
    if not config.ENABLE_IPV6:
        return None
    host_octet = int(ipv4_address.split(".")[-1])
    base_net = config.SERVER_SUBNET6.split("/")[0]
    return f"{base_net}{format(host_octet, 'x')}"


def _get_admin_row():
    with database.cursor() as cur:
        cur.execute("SELECT * FROM admin WHERE id=1")
        return cur.fetchone()


# ============================================================
# admin auth
# ============================================================
@app.post("/api/login")
def login(body: LoginRequest, request: Request):
    key = _client_key("admin", request)
    _check_rate_limit(key)
    row = _get_admin_row()
    if not row or body.username != row["username"] or not auth.verify_password(
        body.password, row["password_hash"]
    ):
        _record_failure(key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    _record_success(key)
    return {"token": auth.create_admin_token(row["username"])}


@app.put("/api/admin/credentials")
def update_admin_credentials(body: AdminCredentialsRequest, _=Depends(auth.require_admin)):
    row = _get_admin_row()
    if not row or not auth.verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    new_username = body.new_username.strip() if body.new_username else row["username"]
    new_hash = auth.hash_password(body.new_password) if body.new_password else row["password_hash"]

    with database.cursor() as cur:
        cur.execute(
            "UPDATE admin SET username=?, password_hash=? WHERE id=1",
            (new_username, new_hash),
        )
    return {"ok": True, "username": new_username}


# ============================================================
# peers (admin)
# ============================================================
@app.get("/api/peers")
def list_peers(_=Depends(auth.require_admin)):
    live = awg.dump()
    now = database.now()
    result = []
    with database.cursor() as cur:
        cur.execute(
            """SELECT p.*, s.cumulative_rx, s.cumulative_tx, s.last_handshake
               FROM peers p LEFT JOIN peer_stats s ON s.peer_id = p.id
               ORDER BY p.created_at DESC"""
        )
        for row in cur.fetchall():
            live_info = live.get(row["public_key"], {})
            last_handshake = live_info.get("latest_handshake") or row["last_handshake"] or 0
            online = bool(last_handshake) and (now - last_handshake) < config.ONLINE_THRESHOLD_SECONDS
            result.append(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "ip_address": row["ip_address"],
                    "ipv6_address": row["ipv6_address"],
                    "note": row["note"],
                    "enabled": bool(row["enabled"]),
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                    "duration_days": row["duration_days"],
                    "data_limit_bytes": row["data_limit_bytes"],
                    "used_bytes": (row["cumulative_rx"] or 0) + (row["cumulative_tx"] or 0),
                    "rx_bytes": row["cumulative_rx"] or 0,
                    "tx_bytes": row["cumulative_tx"] or 0,
                    "last_handshake": last_handshake,
                    "online": online,
                    "portal_username": row["portal_username"],
                }
            )
    return result


@app.post("/api/peers")
def create_peer(body: CreatePeerRequest, _=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT ip_address FROM peers")
        used_ips = {r["ip_address"] for r in cur.fetchall()}

    ip_address = database.next_free_ip(_subnet_base(), used_ips)
    ipv6_address = _derive_ipv6(ip_address)
    private_key = awg.genkey()
    public_key = awg.pubkey(private_key)
    preshared_key = awg.genpsk()
    data_limit_bytes = int(body.data_limit_gb * 1024**3) if body.data_limit_gb else None

    portal_username = auth.random_username()
    portal_password = auth.random_password()
    portal_password_hash = auth.hash_password(portal_password)

    with database.cursor() as cur:
        cur.execute(
            """INSERT INTO peers
               (name, public_key, private_key, preshared_key, ip_address, ipv6_address, note,
                enabled, created_at, expires_at, data_limit_bytes, duration_days,
                portal_username, portal_password_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
            (
                body.name,
                public_key,
                private_key,
                preshared_key,
                ip_address,
                ipv6_address,
                body.note or "",
                database.now(),
                body.expires_at,
                data_limit_bytes,
                body.duration_days,
                portal_username,
                portal_password_hash,
            ),
        )
        peer_id = cur.lastrowid
        cur.execute("INSERT INTO peer_stats (peer_id) VALUES (?)", (peer_id,))

    awg.add_peer_live(public_key, preshared_key, ip_address, ipv6_address)
    awg.append_peer_to_conf(public_key, preshared_key, ip_address, body.name, ipv6_address)

    client_conf = awg.build_client_config(private_key, ip_address, preshared_key, ipv6_address)
    return {
        "id": peer_id,
        "ip_address": ip_address,
        "ipv6_address": ipv6_address,
        "config": client_conf,
        "portal_username": portal_username,
        "portal_password": portal_password,  # shown once, plaintext
    }


@app.put("/api/peers/{peer_id}")
def update_peer(peer_id: int, body: UpdatePeerRequest, _=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")

        new_enabled = row["enabled"] if body.enabled is None else int(body.enabled)
        new_note = row["note"] if body.note is None else body.note
        new_expires = row["expires_at"] if body.expires_at is None else body.expires_at
        new_limit = (
            row["data_limit_bytes"]
            if body.data_limit_gb is None
            else int(body.data_limit_gb * 1024**3)
        )

        cur.execute(
            """UPDATE peers SET enabled=?, note=?, expires_at=?, data_limit_bytes=? WHERE id=?""",
            (new_enabled, new_note, new_expires, new_limit, peer_id),
        )

    if body.enabled is True:
        awg.add_peer_live(row["public_key"], row["preshared_key"], row["ip_address"], row["ipv6_address"])
    elif body.enabled is False:
        awg.remove_peer_live(row["public_key"])

    return {"ok": True}


@app.post("/api/peers/{peer_id}/reset")
def reset_peer(peer_id: int, _=Depends(auth.require_admin)):
    """Resets usage counters to zero and, if a duration_days was set, restarts the expiry period."""
    live = awg.dump()
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")

        live_info = live.get(row["public_key"], {})
        new_expires = row["expires_at"]
        if row["duration_days"]:
            new_expires = database.now() + row["duration_days"] * 86400

        cur.execute(
            """UPDATE peer_stats SET cumulative_rx=0, cumulative_tx=0, last_rx=?, last_tx=?
               WHERE peer_id=?""",
            (live_info.get("rx", 0), live_info.get("tx", 0), peer_id),
        )
        cur.execute("UPDATE peers SET enabled=1, expires_at=? WHERE id=?", (new_expires, peer_id))

    awg.add_peer_live(row["public_key"], row["preshared_key"], row["ip_address"], row["ipv6_address"])
    return {"ok": True, "expires_at": new_expires}


@app.post("/api/peers/{peer_id}/adjust")
def adjust_peer(peer_id: int, body: AdjustPeerRequest, _=Depends(auth.require_admin)):
    """Adds or subtracts GB / days from a user's plan (negative values subtract)."""
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")

        new_limit = row["data_limit_bytes"]
        if body.add_gb is not None:
            base = new_limit or 0
            new_limit = max(0, base + int(body.add_gb * 1024**3))

        new_expires = row["expires_at"]
        if body.add_days is not None:
            base = new_expires or database.now()
            new_expires = base + body.add_days * 86400

        cur.execute(
            "UPDATE peers SET data_limit_bytes=?, expires_at=? WHERE id=?",
            (new_limit, new_expires, peer_id),
        )

        cur.execute(
            """SELECT p.*, s.cumulative_rx, s.cumulative_tx FROM peers p
               JOIN peer_stats s ON s.peer_id = p.id WHERE p.id=?""",
            (peer_id,),
        )
        row2 = cur.fetchone()

        now = database.now()
        used = (row2["cumulative_rx"] or 0) + (row2["cumulative_tx"] or 0)
        still_expired = row2["expires_at"] and now > row2["expires_at"]
        still_over = row2["data_limit_bytes"] and used > row2["data_limit_bytes"]
        needs_reactivate = not row2["enabled"] and not still_expired and not still_over
        if needs_reactivate:
            cur.execute("UPDATE peers SET enabled=1 WHERE id=?", (peer_id,))

    if needs_reactivate:
        awg.add_peer_live(row2["public_key"], row2["preshared_key"], row2["ip_address"], row2["ipv6_address"])

    return {"ok": True, "data_limit_bytes": new_limit, "expires_at": new_expires}


@app.post("/api/peers/{peer_id}/portal-credentials/regenerate")
def regenerate_portal_credentials(peer_id: int, _=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT id FROM peers WHERE id=?", (peer_id,))
        if not cur.fetchone():
            raise HTTPException(404, "User not found")
        new_username = auth.random_username()
        new_password = auth.random_password()
        cur.execute(
            "UPDATE peers SET portal_username=?, portal_password_hash=? WHERE id=?",
            (new_username, auth.hash_password(new_password), peer_id),
        )
    return {"portal_username": new_username, "portal_password": new_password}


@app.delete("/api/peers/{peer_id}")
def delete_peer(peer_id: int, _=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        cur.execute("DELETE FROM peers WHERE id=?", (peer_id,))
        cur.execute("DELETE FROM peer_stats WHERE peer_id=?", (peer_id,))

    awg.remove_peer_live(row["public_key"])
    awg.remove_peer_from_conf(row["public_key"])
    return {"ok": True}


@app.get("/api/peers/{peer_id}/config", response_class=PlainTextResponse)
def get_peer_config(peer_id: int, _=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")
    return awg.build_client_config(row["private_key"], row["ip_address"], row["preshared_key"], row["ipv6_address"])


@app.get("/api/peers/{peer_id}/qr")
def get_peer_qr(peer_id: int, _=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")
    conf = awg.build_client_config(row["private_key"], row["ip_address"], row["preshared_key"], row["ipv6_address"])
    img = qrcode.make(conf)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/system")
def system_info(_=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT COUNT(*) c FROM peers")
        total = cur.fetchone()["c"]
        cur.execute("SELECT COALESCE(SUM(cumulative_rx+cumulative_tx),0) t FROM peer_stats")
        total_traffic = cur.fetchone()["t"]

    live = awg.dump()
    now = database.now()
    online = sum(
        1
        for v in live.values()
        if v.get("latest_handshake") and (now - v["latest_handshake"]) < config.ONLINE_THRESHOLD_SECONDS
    )

    mem = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent(interval=0.2)

    return {
        "endpoint": config.SERVER_ENDPOINT,
        "ipv6_enabled": config.ENABLE_IPV6,
        "port": config.SERVER_PORT,
        "interface": config.INTERFACE,
        "total_peers": total,
        "online_peers": online,
        "total_traffic_bytes": total_traffic,
        "cpu_percent": cpu_percent,
        "ram_percent": mem.percent,
        "ram_used_bytes": mem.used,
        "ram_total_bytes": mem.total,
    }


# ============================================================
# backup / restore
# ============================================================
@app.get("/api/backup")
def create_backup(_=Depends(auth.require_admin)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers")
        peers = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM peer_stats")
        stats_by_id = {r["peer_id"]: dict(r) for r in cur.fetchall()}

    admin_row = _get_admin_row()

    for p in peers:
        s = stats_by_id.get(p["id"], {})
        p["cumulative_rx"] = s.get("cumulative_rx", 0)
        p["cumulative_tx"] = s.get("cumulative_tx", 0)

    return {
        "version": 1,
        "exported_at": database.now(),
        "admin": (
            {"username": admin_row["username"], "password_hash": admin_row["password_hash"]}
            if admin_row
            else None
        ),
        "peers": peers,
    }


@app.post("/api/backup/restore")
def restore_backup(
    payload: dict = Body(...),
    restore_admin: bool = False,
    _=Depends(auth.require_admin),
):
    peers = payload.get("peers", [])
    imported, skipped = 0, 0

    with database.cursor() as cur:
        cur.execute("SELECT public_key FROM peers")
        existing_keys = {r["public_key"] for r in cur.fetchall()}
        cur.execute("SELECT ip_address FROM peers")
        used_ips = {r["ip_address"] for r in cur.fetchall()}

        for p in peers:
            pub = p.get("public_key")
            if not pub or pub in existing_keys:
                skipped += 1
                continue

            ip_address = p.get("ip_address")
            if not ip_address or ip_address in used_ips:
                ip_address = database.next_free_ip(_subnet_base(), used_ips)
            used_ips.add(ip_address)
            existing_keys.add(pub)
            # recompute IPv6 from this server's own subnet rather than trusting
            # the source server's value (it may run a different IPv6 range,
            # or not have IPv6 enabled at all)
            ipv6_address = _derive_ipv6(ip_address)

            cur.execute(
                """INSERT INTO peers
                   (name, public_key, private_key, preshared_key, ip_address, ipv6_address, note,
                    enabled, created_at, expires_at, data_limit_bytes, duration_days,
                    portal_username, portal_password_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    p.get("name", "restored"),
                    pub,
                    p.get("private_key"),
                    p.get("preshared_key"),
                    ip_address,
                    ipv6_address,
                    p.get("note", ""),
                    1 if p.get("enabled", True) else 0,
                    p.get("created_at", database.now()),
                    p.get("expires_at"),
                    p.get("data_limit_bytes"),
                    p.get("duration_days"),
                    p.get("portal_username"),
                    p.get("portal_password_hash"),
                ),
            )
            new_id = cur.lastrowid
            cur.execute(
                "INSERT INTO peer_stats (peer_id, cumulative_rx, cumulative_tx) VALUES (?, ?, ?)",
                (new_id, p.get("cumulative_rx", 0), p.get("cumulative_tx", 0)),
            )
            awg.add_peer_live(pub, p.get("preshared_key"), ip_address, ipv6_address)
            awg.append_peer_to_conf(pub, p.get("preshared_key"), ip_address, p.get("name", "restored"), ipv6_address)
            imported += 1

        if restore_admin and payload.get("admin"):
            a = payload["admin"]
            cur.execute(
                "UPDATE admin SET username=?, password_hash=? WHERE id=1",
                (a["username"], a["password_hash"]),
            )

    return {"ok": True, "imported": imported, "skipped": skipped}


# ============================================================
# self-service portal (peer-scoped, separate from admin auth)
# ============================================================
@app.post("/api/portal/login")
def portal_login(body: PortalLoginRequest, request: Request):
    key = _client_key("portal", request)
    _check_rate_limit(key)
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE portal_username=?", (body.username,))
        row = cur.fetchone()
    if not row or not auth.verify_password(body.password, row["portal_password_hash"] or ""):
        _record_failure(key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    _record_success(key)
    return {"token": auth.create_peer_token(row["id"])}


@app.get("/api/portal/status")
def portal_status(peer_id: int = Depends(auth.require_peer)):
    live = awg.dump()
    with database.cursor() as cur:
        cur.execute(
            """SELECT p.*, s.cumulative_rx, s.cumulative_tx, s.last_handshake
               FROM peers p LEFT JOIN peer_stats s ON s.peer_id = p.id WHERE p.id=?""",
            (peer_id,),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Not found")

    now = database.now()
    live_info = live.get(row["public_key"], {})
    last_handshake = live_info.get("latest_handshake") or row["last_handshake"] or 0
    online = bool(last_handshake) and (now - last_handshake) < config.ONLINE_THRESHOLD_SECONDS
    used = (row["cumulative_rx"] or 0) + (row["cumulative_tx"] or 0)
    remaining_bytes = (row["data_limit_bytes"] - used) if row["data_limit_bytes"] else None
    remaining_days = int((row["expires_at"] - now) / 86400) if row["expires_at"] else None

    return {
        "name": row["name"],
        "ip_address": row["ip_address"],
        "ipv6_address": row["ipv6_address"],
        "enabled": bool(row["enabled"]),
        "online": online,
        "used_bytes": used,
        "data_limit_bytes": row["data_limit_bytes"],
        "remaining_bytes": remaining_bytes,
        "expires_at": row["expires_at"],
        "remaining_days": remaining_days,
        "endpoint": f"{config.SERVER_ENDPOINT}:{config.SERVER_PORT}",
    }


@app.get("/api/portal/config", response_class=PlainTextResponse)
def portal_config(peer_id: int = Depends(auth.require_peer)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    return awg.build_client_config(row["private_key"], row["ip_address"], row["preshared_key"], row["ipv6_address"])


@app.get("/api/portal/qr")
def portal_qr(peer_id: int = Depends(auth.require_peer)):
    with database.cursor() as cur:
        cur.execute("SELECT * FROM peers WHERE id=?", (peer_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    conf = awg.build_client_config(row["private_key"], row["ip_address"], row["preshared_key"], row["ipv6_address"])
    img = qrcode.make(conf)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ============================================================
# background loops
# ============================================================
async def stats_loop():
    while True:
        try:
            live = awg.dump()
            with database.cursor() as cur:
                cur.execute("SELECT id, public_key FROM peers")
                peer_map = {r["public_key"]: r["id"] for r in cur.fetchall()}

                for pubkey, info in live.items():
                    peer_id = peer_map.get(pubkey)
                    if not peer_id:
                        continue
                    cur.execute("SELECT * FROM peer_stats WHERE peer_id=?", (peer_id,))
                    stat = cur.fetchone()
                    if not stat:
                        continue

                    new_rx, new_tx = info["rx"], info["tx"]
                    delta_rx = new_rx if new_rx < stat["last_rx"] else new_rx - stat["last_rx"]
                    delta_tx = new_tx if new_tx < stat["last_tx"] else new_tx - stat["last_tx"]

                    cur.execute(
                        """UPDATE peer_stats SET
                           cumulative_rx = cumulative_rx + ?,
                           cumulative_tx = cumulative_tx + ?,
                           last_rx = ?, last_tx = ?,
                           last_handshake = ?, updated_at = ?
                           WHERE peer_id = ?""",
                        (
                            max(delta_rx, 0),
                            max(delta_tx, 0),
                            new_rx,
                            new_tx,
                            info["latest_handshake"],
                            database.now(),
                            peer_id,
                        ),
                    )
        except Exception as e:
            print(f"[stats_loop] error: {e}")
        await asyncio.sleep(config.STATS_POLL_INTERVAL)


async def enforcement_loop():
    """Removes peers from the live interface once they expire or exceed their data cap."""
    while True:
        try:
            now = database.now()
            with database.cursor() as cur:
                cur.execute(
                    """SELECT p.*, s.cumulative_rx, s.cumulative_tx
                       FROM peers p JOIN peer_stats s ON s.peer_id = p.id
                       WHERE p.enabled = 1"""
                )
                for row in cur.fetchall():
                    expired = row["expires_at"] and now > row["expires_at"]
                    used = (row["cumulative_rx"] or 0) + (row["cumulative_tx"] or 0)
                    over_limit = row["data_limit_bytes"] and used > row["data_limit_bytes"]
                    if expired or over_limit:
                        awg.remove_peer_live(row["public_key"])
                        cur.execute("UPDATE peers SET enabled=0 WHERE id=?", (row["id"],))
            _cleanup_rate_limits()
        except Exception as e:
            print(f"[enforcement_loop] error: {e}")
        await asyncio.sleep(30)


# ============================================================
# static frontend (admin panel + self-service portal)
# ============================================================
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
