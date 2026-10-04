"""
لایه‌ی تعامل با AmneziaWG:
- تولید کلید
- اضافه/حذف peer به‌صورت زنده (بدون قطع شدن peer های دیگه)
- خوندن آمار ترافیک و آخرین handshake
- persist کردن تغییرات روی فایل کانفیگ (تا بعد از ری‌استارت هم بمونه)
"""
import subprocess
import tempfile
import os
from pathlib import Path
from . import config


def _run(cmd: list, input_text: str = None) -> str:
    result = subprocess.run(
        cmd,
        input=input_text.encode() if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\n{result.stderr.decode(errors='ignore')}"
        )
    return result.stdout.decode().strip()


def genkey() -> str:
    return _run(["awg", "genkey"])


def pubkey(private_key: str) -> str:
    return _run(["awg", "pubkey"], input_text=private_key + "\n")


def genpsk() -> str:
    return _run(["awg", "genpsk"])


def add_peer_live(public_key: str, preshared_key: str, ip_address: str, ipv6_address: str = None):
    allowed_ips = f"{ip_address}/32"
    if ipv6_address:
        allowed_ips += f",{ipv6_address}/128"
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(preshared_key + "\n")
        psk_path = f.name
    try:
        _run(
            [
                "awg",
                "set",
                config.INTERFACE,
                "peer",
                public_key,
                "preshared-key",
                psk_path,
                "allowed-ips",
                allowed_ips,
            ]
        )
    finally:
        os.unlink(psk_path)


def remove_peer_live(public_key: str):
    try:
        _run(["awg", "set", config.INTERFACE, "peer", public_key, "remove"])
    except RuntimeError:
        # اگه از قبل روی اینترفیس نبود، مشکلی نیست
        pass


def dump() -> dict:
    """
    خروجی `awg show <iface> dump` رو پارس می‌کنه.
    خط اول: اطلاعات خود اینترفیس
    خطوط بعدی: هر پیر یک خط
    برمی‌گردونه: { public_key: {endpoint, allowed_ips, latest_handshake, rx, tx, keepalive} }
    """
    try:
        raw = _run(["awg", "show", config.INTERFACE, "dump"])
    except RuntimeError:
        return {}

    lines = raw.splitlines()
    peers = {}
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = parts[:8]
        peers[pub] = {
            "endpoint": endpoint,
            "allowed_ips": allowed_ips,
            "latest_handshake": int(handshake) if handshake.isdigit() else 0,
            "rx": int(rx) if rx.isdigit() else 0,
            "tx": int(tx) if tx.isdigit() else 0,
        }
    return peers


def sync_conf_from_file():
    """بعد از تغییر فایل conf، اینترفیس زنده رو بدون قطعی sync می‌کنه"""
    stripped = _run(["awg-quick", "strip", str(config.WG_CONF_PATH)])
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as f:
        f.write(stripped)
        tmp_path = f.name
    try:
        _run(["awg", "syncconf", config.INTERFACE, tmp_path])
    finally:
        os.unlink(tmp_path)


def append_peer_to_conf(public_key: str, preshared_key: str, ip_address: str, name: str, ipv6_address: str = None):
    allowed_ips = f"{ip_address}/32"
    if ipv6_address:
        allowed_ips += f", {ipv6_address}/128"
    block = (
        f"\n# peer: {name}\n"
        f"[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"PresharedKey = {preshared_key}\n"
        f"AllowedIPs = {allowed_ips}\n"
    )
    with open(config.WG_CONF_PATH, "a") as f:
        f.write(block)


def remove_peer_from_conf(public_key: str):
    text = Path(config.WG_CONF_PATH).read_text()
    blocks = text.split("\n[Peer]\n")
    header = blocks[0]
    new_blocks = [header]
    for b in blocks[1:]:
        if f"PublicKey = {public_key}\n" in b:
            continue
        new_blocks.append(b)
    Path(config.WG_CONF_PATH).write_text("\n[Peer]\n".join(new_blocks))


def build_client_config(
    client_private_key: str,
    client_ip: str,
    preshared_key: str,
    client_ipv6: str = None,
) -> str:
    address_line = f"{client_ip}/32"
    if client_ipv6:
        address_line += f", {client_ipv6}/128"
    return f"""[Interface]
PrivateKey = {client_private_key}
Address = {address_line}
DNS = {config.DNS_SERVERS}
MTU = {config.CLIENT_MTU}
Jc = {config.AWG_JC}
Jmin = {config.AWG_JMIN}
Jmax = {config.AWG_JMAX}
S1 = {config.AWG_S1}
S2 = {config.AWG_S2}
H1 = {config.AWG_H1}
H2 = {config.AWG_H2}
H3 = {config.AWG_H3}
H4 = {config.AWG_H4}

[Peer]
PublicKey = {config.SERVER_PUBLIC_KEY}
PresharedKey = {preshared_key}
Endpoint = {config.SERVER_ENDPOINT}:{config.SERVER_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
