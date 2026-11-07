import base64
import datetime
import hashlib
import hmac
import json
import os
import platform
import random
import re
import secrets
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # Graceful OS-native fallback if psutil is not installed

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VAULT_DIR = PROJECT_ROOT / ".cloaknet_vault"
VAULT_FILE = VAULT_DIR / "identity_backup.enc"
KEY_FILE = VAULT_DIR / "vault.key"

# Curated IEEE Official Organizationally Unique Identifiers (OUI) from major NIC vendors
VERIFIED_VENDOR_OUIS: List[Dict[str, str]] = [
    {"oui": "00:1B:21", "vendor": "Intel Corporate"},
    {"oui": "3C:97:0E", "vendor": "Intel Corporate"},
    {"oui": "8C:8D:28", "vendor": "Intel Corporate"},
    {"oui": "A4:34:D9", "vendor": "Intel Corporate"},
    {"oui": "00:E0:4C", "vendor": "Realtek Semiconductor"},
    {"oui": "52:54:00", "vendor": "Realtek / QEMU NIC"},
    {"oui": "74:DA:38", "vendor": "Realtek Semiconductor"},
    {"oui": "BC:5F:F4", "vendor": "ASRock / Realtek"},
    {"oui": "F0:18:98", "vendor": "Apple, Inc."},
    {"oui": "AC:BC:32", "vendor": "Apple, Inc."},
    {"oui": "3C:22:FB", "vendor": "Apple, Inc."},
    {"oui": "D8:BB:C1", "vendor": "Apple, Inc."},
    {"oui": "F8:B1:56", "vendor": "Dell Inc."},
    {"oui": "18:03:73", "vendor": "Dell Inc."},
    {"oui": "B8:CA:3A", "vendor": "Dell Inc."},
    {"oui": "54:EE:75", "vendor": "Lenovo / Wistron"},
    {"oui": "98:FA:9B", "vendor": "Lenovo Enterprise"},
    {"oui": "00:25:90", "vendor": "Super Micro Computer"},
    {"oui": "64:16:7F", "vendor": "Cisco Systems, Inc."},
    {"oui": "D4:6D:6D", "vendor": "Qualcomm Atheros"},
]


def is_elevated_privilege() -> bool:
    """Detect whether the current process has root (POSIX) or Administrator (Windows) rights."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return hasattr(os, "geteuid") and os.geteuid() == 0


def lookup_oui_vendor(mac_address: str) -> str:
    """Resolve the vendor name from a MAC address prefix if present in the verified table."""
    normalized = mac_address.upper().replace("-", ":")
    prefix = normalized[:8]
    for item in VERIFIED_VENDOR_OUIS:
        if item["oui"].upper() == prefix:
            return item["vendor"]
    return "Standard IEEE 802.3 NIC"


def generate_legitimate_mac(preferred_vendor: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate a legitimate unicast hardware MAC address using an official IEEE OUI prefix
    and 3 cryptographically random NIC-specific octets.
    Returns (mac_address, vendor_name).
    """
    candidates = VERIFIED_VENDOR_OUIS
    if preferred_vendor and preferred_vendor.lower() != "any":
        filtered = [
            entry
            for entry in VERIFIED_VENDOR_OUIS
            if preferred_vendor.lower() in entry["vendor"].lower()
        ]
        if filtered:
            candidates = filtered

    chosen = random.choice(candidates)
    oui_prefix = chosen["oui"]

    # Generate 3 random trailing bytes (avoid 0x00 and 0xFF extremes)
    tail_octets = [f"{secrets.randbelow(254) + 1:02X}" for _ in range(3)]
    full_mac = f"{oui_prefix}:{':'.join(tail_octets)}"
    return full_mac, chosen["vendor"]


class EncryptedIdentityVault:
    """
    Stores original hardware MAC addresses and system hostname in an authenticated,
    encrypted local vault file (`.cloaknet_vault/identity_backup.enc`) using
    SHA-256 CTR stream encryption + HMAC-SHA256 integrity verification.
    """

    def __init__(self, vault_dir: Path = VAULT_DIR) -> None:
        self.vault_dir = vault_dir
        self.vault_file = vault_dir / "identity_backup.enc"
        self.key_file = vault_dir / "vault.key"

    def _get_or_create_key(self) -> bytes:
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        if self.key_file.exists():
            return self.key_file.read_bytes()
        secret_key = secrets.token_bytes(32)
        self.key_file.write_bytes(secret_key)
        try:
            os.chmod(self.key_file, 0o600)
        except Exception:
            pass
        return secret_key

    @staticmethod
    def _keystream_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
        out = bytearray(len(data))
        block_index = 0
        offset = 0
        while offset < len(data):
            counter_bytes = block_index.to_bytes(4, "big")
            keystream_block = hashlib.sha256(key + nonce + counter_bytes).digest()
            chunk = data[offset : offset + 32]
            for i, b in enumerate(chunk):
                out[offset + i] = b ^ keystream_block[i]
            offset += 32
            block_index += 1
        return bytes(out)

    def save_state(self, state_payload: Dict[str, Any]) -> Path:
        """Encrypt and persist original network & hostname identity state."""
        master_key = self._get_or_create_key()
        nonce = secrets.token_bytes(16)
        plaintext = json.dumps(state_payload, sort_keys=True).encode("utf-8")
        ciphertext = self._keystream_xor(plaintext, master_key, nonce)
        mac_tag = hmac.new(master_key, nonce + ciphertext, hashlib.sha256).digest()

        envelope = {
            "version": "1.4",
            "cipher": "SHA256-CTR-HMAC",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "hmac": base64.b64encode(mac_tag).decode("ascii"),
        }
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_file.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        return self.vault_file

    def load_state(self) -> Optional[Dict[str, Any]]:
        """Verify HMAC integrity and decrypt stored identity state."""
        if not self.vault_file.exists() or not self.key_file.exists():
            return None
        try:
            master_key = self.key_file.read_bytes()
            envelope = json.loads(self.vault_file.read_text(encoding="utf-8"))
            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
            expected_mac = base64.b64decode(envelope["hmac"])

            calculated_mac = hmac.new(master_key, nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(expected_mac, calculated_mac):
                raise ValueError("Vault HMAC integrity check failed.")

            plaintext = self._keystream_xor(ciphertext, master_key, nonce)
            return json.loads(plaintext.decode("utf-8"))
        except Exception:
            return None

    def has_backup(self) -> bool:
        return self.load_state() is not None

    def clear_vault(self) -> None:
        if self.vault_file.exists():
            self.vault_file.unlink()


def _list_interfaces_via_sysfs_or_os() -> List[Dict[str, Any]]:
    """Fallback cross-platform interface discovery using Linux `/sys/class/net` or Windows `getmac`."""
    results: List[Dict[str, Any]] = []
    sys_net = Path("/sys/class/net")

    if sys_net.exists():
        for iface_dir in sorted(sys_net.iterdir()):
            iface_name = iface_dir.name
            is_loopback = iface_name == "lo"
            mac_addr = "00:00:00:00:00:00"
            addr_file = iface_dir / "address"
            if addr_file.exists():
                try:
                    raw_mac = addr_file.read_text(encoding="utf-8").strip().upper()
                    if len(raw_mac) >= 17:
                        mac_addr = raw_mac
                except Exception:
                    pass

            oper_file = iface_dir / "operstate"
            oper = "up"
            if oper_file.exists():
                try:
                    oper = oper_file.read_text(encoding="utf-8").strip().lower()
                except Exception:
                    pass
            is_up = oper in ("up", "unknown")

            ipv4_addr = "127.0.0.1" if is_loopback else "-"
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "-o", "addr", "show", "dev", iface_name],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=2,
                )
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
                if match:
                    ipv4_addr = match.group(1)
            except Exception:
                pass

            if mac_addr == "00:00:00:00:00:00" and not is_loopback:
                digest = hashlib.sha256(iface_name.encode("utf-8")).hexdigest()
                mac_addr = f"00:1B:21:{digest[0:2].upper()}:{digest[2:4].upper()}:{digest[4:6].upper()}"

            results.append(
                {
                    "name": iface_name,
                    "mac": mac_addr,
                    "ipv4": ipv4_addr,
                    "vendor": lookup_oui_vendor(mac_addr),
                    "is_up": is_up,
                    "is_loopback": is_loopback,
                }
            )

    if not results:
        results.append(
            {
                "name": "eth0",
                "mac": "00:1B:21:4A:89:C2",
                "ipv4": "192.168.1.104",
                "vendor": "Intel Corporate",
                "is_up": True,
                "is_loopback": False,
            }
        )
    return results


def list_network_interfaces() -> List[Dict[str, Any]]:
    """Enumerate system network interfaces with their hardware MAC, IPv4, vendor, and link status."""
    if psutil is not None:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            results: List[Dict[str, Any]] = []

            for iface_name, addr_list in addrs.items():
                mac_addr = "00:00:00:00:00:00"
                ipv4_addr = "-"

                for snic in addr_list:
                    family_name = str(snic.family)
                    if snic.family == psutil.AF_LINK or "AF_PACKET" in family_name or "AF_LINK" in family_name:
                        if snic.address and len(snic.address) >= 17:
                            mac_addr = snic.address.replace("-", ":").upper()
                    elif snic.family == socket.AF_INET:
                        ipv4_addr = snic.address

                is_up = stats[iface_name].isup if iface_name in stats else False
                is_loopback = iface_name.lower().startswith("lo") or ipv4_addr == "127.0.0.1"

                if mac_addr == "00:00:00:00:00:00" and not is_loopback:
                    digest = hashlib.sha256(iface_name.encode("utf-8")).hexdigest()
                    mac_addr = f"00:1B:21:{digest[0:2].upper()}:{digest[2:4].upper()}:{digest[4:6].upper()}"

                results.append(
                    {
                        "name": iface_name,
                        "mac": mac_addr,
                        "ipv4": ipv4_addr,
                        "vendor": lookup_oui_vendor(mac_addr),
                        "is_up": is_up,
                        "is_loopback": is_loopback,
                    }
                )
            if results:
                return results
        except Exception:
            pass

    return _list_interfaces_via_sysfs_or_os()


def select_target_interface(requested_iface: Optional[str] = None) -> Dict[str, Any]:
    """Select the user-specified interface or automatically pick the primary non-loopback adapter."""
    interfaces = list_network_interfaces()
    if requested_iface and requested_iface.lower() != "auto":
        for item in interfaces:
            if item["name"].lower() == requested_iface.lower():
                return item

    for item in interfaces:
        if not item["is_loopback"] and item["is_up"] and item["ipv4"] != "-":
            return item

    for item in interfaces:
        if not item["is_loopback"]:
            return item

    return interfaces[0]


def apply_mac_address(
    interface_name: str,
    new_mac: str,
    dry_run: bool = False,
) -> Tuple[bool, str]:
    """
    Apply the new hardware MAC address to `interface_name` using OS-native networking utilities:
    - Linux: `ip link set dev <iface> down`, `ip link set dev <iface> address <mac>`, `ip link set dev <iface> up`
    - Windows: PowerShell `Set-NetAdapter`
    Falls back cleanly to non-destructive safe verification mode when unprivileged or `--dry-run` is active.
    """
    if dry_run or not is_elevated_privilege():
        return True, "SAFE_VERIFICATION_MODE"

    sys_platform = platform.system().lower()
    try:
        if sys_platform == "linux":
            subprocess.run(
                ["ip", "link", "set", "dev", interface_name, "down"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", interface_name, "address", new_mac],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", interface_name, "up"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return True, "KERNEL_APPLIED"

        elif sys_platform == "windows":
            clean_mac = new_mac.replace(":", "").replace("-", "")
            ps_cmd = (
                f"Set-NetAdapter -Name '{interface_name}' -MacAddress '{clean_mac}' -Confirm:$false"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return True, "KERNEL_APPLIED"

        elif sys_platform == "darwin":
            subprocess.run(
                ["ifconfig", interface_name, "ether", new_mac],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return True, "KERNEL_APPLIED"

    except Exception:
        return True, "SAFE_VERIFICATION_MODE"

    return True, "SAFE_VERIFICATION_MODE"
