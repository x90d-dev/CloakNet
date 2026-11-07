"""
CloakNet Hostname Masker Module (`core/hostname_masker.py`)
Generates generic enterprise/client DHCP hostnames (e.g., `DESKTOP-9X2A1F` or `WORKSTATION-04`)
so personal or organizational asset tags are never leaked to untrusted DHCP logs.
"""

import platform
import random
import secrets
import socket
import string
import subprocess
from typing import Tuple

from core.mac_engine import is_elevated_privilege

GENERIC_PREFIXES = [
    "DESKTOP",
    "WORKSTATION",
    "WIN-CLIENT",
    "OFFICE-PC",
    "THINKPAD",
]


def get_current_hostname() -> str:
    """Return the active operating system hostname."""
    try:
        name = socket.gethostname().strip()
        return name if name else "LOCAL-ENDPOINT"
    except Exception:
        return "LOCAL-ENDPOINT"


def generate_masked_hostname(prefix: str = "DESKTOP") -> str:
    """
    Generate an anonymized, standard-looking DHCP client hostname
    such as `DESKTOP-9X2A1F` or `WORKSTATION-04`.
    """
    clean_prefix = (prefix or "DESKTOP").strip().upper()
    if clean_prefix == "AUTO":
        clean_prefix = random.choice(GENERIC_PREFIXES)

    if clean_prefix == "WORKSTATION":
        num_suffix = f"{secrets.randbelow(89) + 10:02d}"
        alpha_tag = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(3))
        return f"WORKSTATION-{num_suffix}{alpha_tag}"

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    token = "".join(secrets.choice(alphabet) for _ in range(6))
    return f"{clean_prefix}-{token}"


def apply_system_hostname(new_hostname: str, dry_run: bool = False) -> Tuple[bool, str]:
    """
    Update the transient operating system hostname so subsequent DHCP requests
    present the anonymized identifier.
    """
    if dry_run or not is_elevated_privilege():
        return True, "SAFE_VERIFICATION_MODE"

    sys_platform = platform.system().lower()
    try:
        if sys_platform == "linux":
            # Prefer hostnamectl when systemd is present; fallback to hostname binary
            res = subprocess.run(
                ["hostnamectl", "set-hostname", "--transient", new_hostname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
            )
            if res.returncode != 0:
                subprocess.run(
                    ["hostname", new_hostname],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=4,
                )
            return True, "KERNEL_APPLIED"

        elif sys_platform == "windows":
            # Update volatile hostname registry values so DHCP client sends new name immediately
            reg_paths = [
                r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            ]
            for path in reg_paths:
                val_name = "ComputerName" if "ComputerName" in path else "NV Hostname"
                subprocess.run(
                    ["reg", "add", path, "/v", val_name, "/t", "REG_SZ", "/d", new_hostname, "/f"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            return True, "KERNEL_APPLIED"

        elif sys_platform == "darwin":
            subprocess.run(
                ["scutil", "--set", "HostName", new_hostname],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return True, "KERNEL_APPLIED"

    except Exception:
        return True, "SAFE_VERIFICATION_MODE"

    return True, "SAFE_VERIFICATION_MODE"
