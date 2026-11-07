"""
CloakNet Wireless SSID Transition Monitor Daemon (`core/daemon.py`)
Monitors wireless SSID/BSSID changes in the background and automatically rotates
the endpoint's Layer-2 MAC identity, DHCP hostname, and local resolver caches
whenever the host joins a new or untrusted wireless network.
Includes signal-safe termination (`SIGINT`/`SIGTERM`) and `try...finally` cleanup.
"""

import datetime
import platform
import subprocess
import time
from typing import Callable, Optional

from rich.console import Console
from rich.table import Table

from core.hostname_masker import apply_system_hostname, generate_masked_hostname, get_current_hostname
from core.i18n import Localizer
from core.mac_engine import (
    EncryptedIdentityVault,
    apply_mac_address,
    generate_legitimate_mac,
    select_target_interface,
)
from core.network_reset import execute_full_network_hygiene


def detect_active_ssid() -> str:
    """
    Query OS wireless subsystem for the currently associated Wi-Fi SSID:
    - Windows: `netsh wlan show interfaces`
    - Linux: `iwgetid -r` or `nmcli -t -f active,ssid dev wifi`
    - macOS: `networksetup -getairportnetwork en0`
    Returns a deterministic fallback identifier when running on wired Ethernet or inside a VM.
    """
    sys_platform = platform.system().lower()
    try:
        if sys_platform == "windows":
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            )
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        return parts[1].strip()

        elif sys_platform == "linux":
            for cmd in (["iwgetid", "-r"], ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]):
                try:
                    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=2).strip()
                    if cmd[0] == "iwgetid" and out:
                        return out
                    for line in out.splitlines():
                        if line.startswith("yes:"):
                            return line.split(":", 1)[1]
                except Exception:
                    continue

        elif sys_platform == "darwin":
            out = subprocess.check_output(
                ["networksetup", "-getairportnetwork", "en0"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            )
            if ":" in out:
                return out.split(":", 1)[1].strip()
    except Exception:
        pass

    return "LAN-ETHERNET-SEGMENT"


class CloakNetDaemon:
    """Background SSID watcher that rotates Layer-2 identity on every network transition."""

    def __init__(
        self,
        interface_name: Optional[str] = None,
        preferred_vendor: str = "any",
        poll_interval: int = 8,
        lang: str = "en",
        dry_run: bool = False,
        auto_restore_on_exit: bool = True,
        restore_callback: Optional[Callable[[], None]] = None,
        console: Optional[Console] = None,
    ) -> None:
        self.interface_name = interface_name
        self.preferred_vendor = preferred_vendor
        self.poll_interval = max(2, poll_interval)
        self.loc = Localizer(lang)
        self.dry_run = dry_run
        self.auto_restore_on_exit = auto_restore_on_exit
        self.restore_callback = restore_callback
        self.console = console or Console()
        self.vault = EncryptedIdentityVault()
        self.last_observed_ssid: Optional[str] = None
        self._stop_requested = False

    def request_stop(self) -> None:
        """Signal the daemon loop to exit cleanly."""
        self._stop_requested = True

    def run(self, max_cycles: Optional[int] = None) -> None:
        """
        Monitor wireless transitions continuously (or for `max_cycles` iterations during
        interactive testing/CI verification). Guarantees cleanup via `try...finally`.
        """
        target_iface = select_target_interface(self.interface_name)
        iface_name = target_iface["name"]

        # Ensure baseline hardware identity is backed up before daemon rotation starts
        if not self.vault.has_backup():
            self.vault.save_state(
                {
                    "interface": iface_name,
                    "original_mac": target_iface["mac"],
                    "original_vendor": target_iface["vendor"],
                    "original_hostname": get_current_hostname(),
                    "saved_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
            )

        self.console.print(
            f"[bold slate_blue1][DAEMON][/bold slate_blue1] {self.loc.t('msg_daemon_start')} "
            f"(Interface: [bold]{iface_name}[/bold], Interval: [bold]{self.poll_interval}s[/bold])"
        )
        self.console.print(f"[grey70]{self.loc.t('msg_session_hold')}[/grey70]")

        cycle_count = 0
        try:
            while not self._stop_requested:
                cycle_count += 1
                current_ssid = detect_active_ssid()

                # Simulate an untrusted public Wi-Fi roaming event on cycle 2 if on static wired LAN during demo
                if max_cycles is not None and cycle_count == 2 and current_ssid == "LAN-ETHERNET-SEGMENT":
                    current_ssid = "Public-Airport-FreeWiFi-5G"

                if current_ssid != self.last_observed_ssid:
                    self.last_observed_ssid = current_ssid
                    new_mac, vendor_name = generate_legitimate_mac(self.preferred_vendor)
                    new_host = generate_masked_hostname("DESKTOP")

                    _, mac_mode = apply_mac_address(iface_name, new_mac, dry_run=self.dry_run)
                    apply_system_hostname(new_host, dry_run=self.dry_run)
                    execute_full_network_hygiene(iface_name, dry_run=self.dry_run)

                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    table = Table(
                        show_header=True,
                        header_style="bold white on grey19",
                        border_style="grey37",
                        expand=False,
                    )
                    table.add_column("Timestamp", style="cyan", no_wrap=True)
                    table.add_column("Network / SSID", style="white")
                    table.add_column("Assigned OUI MAC", style="green")
                    table.add_column("Vendor Profile", style="grey78")
                    table.add_column("Masked Hostname", style="yellow")
                    table.add_column("Mode", style="grey70")

                    table.add_row(
                        ts,
                        current_ssid,
                        new_mac,
                        vendor_name,
                        new_host,
                        self.loc.t("status_applied") if mac_mode == "KERNEL_APPLIED" else self.loc.t("status_simulated"),
                    )
                    self.console.print(table)

                if max_cycles is not None and cycle_count >= max_cycles:
                    break

                sleep_target = self.poll_interval if max_cycles is None else 0.5
                slept = 0.0
                while slept < sleep_target and not self._stop_requested:
                    step = min(0.25, sleep_target - slept)
                    time.sleep(step)
                    slept += step
        except KeyboardInterrupt:
            pass
        finally:
            self.console.print(f"[bold green][OK][/bold green] {self.loc.t('msg_daemon_stopped')}")
            if self.auto_restore_on_exit and self.restore_callback is not None and self.vault.has_backup():
                self.restore_callback()
