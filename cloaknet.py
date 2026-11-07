#!/usr/bin/env python3
"""
CloakNet: Automated Layer-2 Identity Obfuscation & Local Traffic Randomizer
Main CLI Entry Point (`cloaknet.py`)
Repository: https://github.com/x90d/CloakNet
Author: x90d

Features a complete Graceful Exit & Auto-Restore lifecycle (`signal` handlers for
SIGINT/SIGTERM/SIGBREAK + `atexit` hook + `try...finally` blocks) alongside manual
`python cloaknet.py --restore` recovery.
"""

import argparse
import atexit
import datetime
import signal
import sys
import time
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core import __repo__, __version__
from core.daemon import CloakNetDaemon, detect_active_ssid
from core.hostname_masker import apply_system_hostname, generate_masked_hostname, get_current_hostname
from core.i18n import Localizer, load_config, save_config
from core.mac_engine import (
    EncryptedIdentityVault,
    apply_mac_address,
    generate_legitimate_mac,
    is_elevated_privilege,
    list_network_interfaces,
    select_target_interface,
)
from core.network_reset import execute_full_network_hygiene

console = Console()


class GracefulExitGuard:
    """
    Coordinates idempotent automatic restoration of hardware MAC address and
    system hostname when the process receives SIGINT (Ctrl+C), SIGTERM,
    SIGBREAK (Windows console close), or exits via `atexit` / `try...finally`.
    """

    def __init__(
        self,
        loc: Localizer,
        requested_iface: Optional[str] = None,
        dry_run: bool = False,
        enabled: bool = True,
    ) -> None:
        self.loc = loc
        self.requested_iface = requested_iface
        self.dry_run = dry_run
        self.enabled = enabled
        self._restored = False
        self._active_daemon: Optional[CloakNetDaemon] = None

    def attach_daemon(self, daemon: CloakNetDaemon) -> None:
        self._active_daemon = daemon

    def register_handlers(self) -> None:
        """Register OS signal handlers (SIGINT, SIGTERM, SIGBREAK) and atexit hook."""
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(getattr(signal, "SIGBREAK"), self._handle_signal)
        atexit.register(self.restore_if_needed)

    def _handle_signal(self, signum: int, _frame: Any) -> None:
        try:
            sig_name = signal.Signals(signum).name
        except Exception:
            sig_name = f"SIG({signum})"

        console.print()
        console.print(
            f"[bold yellow][SIGNAL][/bold yellow] "
            f"{self.loc.t('msg_signal_caught').format(sig=sig_name)}"
        )
        if self._active_daemon is not None:
            self._active_daemon.request_stop()
        self.restore_if_needed()
        raise SystemExit(0)

    def restore_if_needed(self) -> None:
        """Idempotently restore original hardware MAC and hostname if enabled and a backup exists."""
        if self._restored or not self.enabled:
            return
        vault = EncryptedIdentityVault()
        if not vault.has_backup():
            return
        self._restored = True
        console.print(
            f"[bold cyan][AUTO-RESTORE][/bold cyan] {self.loc.t('msg_auto_restore_triggered')}"
        )
        cmd_restore_identity(
            self.loc,
            requested_iface=self.requested_iface,
            dry_run=self.dry_run,
        )


def render_header(loc: Localizer) -> None:
    """Render a restrained, professional enterprise CLI header panel."""
    header_text = Text()
    header_text.append("CloakNet ", style="bold white")
    header_text.append(f"v{__version__}", style="grey70")
    header_text.append(f"  |  {__repo__}\n", style="grey58")
    header_text.append(loc.t("app_subtitle"), style="grey82")

    panel = Panel(
        header_text,
        box=box.ROUNDED,
        border_style="grey37",
        padding=(0, 2),
        expand=False,
    )
    console.print(panel)


def cmd_show_status(loc: Localizer, requested_iface: Optional[str] = None) -> None:
    """Display active system posture, privilege level, encrypted vault status, and network interfaces."""
    vault = EncryptedIdentityVault()
    saved_state = vault.load_state()
    elevated = is_elevated_privilege()

    sys_table = Table(
        title=loc.t("app_title"),
        box=box.SIMPLE_HEAVY,
        header_style="bold white",
        border_style="grey37",
        show_lines=False,
    )
    sys_table.add_column(loc.t("col_property"), style="grey82", no_wrap=True)
    sys_table.add_column(loc.t("col_value"), style="white")

    sys_table.add_row(loc.t("lbl_current_hostname"), get_current_hostname())
    sys_table.add_row(loc.t("lbl_current_ssid"), detect_active_ssid())
    sys_table.add_row(
        loc.t("lbl_privilege_level"),
        loc.t("lbl_admin") if elevated else loc.t("lbl_standard_user"),
    )
    if saved_state:
        vault_desc = (
            f"{loc.t('lbl_vault_present')} "
            f"[MAC: {saved_state.get('original_mac')} | Host: {saved_state.get('original_hostname')}]"
        )
    else:
        vault_desc = loc.t("lbl_vault_empty")
    sys_table.add_row(loc.t("lbl_vault_status"), vault_desc)

    console.print(sys_table)

    iface_table = Table(
        box=box.SIMPLE_HEAVY,
        header_style="bold white",
        border_style="grey37",
    )
    iface_table.add_column(loc.t("col_interface"), style="bold white", no_wrap=True)
    iface_table.add_column(loc.t("col_mac"), style="cyan", no_wrap=True)
    iface_table.add_column(loc.t("col_ipv4"), style="white", no_wrap=True)
    iface_table.add_column(loc.t("col_vendor"), style="grey78")
    iface_table.add_column(loc.t("col_state"), style="green")

    selected = select_target_interface(requested_iface)
    for item in list_network_interfaces():
        marker = " *" if item["name"] == selected["name"] else ""
        state_str = loc.t("status_up") if item["is_up"] else loc.t("status_down")
        iface_table.add_row(
            f"{item['name']}{marker}",
            item["mac"],
            item["ipv4"],
            item["vendor"],
            state_str,
        )

    console.print(iface_table)


def cmd_randomize_identity(
    loc: Localizer,
    requested_iface: Optional[str] = None,
    preferred_vendor: str = "any",
    hostname_prefix: str = "DESKTOP",
    dry_run: bool = False,
) -> None:
    """
    Execute full Layer-2 identity obfuscation:
    1. Backup original MAC and hostname to encrypted local vault (`.cloaknet_vault/identity_backup.enc`)
    2. Generate & apply IEEE-valid vendor MAC address
    3. Generate & apply generic workstation hostname
    4. Flush DNS resolver cache, purge ARP neighbor cache, and gracefully cycle interface
    """
    target_iface = select_target_interface(requested_iface)
    iface_name = target_iface["name"]
    current_mac = target_iface["mac"]
    current_host = get_current_hostname()

    vault = EncryptedIdentityVault()
    existing_backup = vault.load_state()
    if existing_backup is None:
        vault.save_state(
            {
                "interface": iface_name,
                "original_mac": current_mac,
                "original_vendor": target_iface["vendor"],
                "original_hostname": current_host,
                "saved_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        )

    new_mac, new_vendor = generate_legitimate_mac(preferred_vendor)
    new_hostname = generate_masked_hostname(hostname_prefix)

    _, mac_mode = apply_mac_address(iface_name, new_mac, dry_run=dry_run)
    _, host_mode = apply_system_hostname(new_hostname, dry_run=dry_run)
    hygiene = execute_full_network_hygiene(iface_name, dry_run=dry_run)

    mode_label = (
        loc.t("status_applied")
        if mac_mode == "KERNEL_APPLIED"
        else loc.t("status_simulated")
    )

    table = Table(
        title=f"{loc.t('msg_iface_selected')}: {iface_name}",
        box=box.SIMPLE_HEAVY,
        header_style="bold white",
        border_style="grey37",
    )
    table.add_column(loc.t("col_step"), style="white", no_wrap=True)
    table.add_column(loc.t("col_before"), style="grey70")
    table.add_column(loc.t("col_after"), style="cyan")
    table.add_column(loc.t("col_result"), style="green", no_wrap=True)

    table.add_row(
        "Layer-2 MAC (OUI)",
        f"{current_mac} ({target_iface['vendor']})",
        f"{new_mac} ({new_vendor})",
        mode_label,
    )
    table.add_row(
        "DHCP Hostname",
        current_host,
        new_hostname,
        loc.t("status_applied") if host_mode == "KERNEL_APPLIED" else loc.t("status_simulated"),
    )
    table.add_row(
        "DNS & ARP Hygiene",
        "Cached Resolver / Neighbor Entries",
        f"DNS: {hygiene['dns_cache']} | ARP: {hygiene['arp_cache']}",
        mode_label,
    )
    table.add_row(
        "Encrypted Vault",
        "SHA256-CTR-HMAC Envelope",
        ".cloaknet_vault/identity_backup.enc",
        loc.t("status_active"),
    )

    console.print(table)
    if not is_elevated_privilege() or dry_run:
        console.print(f"[grey62]{loc.t('msg_priv_notice')}[/grey62]")


def cmd_restore_identity(
    loc: Localizer,
    requested_iface: Optional[str] = None,
    dry_run: bool = False,
) -> None:
    """Restore the original hardware MAC address and hostname from the encrypted vault."""
    vault = EncryptedIdentityVault()
    saved = vault.load_state()
    if not saved:
        console.print(f"[yellow][INFO][/yellow] {loc.t('msg_no_backup')}")
        return

    iface_name = requested_iface or saved.get("interface") or select_target_interface(None)["name"]
    orig_mac = saved["original_mac"]
    orig_vendor = saved.get("original_vendor", "Original Hardware NIC")
    orig_host = saved["original_hostname"]

    apply_mac_address(iface_name, orig_mac, dry_run=dry_run)
    apply_system_hostname(orig_host, dry_run=dry_run)
    execute_full_network_hygiene(iface_name, dry_run=dry_run)
    vault.clear_vault()

    table = Table(
        title=loc.t("msg_restore_complete"),
        box=box.SIMPLE_HEAVY,
        header_style="bold white",
        border_style="grey37",
    )
    table.add_column(loc.t("col_step"), style="white")
    table.add_column(loc.t("col_value"), style="green")
    table.add_column(loc.t("col_result"), style="cyan")

    table.add_row("Hardware MAC Restored", f"{orig_mac} ({orig_vendor})", loc.t("status_restored"))
    table.add_row("System Hostname Restored", orig_host, loc.t("status_restored"))
    table.add_row("Interface Reset & Cache Flush", iface_name, loc.t("status_restored"))

    console.print(table)


def run_interactive_console(
    initial_lang: str,
    interface_arg: Optional[str],
    dry_run: bool,
    exit_guard: GracefulExitGuard,
) -> None:
    """
    Interactive menu launched when `run.bat` or `python cloaknet.py` is run without action flags.
    Wrapped in `try...finally` so quitting via Option 0, Ctrl+C (SIGINT), or closing the terminal
    automatically restores the original MAC address and hostname if an active session backup exists.
    """
    current_lang = initial_lang
    try:
        while True:
            loc = Localizer(current_lang)
            exit_guard.loc = loc
            console.print()
            render_header(loc)

            menu_table = Table(
                title=loc.t("menu_header"),
                box=box.SIMPLE_HEAVY,
                header_style="bold white",
                border_style="grey37",
            )
            menu_table.add_column("#", style="cyan", width=4)
            menu_table.add_column("Operation", style="white")

            menu_table.add_row("1", loc.t("menu_opt_1"))
            menu_table.add_row("2", loc.t("menu_opt_2"))
            menu_table.add_row("3", loc.t("menu_opt_3"))
            menu_table.add_row("4", loc.t("menu_opt_4"))
            menu_table.add_row("5", loc.t("menu_opt_5"))
            menu_table.add_row("0", loc.t("menu_opt_0"))
            console.print(menu_table)

            try:
                choice = input(f"\n> {loc.t('menu_prompt')}: ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            console.print()
            if choice == "1":
                cmd_show_status(loc, requested_iface=interface_arg)
            elif choice == "2":
                exit_guard._restored = False
                cmd_randomize_identity(loc, requested_iface=interface_arg, dry_run=dry_run)
            elif choice == "3":
                cmd_restore_identity(loc, requested_iface=interface_arg, dry_run=dry_run)
                exit_guard._restored = True
            elif choice == "4":
                exit_guard._restored = False
                daemon = CloakNetDaemon(
                    interface_name=interface_arg,
                    lang=current_lang,
                    dry_run=dry_run,
                    auto_restore_on_exit=False,
                    console=console,
                )
                exit_guard.attach_daemon(daemon)
                daemon.run(max_cycles=3)
            elif choice == "5":
                current_lang = "id" if current_lang == "en" else "en"
                save_config({"language": current_lang})
                loc = Localizer(current_lang)
                exit_guard.loc = loc
                console.print(f"[green][OK][/green] {loc.t('msg_lang_updated')}: [bold]{current_lang.upper()}[/bold]")
            elif choice == "0":
                break
    finally:
        exit_guard.restore_if_needed()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloaknet",
        description="CloakNet: Automated Layer-2 Identity Obfuscation & Local Traffic Randomizer (https://github.com/x90d/CloakNet)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Target network interface name (e.g., eth0, wlan0, Wi-Fi). Defaults to primary active adapter.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch the interactive operations console menu.",
    )
    parser.add_argument(
        "-r",
        "--randomize",
        action="store_true",
        help="Randomize Layer-2 MAC (official IEEE OUI), mask DHCP hostname, and flush DNS/ARP caches.",
    )
    parser.add_argument(
        "--hold",
        action="store_true",
        help="Keep randomized identity session active in foreground until Ctrl+C/SIGINT, then auto-restore on exit.",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Manually restore original hardware MAC and system hostname from encrypted local vault.",
    )
    parser.add_argument(
        "-d",
        "--daemon",
        action="store_true",
        help="Run background wireless SSID transition watcher and automatically restore original identity on exit.",
    )
    parser.add_argument(
        "--daemon-cycles",
        type=int,
        default=None,
        help="Optional cycle limit for --daemon mode (useful for automated testing).",
    )
    parser.add_argument(
        "--no-auto-restore",
        action="store_true",
        help="Persist obfuscated MAC and hostname after daemon/session exit without automatic restoration.",
    )
    parser.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="Display current Layer-2 MAC, hostname, privilege state, and interface table.",
    )
    parser.add_argument(
        "--vendor",
        default=None,
        help="Filter OUI pool by hardware vendor (e.g., Intel, Realtek, Apple, Dell, Lenovo, Cisco).",
    )
    parser.add_argument(
        "--lang",
        choices=["en", "id"],
        default=None,
        help="Interface language: 'en' (English, default) or 'id' (Bahasa Indonesia).",
    )
    parser.add_argument(
        "--set-lang",
        choices=["en", "id"],
        default=None,
        help="Persist default language ('en' or 'id') in config.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute in safe non-destructive verification mode without mutating kernel link state.",
    )
    return parser


def main() -> None:
    cfg = load_config()
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.set_lang:
        cfg = save_config({"language": args.set_lang})

    active_lang = args.lang or cfg.get("language", "en")
    loc = Localizer(active_lang)
    iface_target = args.interface or cfg.get("default_interface", "auto")
    if iface_target == "auto":
        iface_target = None
    vendor_pref = args.vendor or cfg.get("preferred_vendor", "any")
    host_prefix = cfg.get("hostname_prefix", "DESKTOP")

    auto_restore_cfg = bool(cfg.get("auto_restore_on_exit", True)) and not args.no_auto_restore

    if args.status:
        render_header(loc)
        cmd_show_status(loc, requested_iface=iface_target)
        return

    if args.restore:
        render_header(loc)
        cmd_restore_identity(loc, requested_iface=iface_target, dry_run=args.dry_run)
        return

    if args.randomize:
        hold_mode = bool(args.hold)
        guard = GracefulExitGuard(
            loc=loc,
            requested_iface=iface_target,
            dry_run=args.dry_run,
            enabled=hold_mode and auto_restore_cfg,
        )
        guard.register_handlers()
        render_header(loc)
        try:
            cmd_randomize_identity(
                loc,
                requested_iface=iface_target,
                preferred_vendor=vendor_pref,
                hostname_prefix=host_prefix,
                dry_run=args.dry_run,
            )
            if hold_mode:
                console.print(f"[grey70]{loc.t('msg_session_hold')}[/grey70]")
                while True:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            if hold_mode:
                guard.restore_if_needed()
        return

    if args.daemon:
        guard = GracefulExitGuard(
            loc=loc,
            requested_iface=iface_target,
            dry_run=args.dry_run,
            enabled=auto_restore_cfg,
        )
        guard.register_handlers()
        render_header(loc)
        daemon = CloakNetDaemon(
            interface_name=iface_target,
            preferred_vendor=vendor_pref,
            poll_interval=int(cfg.get("daemon_poll_interval_sec", 10)),
            lang=active_lang,
            dry_run=args.dry_run,
            auto_restore_on_exit=auto_restore_cfg,
            restore_callback=guard.restore_if_needed,
            console=console,
        )
        guard.attach_daemon(daemon)
        try:
            daemon.run(max_cycles=args.daemon_cycles)
        finally:
            guard.restore_if_needed()
        return

    if args.set_lang and not (args.status or args.randomize or args.restore or args.daemon or args.interactive):
        render_header(loc)
        console.print(f"[green][OK][/green] {loc.t('msg_lang_updated')}: [bold]{active_lang.upper()}[/bold]")
        return

    # Default when launched via `run.bat` or `python cloaknet.py` with no action flags:
    # always enter the interactive menu console so the window stays open and ready for input.
    guard = GracefulExitGuard(
        loc=loc,
        requested_iface=iface_target,
        dry_run=args.dry_run,
        enabled=auto_restore_cfg,
    )
    guard.register_handlers()
    run_interactive_console(active_lang, iface_target, args.dry_run, guard)


if __name__ == "__main__":
    main()
