"""
CloakNet Bilingual Localization (i18n) & Configuration Manager
Supports English (en - Default) and Bahasa Indonesia (id) via CLI argument or config.json.
"""

import json
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "language": "en",
    "default_interface": "auto",
    "preferred_vendor": "any",
    "daemon_poll_interval_sec": 10,
    "hostname_prefix": "DESKTOP",
    "flush_caches_on_rotate": True,
    "auto_restore_on_exit": True,
}

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        "app_title": "CloakNet — Automated Layer-2 Identity Obfuscation & Local Traffic Randomizer",
        "app_subtitle": "Defensive Endpoint Privacy & Local Network Hardening Utility",
        "col_property": "Property",
        "col_value": "Current Value",
        "col_status": "Status",
        "col_interface": "Interface",
        "col_mac": "Hardware MAC",
        "col_ipv4": "IPv4 Address",
        "col_vendor": "OUI Vendor",
        "col_state": "Link State",
        "col_step": "Hardening Step",
        "col_before": "Original State",
        "col_after": "Obfuscated State",
        "col_result": "Result",
        "status_active": "ACTIVE",
        "status_up": "UP",
        "status_down": "DOWN",
        "status_simulated": "APPLIED (SAFE-MODE)",
        "status_applied": "APPLIED (KERNEL)",
        "status_restored": "RESTORED",
        "status_skipped": "SKIPPED",
        "msg_detecting_iface": "Detecting primary active network interface...",
        "msg_iface_selected": "Selected network interface",
        "msg_backup_saved": "Encrypted original hardware identity saved to vault",
        "msg_mac_rotated": "Layer-2 MAC address randomized using verified IEEE OUI",
        "msg_hostname_rotated": "System DHCP hostname masked to generic workstation ID",
        "msg_network_flushed": "DNS resolver cache, ARP neighbor table, and link state refreshed",
        "msg_restore_complete": "Original hardware MAC and system hostname successfully restored.",
        "msg_no_backup": "No encrypted identity backup found in vault. Nothing to restore.",
        "msg_daemon_start": "Starting CloakNet wireless SSID transition monitor...",
        "msg_daemon_cycle": "Monitoring wireless SSID transitions",
        "msg_daemon_new_ssid": "Detected network transition to SSID",
        "msg_daemon_stopped": "CloakNet background daemon terminated cleanly.",
        "msg_signal_caught": "Interrupt signal received ({sig}). Initiating graceful exit & automatic identity restoration...",
        "msg_auto_restore_triggered": "Executing automatic exit restoration from encrypted vault...",
        "msg_session_hold": "Identity obfuscation active. Press [CTRL+C] at any time to quit and automatically restore original MAC & hostname.",
        "msg_lang_updated": "Default interface language updated in config.json",
        "msg_priv_notice": "Note: Running without Administrator/root privileges. OS mutations executed in non-destructive verification mode.",
        "lbl_current_hostname": "System Hostname",
        "lbl_current_ssid": "Connected Wireless SSID",
        "lbl_vault_status": "Encrypted Identity Vault",
        "lbl_privilege_level": "Execution Privilege",
        "lbl_admin": "Elevated (Root / Administrator)",
        "lbl_standard_user": "Standard User (Safe Verification Mode)",
        "lbl_vault_present": "Backup Present (Ready for --restore)",
        "lbl_vault_empty": "Empty (Baseline State)",
        "menu_header": "Interactive Operations Console",
        "menu_opt_1": "Inspect Active Interfaces & Layer-2 Posture (--status)",
        "menu_opt_2": "Randomize MAC Address, Hostname & Flush Caches (--randomize)",
        "menu_opt_3": "Restore Original Hardware Identity from Vault (--restore)",
        "menu_opt_4": "Run SSID Transition Monitor Daemon (--daemon, 3 cycles)",
        "menu_opt_5": "Switch Language / Ganti Bahasa (EN <-> ID)",
        "menu_opt_0": "Exit Console (Auto-Restore Original Identity if Active)",
        "menu_prompt": "Select operation [0-5]",
    },
    "id": {
        "app_title": "CloakNet — Obfuskasi Identitas Layer-2 Otomatis & Pengacak Trafik Lokal",
        "app_subtitle": "Utilitas Privasi Defensif Endpoint & Penguatan Jaringan Lokal",
        "col_property": "Parameter",
        "col_value": "Nilai Saat Ini",
        "col_status": "Status",
        "col_interface": "Antarmuka",
        "col_mac": "Alamat MAC",
        "col_ipv4": "Alamat IPv4",
        "col_vendor": "Vendor OUI",
        "col_state": "Status Link",
        "col_step": "Tahap Hardening",
        "col_before": "Identitas Awal",
        "col_after": "Identitas Tersamar",
        "col_result": "Hasil",
        "status_active": "AKTIF",
        "status_up": "TERHUBUNG",
        "status_down": "TERPUTUS",
        "status_simulated": "DITERAPKAN (MODE-AMAN)",
        "status_applied": "DITERAPKAN (KERNEL)",
        "status_restored": "DIPULIHKAN",
        "status_skipped": "DILEWATI",
        "msg_detecting_iface": "Mendeteksi antarmuka jaringan utama yang aktif...",
        "msg_iface_selected": "Antarmuka jaringan terpilih",
        "msg_backup_saved": "Cadangan identitas asli terenkripsi disimpan ke brankas lokal",
        "msg_mac_rotated": "Alamat MAC Layer-2 diacak menggunakan OUI vendor IEEE resmi",
        "msg_hostname_rotated": "Hostname sistem DHCP disamarkan ke ID workstation generik",
        "msg_network_flushed": "Cache DNS resolver, tabel ARP lokal, dan status antarmuka disegarkan",
        "msg_restore_complete": "Alamat MAC perangkat keras dan hostname asli berhasil dipulihkan.",
        "msg_no_backup": "Tidak ditemukan cadangan identitas di brankas lokal. Tidak ada perubahan.",
        "msg_daemon_start": "Memulai pemantau perpindahan jaringan Wi-Fi/SSID CloakNet...",
        "msg_daemon_cycle": "Memantau perubahan koneksi SSID nirkabel",
        "msg_daemon_new_ssid": "Terdeteksi perpindahan jaringan ke SSID",
        "msg_daemon_stopped": "Layanan background daemon CloakNet dihentikan dengan rapi.",
        "msg_signal_caught": "Sinyal interupsi diterima ({sig}). Memulai penghentian aman & pemulihan identitas otomatis...",
        "msg_auto_restore_triggered": "Menjalankan pemulihan otomatis saat keluar dari brankas terenkripsi...",
        "msg_session_hold": "Penyamaran identitas aktif. Tekan [CTRL+C] kapan saja untuk keluar dan otomatis memulihkan MAC & hostname asli.",
        "msg_lang_updated": "Bahasa antarmuka utama berhasil diperbarui pada config.json",
        "msg_priv_notice": "Catatan: Berjalan tanpa hak akses Administrator/root. Mutasi sistem dijalankan dalam mode verifikasi aman.",
        "lbl_current_hostname": "Hostname Sistem",
        "lbl_current_ssid": "SSID Wi-Fi Terhubung",
        "lbl_vault_status": "Brankas Identitas Terenkripsi",
        "lbl_privilege_level": "Hak Akses Eksekusi",
        "lbl_admin": "Tinggi (Root / Administrator)",
        "lbl_standard_user": "Pengguna Standar (Mode Verifikasi Aman)",
        "lbl_vault_present": "Tersedia (Siap untuk --restore)",
        "lbl_vault_empty": "Kosong (Status Dasar)",
        "menu_header": "Konsol Operasi Interaktif",
        "menu_opt_1": "Periksa Antarmuka Aktif & Postur Layer-2 (--status)",
        "menu_opt_2": "Samarkan Alamat MAC, Hostname & Bersihkan Cache (--randomize)",
        "menu_opt_3": "Pulihkan Identitas Perangkat Asli dari Brankas (--restore)",
        "menu_opt_4": "Jalankan Daemon Pemantau Perpindahan SSID (--daemon, 3 siklus)",
        "menu_opt_5": "Ganti Bahasa / Switch Language (ID <-> EN)",
        "menu_opt_0": "Keluar Konsol (Otomatis Pulihkan Identitas Asli jika Aktif)",
        "menu_prompt": "Pilih operasi [0-5]",
    },
}


def load_config() -> Dict[str, Any]:
    """Load configuration from config.json or return defaults if missing."""
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                config.update(loaded)
        except Exception:
            pass
    return config


def save_config(new_values: Dict[str, Any]) -> Dict[str, Any]:
    """Persist updated configuration values to config.json."""
    cfg = load_config()
    cfg.update(new_values)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    return cfg


class Localizer:
    """Thread-safe string localizer for English (en) and Bahasa Indonesia (id)."""

    def __init__(self, lang: str = "en") -> None:
        normalized = (lang or "en").strip().lower()
        self.lang = normalized if normalized in TRANSLATIONS else "en"

    def t(self, key: str) -> str:
        return TRANSLATIONS.get(self.lang, TRANSLATIONS["en"]).get(
            key, TRANSLATIONS["en"].get(key, key)
        )
