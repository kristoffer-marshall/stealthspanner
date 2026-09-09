#!/usr/bin/env python3
"""
StealthSpanner - VPN Latency Checker

Tests latency for VPN servers by reading .ovpn configuration files
and pinging each server concurrently. Supports multiple VPN providers
with automatic configuration download.
"""

import argparse
import getpass
import math
import os
import random
import re
import socket
import stat
import subprocess
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

try:
    import readchar
except ImportError:  # pragma: no cover - optional interactive enhancement
    readchar = None
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

import requests

from xdg_paths import (
    ensure_directory,
    get_credentials_path,
    get_last_scan_log_path,
    get_legacy_credentials_path,
    get_state_log_path,
)

# Import our modules
from config_manager import (
    get_config_directory,
    get_default_provider,
    get_picker_preferences,
    get_privacy_scores,
    get_privacy_weight,
    is_privacy_scoring_enabled,
    load_config,
    should_auto_download,
    update_picker_preferences,
)
from vpn_config_downloader import download_vpn_configs


KILLSWITCH_DEFAULT = "killswitch"
CREDS_FILE_DEFAULT = str(get_credentials_path())
console = Console()
error_console = Console(stderr=True)
log_console = Console(color_system=None, force_terminal=False, width=160)


@dataclass(frozen=True)
class VPNSelectionResult:
    filename: str
    hostname: str
    latency_ms: float
    status: str


@dataclass(frozen=True)
class PickerVPNResult:
    filename: str
    hostname: str
    latency_ms: float | None
    status: str
    country_code: str | None
    country_name: str
    city_name: str
    privacy_score: int
    packet_loss: float | None
    score: float
    region: str


@dataclass(frozen=True)
class LastScanMetadata:
    log_path: Path
    last_run: str


@dataclass(frozen=True)
class NetworkIdentity:
    ip: str
    fqdn: str


@dataclass(frozen=True)
class PickerMenuItem:
    key: str
    label: str
    description: str = ""
    value: str | None = None


# Country code to country name mapping
COUNTRY_NAMES = {
    'AD': 'Andorra',
    'AE': 'United Arab Emirates',
    'AL': 'Albania',
    'AM': 'Armenia',
    'AR': 'Argentina',
    'AT': 'Austria',
    'AU': 'Australia',
    'AZ': 'Azerbaijan',
    'BA': 'Bosnia and Herzegovina',
    'BD': 'Bangladesh',
    'BE': 'Belgium',
    'BG': 'Bulgaria',
    'BM': 'Bermuda',
    'BN': 'Brunei',
    'BO': 'Bolivia',
    'BR': 'Brazil',
    'BS': 'Bahamas',
    'BT': 'Bhutan',
    'BZ': 'Belize',
    'CA': 'Canada',
    'CH': 'Switzerland',
    'CL': 'Chile',
    'CO': 'Colombia',
    'CR': 'Costa Rica',
    'CY': 'Cyprus',
    'CZ': 'Czech Republic',
    'DE': 'Germany',
    'DK': 'Denmark',
    'DO': 'Dominican Republic',
    'DZ': 'Algeria',
    'EC': 'Ecuador',
    'EE': 'Estonia',
    'EG': 'Egypt',
    'ES': 'Spain',
    'FI': 'Finland',
    'FR': 'France',
    'GE': 'Georgia',
    'GH': 'Ghana',
    'GR': 'Greece',
    'GT': 'Guatemala',
    'HK': 'Hong Kong',
    'HN': 'Honduras',
    'HR': 'Croatia',
    'HT': 'Haiti',
    'HU': 'Hungary',
    'ID': 'Indonesia',
    'IE': 'Ireland',
    'IL': 'Israel',
    'IM': 'Isle of Man',
    'IN': 'India',
    'IS': 'Iceland',
    'IT': 'Italy',
    'JE': 'Jersey',
    'JM': 'Jamaica',
    'JO': 'Jordan',
    'JP': 'Japan',
    'KE': 'Kenya',
    'KH': 'Cambodia',
    'KR': 'South Korea',
    'KY': 'Cayman Islands',
    'KZ': 'Kazakhstan',
    'LA': 'Laos',
    'LB': 'Lebanon',
    'LI': 'Liechtenstein',
    'LK': 'Sri Lanka',
    'LT': 'Lithuania',
    'LU': 'Luxembourg',
    'LV': 'Latvia',
    'MA': 'Morocco',
    'MC': 'Monaco',
    'MD': 'Moldova',
    'ME': 'Montenegro',
    'MK': 'North Macedonia',
    'MM': 'Myanmar',
    'MN': 'Mongolia',
    'MO': 'Macau',
    'MT': 'Malta',
    'MX': 'Mexico',
    'MY': 'Malaysia',
    'NG': 'Nigeria',
    'NI': 'Nicaragua',
    'NL': 'Netherlands',
    'NO': 'Norway',
    'NP': 'Nepal',
    'NZ': 'New Zealand',
    'PA': 'Panama',
    'PE': 'Peru',
    'PG': 'Papua New Guinea',
    'PH': 'Philippines',
    'PK': 'Pakistan',
    'PL': 'Poland',
    'PR': 'Puerto Rico',
    'PT': 'Portugal',
    'PY': 'Paraguay',
    'RO': 'Romania',
    'RS': 'Serbia',
    'SA': 'Saudi Arabia',
    'SE': 'Sweden',
    'SG': 'Singapore',
    'SI': 'Slovenia',
    'SK': 'Slovakia',
    'TH': 'Thailand',
    'TR': 'Turkey',
    'TT': 'Trinidad and Tobago',
    'TW': 'Taiwan',
    'UA': 'Ukraine',
    'UK': 'United Kingdom',
    'US': 'United States',
    'UY': 'Uruguay',
    'VE': 'Venezuela',
    'VN': 'Vietnam',
    'ZA': 'South Africa',
}


REGION_BY_COUNTRY_CODE = {
    'US': 'North America', 'CA': 'North America', 'MX': 'North America', 'PA': 'Central America', 'CR': 'Central America',
    'GT': 'Central America', 'HN': 'Central America', 'NI': 'Central America', 'BZ': 'Central America', 'DO': 'Caribbean',
    'PR': 'Caribbean', 'BS': 'Caribbean', 'JM': 'Caribbean', 'KY': 'Caribbean', 'BM': 'Atlantic',
    'AR': 'South America', 'BO': 'South America', 'BR': 'South America', 'CL': 'South America', 'CO': 'South America',
    'EC': 'South America', 'PE': 'South America', 'PY': 'South America', 'UY': 'South America', 'VE': 'South America',
    'AD': 'Europe', 'AT': 'Europe', 'BA': 'Europe', 'BE': 'Europe', 'BG': 'Europe', 'CH': 'Europe', 'CY': 'Europe',
    'CZ': 'Europe', 'DE': 'Europe', 'DK': 'Europe', 'EE': 'Europe', 'ES': 'Europe', 'FI': 'Europe', 'FR': 'Europe',
    'GR': 'Europe', 'HR': 'Europe', 'HU': 'Europe', 'IE': 'Europe', 'IM': 'Europe', 'IS': 'Europe', 'IT': 'Europe',
    'JE': 'Europe', 'LI': 'Europe', 'LT': 'Europe', 'LU': 'Europe', 'LV': 'Europe', 'MC': 'Europe', 'MD': 'Europe',
    'ME': 'Europe', 'MK': 'Europe', 'MT': 'Europe', 'NL': 'Europe', 'NO': 'Europe', 'PL': 'Europe', 'PT': 'Europe',
    'RO': 'Europe', 'RS': 'Europe', 'SE': 'Europe', 'SI': 'Europe', 'SK': 'Europe', 'SM': 'Europe', 'UA': 'Europe', 'UK': 'Europe',
    'AE': 'Middle East', 'IL': 'Middle East', 'JO': 'Middle East', 'LB': 'Middle East', 'SA': 'Middle East', 'TR': 'Middle East',
    'EG': 'Africa', 'GH': 'Africa', 'KE': 'Africa', 'MA': 'Africa', 'NG': 'Africa', 'SC': 'Africa', 'ZA': 'Africa',
    'AM': 'Asia', 'AZ': 'Asia', 'BD': 'Asia', 'BN': 'Asia', 'BT': 'Asia', 'GE': 'Asia', 'HK': 'Asia', 'ID': 'Asia',
    'IN': 'Asia', 'JP': 'Asia', 'KH': 'Asia', 'KR': 'Asia', 'KZ': 'Asia', 'LA': 'Asia', 'LK': 'Asia', 'MM': 'Asia',
    'MN': 'Asia', 'MO': 'Asia', 'MY': 'Asia', 'NP': 'Asia', 'PH': 'Asia', 'PK': 'Asia', 'SG': 'Asia', 'TH': 'Asia',
    'TW': 'Asia', 'VN': 'Asia', 'AU': 'Oceania', 'NZ': 'Oceania', 'PG': 'Oceania'
}


def get_country_name(country_code: str | None) -> str:
    """
    Get full country name from ISO 2-letter country code.
    
    Args:
        country_code: Two-letter country code (e.g., 'CH')
        
    Returns:
        Full country name (e.g., 'Switzerland') or 'Unknown' if not found
    """
    if country_code is None:
        return 'Unknown'
    return COUNTRY_NAMES.get(country_code.upper(), 'Unknown')


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Colors
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    GRAY = '\033[90m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'


def supports_color(file=None) -> bool:
    """
    Check if the terminal supports ANSI color codes.
    
    Args:
        file: File object to check (default: stdout)
        
    Returns:
        True if colors are supported, False otherwise
    """
    if file is None:
        file = sys.stdout
    
    # Check if it's a TTY
    if not hasattr(file, 'isatty') or not file.isatty():
        return False
    
    # Check for NO_COLOR environment variable
    return not os.environ.get('NO_COLOR')


def colorize(text: str, color: str, file=None) -> str:
    """
    Apply color to text if terminal supports it.
    
    Args:
        text: Text to colorize
        color: ANSI color code
        file: File object to check color support (default: stdout)
        
    Returns:
        Colorized text if supported, plain text otherwise
    """
    if supports_color(file):
        return f"{color}{text}{Colors.RESET}"
    return text


def pad_and_colorize(text: str, width: int, color: str, file=None) -> str:
    """
    Pad text to specified width, then colorize it.
    This ensures proper column alignment when colors are used.
    
    Args:
        text: Text to pad and colorize
        width: Desired display width
        color: ANSI color code
        file: File object to check color support (default: stdout)
        
    Returns:
        Padded and colorized text
    """
    padded = f"{text:<{width}}"
    return colorize(padded, color, file)


class Tee:
    """A file-like object that writes to multiple file handles (like Unix tee command)."""
    
    def __init__(self, *files):
        self.files = files
    
    def write(self, data):
        for f in self.files:
            f.write(data)
            f.flush()
    
    def flush(self):
        for f in self.files:
            f.flush()
    
    def close(self):
        # Don't close stdout/stderr, only close log file
        for f in self.files:
            if f not in (sys.stdout, sys.stderr):
                f.close()


def print_progress_bar(completed: int, total: int, file=None, bar_length: int = 40) -> None:
    """Legacy progress-bar fallback for non-Rich paths."""
    if total == 0:
        return

    percent = (completed / total) * 100
    filled_length = int(bar_length * completed // total)
    filled_char = '█'
    empty_char = '░'

    if supports_color(file):
        filled = colorize(filled_char * filled_length, Colors.BRIGHT_GREEN, file)
        empty = colorize(empty_char * (bar_length - filled_length), Colors.GRAY, file)
        bar = f"{filled}{empty}"
        percent_text = colorize(f"{percent:.1f}%", Colors.BRIGHT_CYAN, file)
        count_text = colorize(f"({completed}/{total})", Colors.WHITE, file)
    else:
        bar = filled_char * filled_length + empty_char * (bar_length - filled_length)
        percent_text = f"{percent:.1f}%"
        count_text = f"({completed}/{total})"

    print(f'\r[{bar}] {percent_text} {count_text}', end='', flush=True, file=file)
    if completed == total:
        print(file=file)


def print_banner(title: str, subtitle: str | None = None) -> None:
    text = Text()
    text.append(title, style="bold bright_cyan")
    if subtitle:
        text.append(f"\n{subtitle}", style="white")
    console.print(Panel(text, border_style="bright_blue", expand=False))


def print_info(message: str) -> None:
    console.print(f"[bright_cyan]•[/bright_cyan] {message}")


def print_success(message: str) -> None:
    console.print(f"[bright_green]✓[/bright_green] {message}")


def print_warning(message: str) -> None:
    error_console.print(f"[yellow]![/yellow] {message}")


def print_error(message: str) -> None:
    error_console.print(f"[red]✗[/red] {message}")


def render_selection_table(results: list[VPNSelectionResult], top_count: int, output_console: Console = console) -> None:
    table = Table(title="Top VPN Candidates", box=box.ROUNDED, header_style="bold bright_cyan")
    table.add_column("#", justify="right", style="bright_black", width=3)
    table.add_column("File", style="white", overflow="ellipsis", no_wrap=True, max_width=42)
    table.add_column("Host", style="cyan", overflow="ellipsis", no_wrap=True, max_width=30)
    table.add_column("Latency", justify="right", width=10)
    table.add_column("Status", justify="center", width=9)

    for index, result in enumerate(results[:top_count], start=1):
        latency_style = "bright_green" if result.latency_ms < 50 else "green" if result.latency_ms < 100 else "yellow"
        table.add_row(
            str(index),
            result.filename,
            result.hostname,
            f"[{latency_style}]{result.latency_ms:.2f} ms[/{latency_style}]",
            "[bright_green]Success[/bright_green]",
        )

    output_console.print(table)


def render_selection_summary(best: VPNSelectionResult, ovpn_path: Path, mode: str, log_path: Path, vpn_dir: Path, output_console: Console = console) -> None:
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold bright_cyan", justify="right")
    summary.add_column(style="white", overflow="fold")
    summary.add_row("Latency log", str(log_path))
    summary.add_row("VPN directory", str(vpn_dir))
    summary.add_row("File", best.filename)
    summary.add_row("Host", best.hostname)
    summary.add_row("Latency", f"{best.latency_ms:.2f} ms")
    summary.add_row("Path", str(ovpn_path))
    summary.add_row("Mode", mode)
    output_console.print(Panel(summary, title="Selected VPN", border_style="bright_green", expand=False))


def render_connection_panel(mode: str, ovpn_path: Path, creds_file: Path | None = None, killswitch_path: Path | None = None, output_console: Console = console) -> None:
    details = Table.grid(padding=(0, 2))
    details.add_column(style="bold bright_cyan", justify="right")
    details.add_column(style="white", overflow="fold")
    details.add_row("Mode", mode)
    details.add_row("Config", str(ovpn_path))
    if creds_file is not None:
        details.add_row("Credentials", str(creds_file))
    if killswitch_path is not None:
        details.add_row("Killswitch", str(killswitch_path))
    output_console.print(Panel(details, title="Connection", border_style="bright_magenta", expand=False))


def render_results_table(results: list[dict], output_console: Console = console) -> tuple[list[dict], list[dict]]:
    successful = [r for r in results if r['latency'] is not None]
    failed = [r for r in results if r['latency'] is None]
    successful.sort(key=lambda x: x.get('score', 0.0), reverse=True)
    failed.sort(key=lambda x: x.get('score', 0.0), reverse=True)
    sorted_results = successful + failed

    table = Table(title="VPN Latency Results", box=box.ROUNDED, header_style="bold bright_cyan")
    table.add_column("File", style="white", overflow="ellipsis", no_wrap=True, max_width=38)
    table.add_column("Host", style="cyan", overflow="ellipsis", no_wrap=True, max_width=26)
    table.add_column("Country", style="magenta", overflow="ellipsis", max_width=20)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Latency", justify="right", width=10)
    table.add_column("Jitter", justify="right", width=18)
    table.add_column("Loss", justify="right", width=8)
    table.add_column("Status", justify="center", overflow="ellipsis", max_width=18)

    for result in sorted_results:
        country_name = result.get('country_name', 'Unknown')
        privacy_score = result.get('privacy_score', 0)
        score = result.get('score', 0.0)
        latency = result['latency']
        jitter = result.get('jitter')
        packet_loss = result.get('packet_loss', 100.0)
        status = result['status']

        country_display = f"{country_name} ({privacy_score})"
        if privacy_score >= 80:
            country_display += " ★"

        score_style = "bright_green" if score >= 80 else "green" if score >= 60 else "yellow" if score >= 40 else "red"
        if latency is None:
            latency_display = "[red]N/A[/red]"
        else:
            latency_style = "bright_green" if latency < 50 else "green" if latency < 100 else "yellow"
            latency_display = f"[{latency_style}]{latency:.2f} ms[/{latency_style}]"

        if jitter and jitter.get('std_dev') is not None:
            std_dev = jitter['std_dev']
            jitter_style = "bright_green" if std_dev < 10 else "yellow" if std_dev < 30 else "red"
            jitter_display = f"[{jitter_style}]{std_dev:.2f} ms[/{jitter_style}]"
        else:
            jitter_display = "[bright_black]N/A[/bright_black]"

        if packet_loss == 0.0:
            loss_style = "bright_green"
        elif packet_loss < 5.0:
            loss_style = "green"
        elif packet_loss < 25.0:
            loss_style = "yellow"
        else:
            loss_style = "red"

        status_style = "bright_green" if latency is not None else "red"
        table.add_row(
            result['filename'],
            result.get('hostname', 'Unknown'),
            country_display,
            f"[{score_style}]{score:.1f}[/{score_style}]",
            latency_display,
            jitter_display,
            f"[{loss_style}]{packet_loss:.1f}%[/{loss_style}]",
            f"[{status_style}]{status}[/{status_style}]",
        )

    output_console.print(table)
    return successful, failed


def render_last_scan_panel(metadata: LastScanMetadata, output_console: Console = console) -> None:
    details = Table.grid(padding=(0, 2))
    details.add_column(style="bold bright_cyan", justify="right")
    details.add_column(style="white", overflow="fold")
    details.add_row("Last scan", metadata.last_run)
    details.add_row("Source log", str(metadata.log_path))
    output_console.print(Panel(details, title="Last Scan", border_style="bright_yellow", expand=False))


def render_results_summary(results: list[dict], successful: list[dict], failed: list[dict], output_console: Console = console) -> None:
    dns_failures = [r for r in failed if 'DNS' in r['status']]
    other_failures = [r for r in failed if 'DNS' not in r['status']]

    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="bold bright_cyan")
    stats.add_column(style="white", overflow="fold")
    stats.add_row("Total", str(len(results)))
    stats.add_row("Successful", f"[bright_green]{len(successful)}[/bright_green]")
    stats.add_row("Failed", f"[red]{len(failed)}[/red]")
    if dns_failures:
        stats.add_row("DNS failures", f"[red]{len(dns_failures)}[/red]")
    if other_failures:
        stats.add_row("Other failures", f"[yellow]{len(other_failures)}[/yellow]")

    if successful:
        best_score = successful[0]
        worst_score = successful[-1]
        best_latency = min(successful, key=lambda x: x['latency'])
        worst_latency = max(successful, key=lambda x: x['latency'])
        stats.add_row("Best score", f"{best_score['hostname']} ({best_score.get('score', 0.0):.1f})")
        stats.add_row("Worst score", f"{worst_score['hostname']} ({worst_score.get('score', 0.0):.1f})")
        stats.add_row("Best latency", f"{best_latency['hostname']} ({best_latency['latency']:.2f} ms)")
        stats.add_row("Worst latency", f"{worst_latency['hostname']} ({worst_latency['latency']:.2f} ms)")

        successful_with_jitter = [r for r in successful if r.get('jitter') and r['jitter'].get('std_dev') is not None]
        if successful_with_jitter:
            best_jitter = min(successful_with_jitter, key=lambda x: x['jitter']['std_dev'])
            worst_jitter = max(successful_with_jitter, key=lambda x: x['jitter']['std_dev'])
            stats.add_row("Best jitter", f"{best_jitter['hostname']} ({best_jitter['jitter']['std_dev']:.2f} ms)")
            stats.add_row("Worst jitter", f"{worst_jitter['hostname']} ({worst_jitter['jitter']['std_dev']:.2f} ms)")

        successful_with_loss = [r for r in successful if r.get('packet_loss') is not None]
        if successful_with_loss:
            best_loss = min(successful_with_loss, key=lambda x: x['packet_loss'])
            worst_loss = max(successful_with_loss, key=lambda x: x['packet_loss'])
            stats.add_row("Best packet loss", f"{best_loss['hostname']} ({best_loss['packet_loss']:.1f}%)")
            stats.add_row("Worst packet loss", f"{worst_loss['hostname']} ({worst_loss['packet_loss']:.1f}%)")

        successful_with_privacy = [r for r in successful if r.get('privacy_score') is not None]
        if successful_with_privacy:
            best_privacy = max(successful_with_privacy, key=lambda x: x['privacy_score'])
            worst_privacy = min(successful_with_privacy, key=lambda x: x['privacy_score'])
            stats.add_row("Best privacy", f"{best_privacy['hostname']} ({best_privacy.get('country_name', 'Unknown')}, {best_privacy['privacy_score']})")
            stats.add_row("Worst privacy", f"{worst_privacy['hostname']} ({worst_privacy.get('country_name', 'Unknown')}, {worst_privacy['privacy_score']})")

    output_console.print(Panel(stats, title="Summary", border_style="bright_blue", expand=False))


def extract_country_code(filename: str) -> str | None:
    """
    Extract country code from IPVanish .ovpn filename.
    
    Args:
        filename: .ovpn filename (e.g., 'ipvanish-CH-Zurich-zrh-c18.ovpn')
        
    Returns:
        Two-letter country code (e.g., 'CH') or None if pattern doesn't match
    """
    # Pattern: ipvanish-{COUNTRY_CODE}-{city}-{code}.ovpn
    # Example: ipvanish-CH-Zurich-zrh-c18.ovpn -> CH
    if not filename.startswith('ipvanish-'):
        return None
    
    # Remove 'ipvanish-' prefix
    remaining = filename[9:]  # len('ipvanish-') = 9
    
    # Find the first hyphen after country code (country code is 2 letters)
    if len(remaining) < 3:  # Need at least 2 chars for country + 1 hyphen
        return None
    
    # Country code should be 2 uppercase letters followed by a hyphen
    if remaining[2] == '-':
        country_code = remaining[:2].upper()
        # Validate it's 2 uppercase letters
        if country_code.isalpha() and country_code.isupper():
            return country_code
    
    return None


def parse_ovpn_file(file_path: Path) -> str | None:
    """
    Parse an .ovpn file to extract the hostname from the 'remote' line.
    
    Args:
        file_path: Path to the .ovpn file
        
    Returns:
        Hostname if found, None otherwise
    """
    try:
        with file_path.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('remote'):
                    # Format: remote <hostname> <port>
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]  # Return hostname
    except OSError as e:
        warning_msg = colorize(f"Warning: Could not read {file_path}: {e}", Colors.YELLOW, sys.stderr)
        print(warning_msg, file=sys.stderr)
    return None


def discover_ovpn_files(directory: Path) -> dict[str, tuple[str, str | None]]:
    """
    Discover all .ovpn files in the directory and extract hostnames and country codes.
    
    Args:
        directory: Directory containing .ovpn files
        
    Returns:
        Dictionary mapping filename to (hostname, country_code) tuple
    """
    files_to_hosts = {}
    
    if not directory.exists():
        print_error(f"Directory {directory} does not exist")
        return files_to_hosts
    
    ovpn_files = list(directory.glob('*.ovpn'))
    print_info(f"Found {len(ovpn_files)} .ovpn files")
    
    for ovpn_file in ovpn_files:
        hostname = parse_ovpn_file(ovpn_file)
        country_code = extract_country_code(ovpn_file.name)
        if hostname:
            files_to_hosts[ovpn_file.name] = (hostname, country_code)
        else:
            print_warning(f"No 'remote' line found in {ovpn_file.name}")
    
    return files_to_hosts


def ping_host(hostname: str, count: int = 4, timeout: float = 3.0) -> tuple[float | None, dict[str, float | None] | None, float, str]:
    """
    Ping a host multiple times and calculate average latency, jitter, and packet loss.
    Uses the system ping command via subprocess to avoid permission issues.
    
    Args:
        hostname: Hostname or IP address to ping
        count: Number of ping attempts
        timeout: Timeout in seconds for each ping
        
    Returns:
        Tuple of (average_latency_ms, jitter_metrics_dict, packet_loss_percent, status_message)
        If all pings fail, returns (None, None, 100.0, error_message)
        jitter_metrics_dict contains: {'std_dev': float, 'mean_dev': float, 'min_max_range': float}
        packet_loss_percent is 0.0-100.0
    """
    # First, try to resolve the hostname to detect DNS failures
    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        return (None, None, 100.0, "DNS Resolution Failed")
    except OSError as e:
        # Other socket errors
        return (None, None, 100.0, f"Resolution Error: {e!s}")
    
    # Use system ping command - it has proper permissions and works reliably
    # Format: ping -c <count> -W <timeout_seconds> <hostname>
    # -c: count of pings
    # -W: timeout in seconds (Linux)
    # -w: timeout in seconds (alternative, some systems)
    try:
        # Convert timeout to milliseconds for ping command (ping uses seconds, but we want precise timeout)
        # Use -W for Linux (timeout in seconds) or -w for some other systems
        # We'll use -W which works on Linux
        timeout_seconds = math.ceil(timeout)
        timeout_seconds = max(timeout_seconds, 1)
        
        # Run ping command
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', str(timeout_seconds), hostname],
            capture_output=True,
            text=True,
            timeout=timeout * count + 5,
            check=False,
        )
        
        # Parse ping output
        output = result.stdout + result.stderr
        
        # Check for DNS errors in output
        if 'Name or service not known' in output or 'cannot resolve' in output.lower() or 'unknown host' in output.lower():
            return (None, None, 100.0, "DNS Resolution Failed")
        
        # Extract individual ping latencies from output
        # Pattern: "64 bytes from <host>: icmp_seq=<n> ttl=<ttl> time=<time> ms"
        latency_pattern = r'time=([\d.]+)\s*ms'
        latencies = []
        
        for line in output.split('\n'):
            match = re.search(latency_pattern, line)
            if match:
                try:
                    latency = float(match.group(1))
                    latencies.append(latency)
                except ValueError:
                    continue
        
        # Also try to extract from statistics line if individual pings weren't captured
        # Pattern: "rtt min/avg/max/mdev = <min>/<avg>/<max>/<mdev> ms"
        if not latencies:
            stats_pattern = r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms'
            stats_match = re.search(stats_pattern, output)
            if stats_match:
                # If we only have stats, we can't calculate jitter properly
                # But we can use the average
                try:
                    avg_latency = float(stats_match.group(2))
                    latencies = [avg_latency] * count  # Approximate - not ideal but better than nothing
                except ValueError:
                    pass
        
        # Extract packet loss from statistics
        # Pattern: "X packets transmitted, Y received, Z% packet loss"
        packet_loss_percent = 100.0
        loss_pattern = r'(\d+)% packet loss'
        loss_match = re.search(loss_pattern, output)
        if loss_match:
            try:
                packet_loss_percent = float(loss_match.group(1))
            except ValueError:
                pass
        
        # If we got successful pings, calculate metrics
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            
            # Calculate jitter metrics if we have at least 2 measurements
            jitter_metrics: dict[str, float | None]
            if len(latencies) >= 2:
                variance = sum((x - avg_latency) ** 2 for x in latencies) / len(latencies)
                std_dev = math.sqrt(variance)
                mean_dev = sum(abs(x - avg_latency) for x in latencies) / len(latencies)
                min_max_range = max(latencies) - min(latencies)

                jitter_metrics = {
                    'std_dev': std_dev,
                    'mean_dev': mean_dev,
                    'min_max_range': min_max_range,
                }
            else:
                jitter_metrics = {
                    'std_dev': None,
                    'mean_dev': None,
                    'min_max_range': None,
                }
            
            return (avg_latency, jitter_metrics, packet_loss_percent, "Success")
        
        # If ping command failed or returned no results
        if result.returncode != 0:
            if 'Name or service not known' in output or 'cannot resolve' in output.lower():
                return (None, None, 100.0, "DNS Resolution Failed")
            else:
                return (None, None, 100.0, "Timeout/Unreachable")
        
        # No latencies found but command succeeded - unusual case
        return (None, None, 100.0, "No Response")
        
    except subprocess.TimeoutExpired:
        return (None, None, 100.0, "Timeout/Unreachable")
    except FileNotFoundError:
        return (None, None, 100.0, "Ping Command Not Found")
    except OSError as e:
        # Check error message for DNS-related issues
        error_str = str(e).lower()
        if 'cannot resolve' in error_str or 'unknown host' in error_str or 'name or service not known' in error_str:
            return (None, None, 100.0, "DNS Resolution Failed")
        return (None, None, 100.0, f"Error: {e!s}")


def calculate_score(
    latency: float | None,
    jitter: dict[str, float | None] | None,
    packet_loss: float,
    country_code: str | None,
    privacy_config: dict,
) -> float:
    """
    Calculate a composite score (0-100) based on latency, jitter, packet loss, and privacy.
    
    Args:
        latency: Average latency in milliseconds (None if failed)
        jitter: Jitter metrics dictionary with 'std_dev' key (None if unavailable)
        packet_loss: Packet loss percentage (0.0-100.0)
        country_code: Two-letter country code (e.g., 'CH') or None
        privacy_config: Dictionary with privacy settings:
            - 'enabled': bool - Whether privacy scoring is enabled
            - 'weight': float - Weight of privacy in score (0.0-1.0)
            - 'scores': Dict[str, int] - Mapping of country codes to privacy scores (0-100)
        
    Returns:
        Score from 0.0 to 100.0, where 100 is best and 0 is worst
    """
    # If latency is None, the connection failed - score is 0
    if latency is None:
        return 0.0
    
    # Get privacy score for this country (default to 0 if not found or disabled)
    privacy_enabled = privacy_config.get('enabled', False)
    privacy_weight = privacy_config.get('weight', 0.35)
    privacy_scores = privacy_config.get('scores', {})
    
    if privacy_enabled and country_code:
        privacy_score = privacy_scores.get(country_code, 0)
    else:
        privacy_score = 0
    
    # Get jitter std_dev, default to a high value if unavailable
    jitter_std_dev = jitter.get('std_dev') if jitter else None
    if jitter_std_dev is None:
        # If we don't have jitter data, assume worst case for scoring
        jitter_std_dev = 100.0
    
    # Calculate component scores (each normalized to 0-100)
    # Latency score: 0ms = 100 points, 500ms = 0 points (linear)
    # Formula: max(0, 100 - (latency / 5))
    latency_score = max(0.0, 100.0 - (latency / 5.0))
    
    # Jitter score: 0ms = 100 points, 50ms = 0 points (linear)
    # Formula: max(0, 100 - (jitter * 2))
    jitter_score = max(0.0, 100.0 - (jitter_std_dev * 2.0))
    
    # Packet loss score: 0% = 100 points, 100% = 0 points (linear)
    # Formula: 100 - packet_loss
    packet_loss_score = max(0.0, 100.0 - packet_loss)
    
    # Calculate weights: if privacy weight is W, remaining (1-W) is distributed
    # among latency, jitter, and packet loss
    if privacy_enabled:
        remaining_weight = 1.0 - privacy_weight
        latency_weight = remaining_weight * 0.4
        jitter_weight = remaining_weight * 0.3
        packet_loss_weight = remaining_weight * 0.3
        
        composite_score = (
            (privacy_score * privacy_weight) +
            (latency_score * latency_weight) +
            (jitter_score * jitter_weight) +
            (packet_loss_score * packet_loss_weight)
        )
    else:
        # No privacy scoring: use original weights
        composite_score = (latency_score * 0.4) + (jitter_score * 0.3) + (packet_loss_score * 0.3)
    
    # Round to 2 decimal places
    return round(composite_score, 2)


def test_host_latency(filename: str, hostname: str, country_code: str | None, pings: int, timeout: float, privacy_config: dict) -> dict:
    """
    Test latency for a single host (wrapper for threading).
    
    Args:
        filename: Name of the .ovpn file
        hostname: Hostname to ping
        country_code: Two-letter country code or None
        pings: Number of ping attempts
        timeout: Timeout in seconds
        privacy_config: Dictionary with privacy settings for score calculation
        
    Returns:
        Dictionary with results including latency, jitter metrics, packet loss, and privacy info
    """
    latency, jitter_metrics, packet_loss, status = ping_host(hostname, count=pings, timeout=timeout)
    
    # Get privacy score for this country
    privacy_enabled = privacy_config.get('enabled', False)
    privacy_scores = privacy_config.get('scores', {})
    privacy_score = 0
    if privacy_enabled and country_code:
        privacy_score = privacy_scores.get(country_code, 0)
    
    # Calculate composite score
    score = calculate_score(latency, jitter_metrics, packet_loss, country_code, privacy_config)
    
    # Get country name
    country_name = get_country_name(country_code)
    
    return {
        'filename': filename,
        'hostname': hostname,
        'country_code': country_code,
        'country_name': country_name,
        'privacy_score': privacy_score,
        'latency': latency,
        'jitter': jitter_metrics,
        'packet_loss': packet_loss,
        'score': score,
        'status': status
    }


def format_output(results: list[dict], output_console: Console = console) -> None:
    """Format and display latency test results with the Rich TUI."""
    successful, failed = render_results_table(results, output_console=output_console)
    render_results_summary(results, successful, failed, output_console=output_console)


def write_parseable_log(results: list[dict], log_file, log_path: Path) -> None:
    timestamp = format_timestamp(log_path.stat().st_mtime if log_path.exists() else datetime.now(UTC).timestamp())
    log_file.write(f"# stealthspanner_scan timestamp={timestamp}\n")
    log_file.write("filename\thostname\tcountry_code\tcountry_name\tscore\tlatency_ms\tjitter_std_dev_ms\tpacket_loss_percent\tstatus\n")

    successful = [r for r in results if r['latency'] is not None]
    failed = [r for r in results if r['latency'] is None]
    successful.sort(key=lambda x: x.get('score', 0.0), reverse=True)
    failed.sort(key=lambda x: x.get('score', 0.0), reverse=True)

    for result in successful + failed:
        jitter = result.get('jitter') or {}
        jitter_std_dev = jitter.get('std_dev')
        log_file.write(
            "\t".join([
                result.get('filename', ''),
                result.get('hostname', ''),
                result.get('country_code') or '',
                result.get('country_name', 'Unknown'),
                f"{result.get('score', 0.0):.2f}",
                '' if result.get('latency') is None else f"{result['latency']:.2f}",
                '' if jitter_std_dev is None else f"{jitter_std_dev:.2f}",
                f"{result.get('packet_loss', 100.0):.1f}",
                result.get('status', ''),
            ]) + "\n"
        )

    log_file.write("# end_stealthspanner_scan\n")


def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def get_region_name(country_code: str | None) -> str:
    if not country_code:
        return 'Unknown'
    return REGION_BY_COUNTRY_CODE.get(country_code.upper(), 'Unknown')


def extract_city_name(filename: str) -> str:
    if not filename.startswith('ipvanish-') or not filename.endswith('.ovpn'):
        return 'Unknown'

    stem = filename.removesuffix('.ovpn')
    parts = stem.split('-')
    if len(parts) < 4:
        return 'Unknown'

    city_tokens: list[str] = []
    for token in parts[2:]:
        if re.fullmatch(r'[a-z]{3,4}', token) or re.fullmatch(r'[a-z]{3,4}[a-z0-9]*', token):
            break
        if re.fullmatch(r'[a-z]\d+', token) or re.fullmatch(r'[bc]\d+', token):
            break
        city_tokens.append(token)

    if not city_tokens:
        return 'Unknown'

    city = ' '.join(token for token in city_tokens if token)
    city = city.replace('---', ' - ').replace('--', ' ')
    city = re.sub(r'\s+', ' ', city).strip(' -')
    city = re.sub(r'\bVirtual\b', '', city, flags=re.IGNORECASE)
    city = re.sub(r'\s+', ' ', city).strip(' -')
    return city if city else 'Unknown'


def build_picker_results(selection_results: list[VPNSelectionResult], privacy_config: dict) -> list[PickerVPNResult]:
    picker_results: list[PickerVPNResult] = []

    for result in selection_results:
        country_code = extract_country_code(result.filename)
        country_name = get_country_name(country_code)
        privacy_enabled = privacy_config.get('enabled', False)
        privacy_scores = privacy_config.get('scores', {})
        privacy_score = privacy_scores.get(country_code, 0) if privacy_enabled and country_code else 0
        city_name = extract_city_name(result.filename)
        packet_loss = 0.0 if result.status.lower() == 'success' else 100.0
        score = calculate_score(
            result.latency_ms,
            None,
            packet_loss,
            country_code,
            privacy_config,
        ) if result.status.lower() == 'success' else 0.0
        picker_results.append(
            PickerVPNResult(
                filename=result.filename,
                hostname=result.hostname,
                latency_ms=result.latency_ms if result.status.lower() == 'success' else None,
                status=result.status,
                country_code=country_code,
                country_name=country_name,
                city_name=city_name,
                privacy_score=privacy_score,
                packet_loss=packet_loss,
                score=score,
                region=get_region_name(country_code),
            )
        )

    return picker_results


def build_last_scan_results(selection_results: list[VPNSelectionResult], privacy_config: dict) -> list[dict]:
    results: list[dict] = []

    for result in selection_results:
        country_code = extract_country_code(result.filename)
        country_name = get_country_name(country_code)
        privacy_enabled = privacy_config.get('enabled', False)
        privacy_scores = privacy_config.get('scores', {})
        privacy_score = privacy_scores.get(country_code, 0) if privacy_enabled and country_code else 0
        score = calculate_score(
            result.latency_ms,
            None,
            0.0,
            country_code,
            privacy_config,
        ) if result.status.lower() == 'success' else 0.0

        results.append({
            'filename': result.filename,
            'hostname': result.hostname,
            'country_code': country_code,
            'country_name': country_name,
            'privacy_score': privacy_score,
            'latency': result.latency_ms if result.status.lower() == 'success' else None,
            'jitter': None,
            'packet_loss': 0.0 if result.status.lower() == 'success' else 100.0,
            'score': score,
            'status': result.status,
        })

    return results


def show_last_scan(log_path: Path, privacy_config: dict) -> int:
    if not log_path.is_file():
        print_error(f"Last scan log not found: {log_path}")
        return 1

    selection_results = parse_latency_log(log_path)
    if not selection_results:
        print_error(f"No scan results found in {log_path}")
        return 1

    metadata = LastScanMetadata(
        log_path=log_path,
        last_run=format_timestamp(log_path.stat().st_mtime),
    )
    results = build_last_scan_results(selection_results, privacy_config)
    successful, failed = render_results_table(results)
    render_last_scan_panel(metadata)
    render_results_summary(results, successful, failed)
    return 0


def parse_latency_log(log_path: Path) -> list[VPNSelectionResult]:
    if not log_path.is_file():
        raise FileNotFoundError(f"Latency log not found: {log_path}")

    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    results: list[VPNSelectionResult] = []

    in_machine_section = False
    saw_machine_section = False
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if line.startswith("# stealthspanner_scan "):
            in_machine_section = True
            saw_machine_section = True
            results = []
            continue
        if line.startswith("# end_stealthspanner_scan"):
            in_machine_section = False
            continue
        if not in_machine_section:
            continue
        if line.startswith("filename\t") or not line.strip():
            continue

        parts = line.split("\t")
        if len(parts) < 9:
            continue

        filename, hostname, _country_code, _country_name, _score, latency_text, _jitter_text, _loss_text, status = parts[:9]
        if not filename.endswith('.ovpn') or not hostname:
            continue
        if not latency_text:
            continue

        try:
            latency_ms = float(latency_text)
        except ValueError:
            continue

        results.append(
            VPNSelectionResult(
                filename=filename,
                hostname=hostname,
                latency_ms=latency_ms,
                status=status.strip() or 'Success',
            )
        )

    if results or saw_machine_section:
        return results

    simple_pattern = re.compile(
        r"^(?P<filename>.+?\.ovpn)\s+(?P<hostname>\S+)\s+(?P<latency>\d+(?:\.\d+)?)\s+(?P<status>.+?)\s*$"
    )

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("=", "Filename", "Total", "Successful", "Failed", "Best ", "Worst ", "#")):
            continue

        match = simple_pattern.match(line)
        if match:
            results.append(
                VPNSelectionResult(
                    filename=match.group("filename"),
                    hostname=match.group("hostname"),
                    latency_ms=float(match.group("latency")),
                    status=match.group("status").strip(),
                )
            )
            continue

        if ".ovpn" not in line:
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        filename = parts[0]
        if not filename.endswith('.ovpn'):
            continue

        try:
            first_numeric_index = next(i for i, token in enumerate(parts[1:], start=1) if re.fullmatch(r"\d+(?:\.\d+)?", token))
        except StopIteration:
            continue

        has_explicit_hostname = first_numeric_index >= 3
        if has_explicit_hostname:
            hostname = parts[1]
            score_index = first_numeric_index
        else:
            host_stem = filename.removesuffix('.ovpn').split('-')[-2:]
            hostname = "-".join(host_stem) + ".ipvanish.com" if len(host_stem) == 2 else filename.removesuffix('.ovpn') + ".ipvanish.com"
            score_index = first_numeric_index

        try:
            latency_ms = float(parts[score_index + 1])
        except (ValueError, IndexError):
            continue

        status_tokens = []
        for token in reversed(parts):
            if token.endswith('%'):
                break
            status_tokens.insert(0, token)
        status = " ".join(status_tokens).strip() or "Success"

        results.append(
            VPNSelectionResult(
                filename=filename,
                hostname=hostname,
                latency_ms=latency_ms,
                status=status,
            )
        )

    return results


def pick_best_result(results: Iterable[VPNSelectionResult]) -> VPNSelectionResult:
    successful = [result for result in results if result.status.lower() == "success"]
    if not successful:
        raise ValueError("No successful VPN results were found in the latency log.")
    return min(successful, key=lambda result: result.latency_ms)


def resolve_ovpn_path(filename: str, vpn_dir: Path) -> Path:
    candidate = vpn_dir / filename
    if candidate.is_file():
        return candidate.resolve()

    matches = list(vpn_dir.rglob(filename))
    if len(matches) == 1:
        return matches[0].resolve()
    if len(matches) > 1:
        raise FileNotFoundError(
            f"Multiple matching .ovpn files found for {filename!r} under {vpn_dir}."
        )

    raise FileNotFoundError(f"Could not find {filename!r} under {vpn_dir}.")


def get_public_network_identity() -> NetworkIdentity | None:
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        response.raise_for_status()
        ip_address = response.text.strip()
        try:
            fqdn = socket.getfqdn(ip_address) or 'Unknown'
        except OSError:
            fqdn = 'Unknown'
        return NetworkIdentity(ip=ip_address, fqdn=fqdn)
    except requests.RequestException:
        return None


def render_network_identity_panel(before: NetworkIdentity | None, after: NetworkIdentity | None) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style='bold bright_cyan', justify='right')
    table.add_column(style='white')
    table.add_column(style='white')
    table.add_row('State', 'Public IP', 'FQDN')
    table.add_row('Before VPN', before.ip if before else 'Unknown', before.fqdn if before else 'Unknown')
    table.add_row('On VPN', after.ip if after else 'Unknown', after.fqdn if after else 'Unknown')
    console.print(Panel(table, title='Network Identity', border_style='bright_yellow', expand=False))


def terminate_process_gracefully(process: subprocess.Popen[str], label: str) -> int:
    if process.poll() is not None:
        return process.returncode or 0

    print_warning(f'{label} interrupted. Stopping VPN connection...')
    process.terminate()
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print_warning(f'{label} did not stop in time; killing process.')
        process.kill()
        return process.wait(timeout=5)


def stream_process_until_ready(
    process: subprocess.Popen[str],
    *,
    verbose: bool,
    ready_pattern: str,
    failure_patterns: list[str],
) -> tuple[bool, list[str]]:
    buffered_lines: list[str] = []
    connected = False

    assert process.stdout is not None
    while True:
        line = process.stdout.readline()
        if not line:
            break
        stripped = line.rstrip()
        buffered_lines.append(stripped)
        if verbose:
            console.print(stripped)
        if ready_pattern in stripped:
            connected = True
            break
        if any(pattern in stripped for pattern in failure_patterns):
            break

    return connected, buffered_lines


def ensure_credentials(creds_file: Path) -> Path:
    legacy_creds_file = get_legacy_credentials_path()

    if creds_file.is_file():
        return creds_file

    if legacy_creds_file.is_file() and creds_file != legacy_creds_file:
        print(
            f"Warning: Using legacy credentials path at {legacy_creds_file}. "
            f"Please migrate to {creds_file}.",
            file=sys.stderr,
        )
        return legacy_creds_file

    print(f"VPN credentials not found at {creds_file}.")
    print("Let's set them up for future use.")
    vpn_user = input("Enter VPN Username: ").strip()
    vpn_pass = getpass.getpass("Enter VPN Password: ")

    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(f"{vpn_user}\n{vpn_pass}\n", encoding="utf-8")
    os.chmod(creds_file, stat.S_IRUSR | stat.S_IWUSR)
    print(f"Credentials saved securely to {creds_file}")
    return creds_file


def run_openvpn(ovpn_path: Path, creds_file: Path, verbose: bool = False) -> int:
    creds_path = ensure_credentials(creds_file)
    before_identity = get_public_network_identity()

    process = subprocess.Popen(
        [
            'sudo',
            'openvpn',
            '--mute-replay-warnings',
            '--config',
            str(ovpn_path),
            '--auth-user-pass',
            str(creds_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        connected, buffered_lines = stream_process_until_ready(
            process,
            verbose=verbose,
            ready_pattern='Initialization Sequence Completed',
            failure_patterns=['AUTH_FAILED', 'Exiting due to fatal error', 'SIGTERM'],
        )

        if not connected:
            if not verbose:
                for line in buffered_lines[-15:]:
                    console.print(line)
            return process.wait()

        after_identity = get_public_network_identity()
        print_success('VPN connected successfully.')
        render_network_identity_panel(before_identity, after_identity)
        print_info('Press Ctrl+C to disconnect and return to your normal connection.')

        return process.wait()
    except KeyboardInterrupt:
        return terminate_process_gracefully(process, 'OpenVPN')


def run_with_killswitch(ovpn_path: Path, killswitch_path: Path, verbose: bool = False) -> int:
    if not killswitch_path.is_file():
        raise FileNotFoundError(f"killswitch script not found: {killswitch_path}")

    before_identity = get_public_network_identity()
    process = subprocess.Popen(
        ['bash', str(killswitch_path), str(ovpn_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        connected, buffered_lines = stream_process_until_ready(
            process,
            verbose=verbose,
            ready_pattern='Initialization Sequence Completed',
            failure_patterns=['AUTH_FAILED', 'Exiting due to fatal error', 'SIGTERM'],
        )

        if not connected:
            if not verbose:
                for line in buffered_lines[-20:]:
                    console.print(line)
            return process.wait()

        after_identity = get_public_network_identity()
        print_success('VPN connected with killswitch enabled.')
        render_network_identity_panel(before_identity, after_identity)
        print_info('Press Ctrl+C to disconnect the VPN and restore normal internet access.')

        return process.wait()
    except KeyboardInterrupt:
        return terminate_process_gracefully(process, 'Killswitch VPN')


def parse_csv_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(',') if item.strip()]


def format_picker_choice(result: PickerVPNResult) -> str:
    latency_text = f"{result.latency_ms:.2f} ms" if result.latency_ms is not None else "N/A"
    return (
        f"{result.filename} | {result.hostname} | {result.country_name} / {result.region} | "
        f"score {result.score:.1f} | latency {latency_text} | loss {(result.packet_loss or 0.0):.1f}%"
    )


def get_preference_sets(preferences: dict[str, str]) -> tuple[set[str], set[str], set[str], set[str], str, str]:
    return (
        set(parse_csv_list(preferences.get('favorite_profiles', ''))),
        set(parse_csv_list(preferences.get('favorite_countries', ''))),
        set(parse_csv_list(preferences.get('favorite_regions', ''))),
        set(parse_csv_list(preferences.get('favorite_cities', ''))),
        preferences.get('default_mode', ''),
        preferences.get('default_value', ''),
    )


def get_result_badges(result: PickerVPNResult, preferences: dict[str, str]) -> tuple[str, str]:
    favorite_profiles, favorite_countries, favorite_regions, favorite_cities, default_mode, default_value = get_preference_sets(preferences)
    favorite_badges: list[str] = []
    if result.filename in favorite_profiles:
        favorite_badges.append('VPN')
    if (result.country_code or '') in favorite_countries:
        favorite_badges.append('CTRY')
    if result.region in favorite_regions:
        favorite_badges.append('REG')
    if result.city_name in favorite_cities:
        favorite_badges.append('CITY')

    is_default = (
        (default_mode == 'profile' and default_value == result.filename) or
        (default_mode == 'country' and default_value == (result.country_code or '')) or
        (default_mode == 'region' and default_value == result.region) or
        (default_mode == 'city' and default_value == result.city_name)
    )
    return (", ".join(favorite_badges) if favorite_badges else '—', 'YES' if is_default else '—')


def render_picker_results_table(
    title: str,
    results: list[PickerVPNResult],
    preferences: dict[str, str],
    selected_index: int | None = None,
    limit: int | None = None,
) -> None:
    table = Table(title=title, box=box.ROUNDED, header_style="bold bright_cyan")
    table.add_column("Sel", justify="center", width=3)
    table.add_column("Fav", justify="center", width=10)
    table.add_column("Def", justify="center", width=5)
    table.add_column("File", style="white", overflow="ellipsis", no_wrap=True, max_width=34)
    table.add_column("Host", style="cyan", overflow="ellipsis", no_wrap=True, max_width=24)
    table.add_column("Country", style="magenta", overflow="ellipsis", max_width=18)
    table.add_column("City", style="bright_blue", overflow="ellipsis", max_width=18)
    table.add_column("Region", style="yellow", max_width=16)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Latency", justify="right", width=10)

    if not results:
        table.add_row('—', '—', '—', 'No results', '', '', '', '', '')
        console.print(table)
        return

    if limit is None:
        terminal_height = console.size.height or 24
        limit = max(5, terminal_height - 13)

    start = 0
    end = min(len(results), limit)
    if selected_index is not None and len(results) > limit:
        start = max(0, min(selected_index - (limit // 2), len(results) - limit))
        end = start + limit

    for index in range(start, end):
        result = results[index]
        fav_badge, def_badge = get_result_badges(result, preferences)
        latency_text = f"{result.latency_ms:.2f} ms" if result.latency_ms is not None else "N/A"
        marker = "➜" if selected_index == index else " "
        style = "bold bright_green" if selected_index == index else ""
        table.add_row(
            marker,
            fav_badge,
            def_badge,
            result.filename,
            result.hostname,
            result.country_name,
            result.city_name,
            result.region,
            f"{result.score:.1f}",
            latency_text,
            style=style,
        )

    console.print(table)
    if len(results) > limit:
        console.print(f"[bright_black]Showing {start + 1}-{end} of {len(results)} results[/bright_black]")


def calculate_visible_window(total_items: int, selected_index: int, reserved_rows: int, minimum_rows: int = 5) -> tuple[int, int]:
    terminal_height = console.size.height or 24
    visible_rows = max(minimum_rows, terminal_height - reserved_rows)
    visible_rows = min(visible_rows, total_items)
    start = max(0, min(selected_index - (visible_rows // 2), total_items - visible_rows))
    end = start + visible_rows
    return start, end


def render_menu_table(
    title: str,
    items: list[PickerMenuItem],
    selected_index: int,
    breadcrumb: list[str],
    footer: str,
) -> None:
    console.clear()
    header = " → ".join(breadcrumb) if breadcrumb else title
    console.print(Panel(header, title=title, border_style="bright_blue", expand=False))

    table = Table(box=box.ROUNDED, header_style="bold bright_cyan")
    table.add_column("Sel", width=3, justify="center")
    table.add_column("Option", style="white", overflow="fold")
    table.add_column("Details", style="bright_black", overflow="fold")

    start, end = calculate_visible_window(len(items), selected_index, reserved_rows=9)
    for index in range(start, end):
        item = items[index]
        marker = "➜" if index == selected_index else " "
        style = "bold bright_green" if index == selected_index else ""
        table.add_row(marker, item.label, item.description, style=style)

    console.print(table)
    if len(items) > (end - start):
        console.print(f"[bright_black]Showing {start + 1}-{end} of {len(items)} options[/bright_black]")
    console.print(f"[bright_black]{footer}[/bright_black]")


def prompt_menu_choice(
    title: str,
    items: list[PickerMenuItem],
    breadcrumb: list[str],
    allow_back: bool = True,
    allow_cancel_in_legacy: bool = True,
) -> str:
    if not items:
        return 'back'

    if readchar is None or not sys.stdin.isatty():
        options = [item.label for item in items]
        selection = prompt_for_number_legacy(
            title,
            options,
            include_cancel=True,
            cancel_label='Back' if allow_back else 'Cancel',
        )
        if selection is None:
            return 'back' if allow_back else 'cancel'
        return items[selection].key

    selected_index = 0
    footer = '↑/↓ or j/k to move • Enter to select • b or ← to go back • q to cancel'
    while True:
        render_menu_table(title, items, selected_index, breadcrumb, footer)
        key = readchar.readkey()
        if key in (readchar.key.UP, 'k'):
            selected_index = (selected_index - 1) % len(items)
        elif key in (readchar.key.DOWN, 'j'):
            selected_index = (selected_index + 1) % len(items)
        elif key in (readchar.key.ENTER, readchar.key.CR, readchar.key.LF):
            return items[selected_index].key
        elif key in ('q', 'Q'):
            return 'cancel'
        elif allow_back and key in ('b', 'B', readchar.key.LEFT):
            return 'back'


def prompt_for_number_legacy(
    title: str,
    options: list[str],
    include_cancel: bool = True,
    cancel_label: str = 'Back',
) -> int | None:
    console.print(Panel(title, border_style="bright_blue", expand=False))
    for index, option in enumerate(options, start=1):
        console.print(f"[bright_cyan]{index}[/bright_cyan]. {option}")
    if include_cancel:
        console.print(f"[bright_black]0[/bright_black]. {cancel_label}")

    while True:
        try:
            choice = console.input("[bold bright_cyan]Choose an option:[/bold bright_cyan] ").strip()
        except EOFError:
            return None
        if include_cancel and choice == '0':
            return None
        if choice.isdigit():
            numeric = int(choice)
            if 1 <= numeric <= len(options):
                return numeric - 1
        valid_range = f"0-{len(options)}" if include_cancel else f"1-{len(options)}"
        print_warning(f"Invalid selection. Enter a number from the list ({valid_range}).")


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = '[Y/n]' if default else '[y/N]'
    try:
        choice = console.input(f"[bold bright_cyan]{prompt} {suffix}:[/bold bright_cyan] ").strip().lower()
    except EOFError:
        return default
    if not choice:
        return default
    return choice in {'y', 'yes'}


def prompt_for_result_choice(title: str, results: list[PickerVPNResult], preferences: dict[str, str], breadcrumb: list[str]) -> PickerVPNResult | str | None:
    if not results:
        print_warning('No VPN results are available in this view.')
        return 'back'

    if readchar is None or not sys.stdin.isatty():
        render_picker_results_table(title, results, preferences)
        selection = prompt_for_number_legacy(title, [result.filename for result in results])
        if selection is None:
            return 'back'
        return results[selection]

    selected_index = 0
    while True:
        console.clear()
        console.print(Panel(" → ".join(breadcrumb), title=title, border_style="bright_blue", expand=False))
        render_picker_results_table(title, results, preferences, selected_index=selected_index)
        console.print("[bright_black]↑/↓ or j/k to move • Enter to select • b or ← to go back • q to cancel[/bright_black]")
        key = readchar.readkey()
        if key in (readchar.key.UP, 'k'):
            selected_index = (selected_index - 1) % len(results)
        elif key in (readchar.key.DOWN, 'j'):
            selected_index = (selected_index + 1) % len(results)
        elif key in (readchar.key.ENTER, readchar.key.CR, readchar.key.LF):
            return results[selected_index]
        elif key in ('q', 'Q'):
            return None
        elif key in ('b', 'B', readchar.key.LEFT):
            return 'back'


def save_picker_preference(result: PickerVPNResult, target: str) -> None:
    if target == 'profile_favorite':
        update_picker_preferences({'favorite_profiles': result.filename}, append_keys={'favorite_profiles'})
        print_success(f"Saved favorite profile: {result.filename}")
    elif target == 'country_favorite' and result.country_code:
        update_picker_preferences({'favorite_countries': result.country_code}, append_keys={'favorite_countries'})
        print_success(f"Saved favorite country: {result.country_name}")
    elif target == 'region_favorite':
        update_picker_preferences({'favorite_regions': result.region}, append_keys={'favorite_regions'})
        print_success(f"Saved favorite region: {result.region}")
    elif target == 'city_favorite':
        update_picker_preferences({'favorite_cities': result.city_name}, append_keys={'favorite_cities'})
        print_success(f"Saved favorite city: {result.city_name}")
    elif target == 'profile_default':
        update_picker_preferences({'default_mode': 'profile', 'default_value': result.filename})
        print_success(f"Saved default profile: {result.filename}")
    elif target == 'country_default' and result.country_code:
        update_picker_preferences({'default_mode': 'country', 'default_value': result.country_code})
        print_success(f"Saved default country: {result.country_name}")
    elif target == 'region_default':
        update_picker_preferences({'default_mode': 'region', 'default_value': result.region})
        print_success(f"Saved default region: {result.region}")
    elif target == 'city_default':
        update_picker_preferences({'default_mode': 'city', 'default_value': result.city_name})
        print_success(f"Saved default city: {result.city_name}")


def prompt_picker_actions(result: PickerVPNResult) -> None:
    items = [
        PickerMenuItem('profile_favorite', 'Make this VPN a favorite'),
        PickerMenuItem('country_favorite', "Make this VPN's country a favorite", result.country_name),
        PickerMenuItem('region_favorite', "Make this VPN's region a favorite", result.region),
        PickerMenuItem('city_favorite', "Make this VPN's city a favorite", result.city_name),
        PickerMenuItem('profile_default', 'Set this VPN as default'),
        PickerMenuItem('country_default', "Set this VPN's country as default", result.country_name),
        PickerMenuItem('region_default', "Set this VPN's region as default", result.region),
        PickerMenuItem('city_default', "Set this VPN's city as default", result.city_name),
        PickerMenuItem('done', 'Done'),
    ]

    while True:
        selected = prompt_menu_choice('Favorite / Default actions', items, ['Picker', result.country_name, result.filename], allow_back=True)
        if selected in {'cancel', 'back', 'done'}:
            return
        save_picker_preference(result, selected)


def choose_random_result(results: list[PickerVPNResult]) -> PickerVPNResult:
    return random.choice(results)


def select_best_by_mode(results: list[PickerVPNResult], mode: str) -> PickerVPNResult:
    successful = [result for result in results if result.status.lower() == 'success' and result.latency_ms is not None]
    if not successful:
        raise ValueError('No successful VPN results were found in the last scan log.')

    if mode == 'best_score':
        return max(successful, key=lambda result: result.score)
    if mode == 'best_latency':
        return min(successful, key=lambda result: result.latency_ms or float('inf'))
    if mode == 'best_packet_loss':
        return min(successful, key=lambda result: ((result.packet_loss if result.packet_loss is not None else 100.0), result.latency_ms or float('inf')))
    if mode == 'best_privacy':
        return max(successful, key=lambda result: (result.privacy_score, -(result.latency_ms or float('inf'))))
    raise ValueError(f'Unsupported picker mode: {mode}')


def filter_results_by_location(results: list[PickerVPNResult], location_type: str, location_value: str) -> list[PickerVPNResult]:
    successful = [result for result in results if result.status.lower() == 'success' and result.latency_ms is not None]
    normalized = location_value.strip().lower()
    if location_type == 'country':
        return [result for result in successful if (result.country_code or '').lower() == normalized or result.country_name.lower() == normalized]
    if location_type == 'region':
        return [result for result in successful if result.region.lower() == normalized]
    if location_type == 'city':
        return [result for result in successful if result.city_name.lower() == normalized]
    if location_type == 'profile':
        return [result for result in successful if result.filename.lower() == normalized]
    return []


def run_with_default_preference(results: list[PickerVPNResult], preferences: dict[str, str]) -> PickerVPNResult | None:
    default_mode = preferences.get('default_mode', '')
    default_value = preferences.get('default_value', '')
    if not default_mode or not default_value:
        return None

    if default_mode in {'best_score', 'best_latency', 'best_packet_loss', 'best_privacy'}:
        return select_best_by_mode(results, default_mode)

    matching = filter_results_by_location(results, default_mode, default_value)
    if not matching:
        return None

    if default_mode in {'country', 'region', 'city'}:
        return choose_random_result(matching)
    return matching[0]


def run_interactive_picker(results: list[PickerVPNResult], preferences: dict[str, str]) -> tuple[PickerVPNResult | None, bool, bool]:
    favorite_profiles, favorite_countries, favorite_regions, favorite_cities, _default_mode, _default_value = get_preference_sets(preferences)
    successful = [result for result in results if result.status.lower() == 'success' and result.latency_ms is not None]
    if not successful:
        raise ValueError('No successful VPN results were found in the last scan log.')

    while True:
        main_items = [
            PickerMenuItem('best_score', 'Best score', 'Highest combined score'),
            PickerMenuItem('best_latency', 'Best latency', 'Lowest latency'),
            PickerMenuItem('best_packet_loss', 'Best packet loss', 'Lowest packet loss, then latency'),
            PickerMenuItem('best_privacy', 'Best privacy', 'Highest privacy score, then latency'),
            PickerMenuItem('country', 'Browse by country', 'Choose a country first'),
            PickerMenuItem('city', 'Browse by city', 'Choose a city, then use a random profile from it'),
            PickerMenuItem('region', 'Browse by region', 'Region → country → VPN'),
            PickerMenuItem('favorite_profile', 'Favorite profiles', f'{len(favorite_profiles)} saved'),
            PickerMenuItem('favorite_country', 'Favorite countries', f'{len(favorite_countries)} saved'),
            PickerMenuItem('favorite_region', 'Favorite regions', f'{len(favorite_regions)} saved'),
            PickerMenuItem('favorite_city', 'Favorite cities', f'{len(favorite_cities)} saved'),
        ]
        selected = prompt_menu_choice('Interactive VPN Picker', main_items, ['Picker'], allow_back=False, allow_cancel_in_legacy=True)
        if selected in {'cancel', 'back'}:
            return None, False, False

        chosen: PickerVPNResult | None = None

        if selected in {'best_score', 'best_latency', 'best_packet_loss', 'best_privacy'}:
            chosen = select_best_by_mode(successful, selected)
        elif selected == 'country':
            while True:
                countries = sorted({result.country_name for result in successful if result.country_code})
                country_items = [
                    PickerMenuItem(country, country, f"{len([r for r in successful if r.country_name == country])} profiles")
                    for country in countries
                ]
                country_choice = prompt_menu_choice('Choose a country', country_items, ['Picker', 'Countries'])
                if country_choice == 'cancel':
                    return None, False, False
                if country_choice == 'back':
                    break
                matches = [result for result in successful if result.country_name == country_choice]
                vpn_choice = prompt_for_result_choice('Choose a VPN', matches, preferences, ['Picker', 'Countries', country_choice])
                if vpn_choice is None:
                    return None, False, False
                if vpn_choice == 'back':
                    continue
                if isinstance(vpn_choice, str):
                    continue
                chosen = vpn_choice
                break
        elif selected == 'city':
            while True:
                cities = sorted({result.city_name for result in successful if result.city_name != 'Unknown'})
                city_items = [
                    PickerMenuItem(city, city, f"{len([r for r in successful if r.city_name == city])} profiles • random on run")
                    for city in cities
                ]
                city_choice = prompt_menu_choice('Choose a city', city_items, ['Picker', 'Cities'])
                if city_choice == 'cancel':
                    return None, False, False
                if city_choice == 'back':
                    break
                matches = [result for result in successful if result.city_name == city_choice]
                chosen = choose_random_result(matches)
                break
        elif selected == 'region':
            while True:
                regions = sorted({result.region for result in successful if result.region != 'Unknown'})
                region_items = [
                    PickerMenuItem(region, region, f"{len([r for r in successful if r.region == region])} profiles")
                    for region in regions
                ]
                region_choice = prompt_menu_choice('Choose a region', region_items, ['Picker', 'Regions'])
                if region_choice == 'cancel':
                    return None, False, False
                if region_choice == 'back':
                    break
                region_matches = [result for result in successful if result.region == region_choice]
                while True:
                    countries = sorted({result.country_name for result in region_matches if result.country_code})
                    country_items = [
                        PickerMenuItem(country, country, f"{len([r for r in region_matches if r.country_name == country])} profiles")
                        for country in countries
                    ]
                    country_choice = prompt_menu_choice('Choose a country in region', country_items, ['Picker', 'Regions', region_choice])
                    if country_choice == 'cancel':
                        return None, False, False
                    if country_choice == 'back':
                        break
                    matches = [result for result in region_matches if result.country_name == country_choice]
                    vpn_choice = prompt_for_result_choice('Choose a VPN', matches, preferences, ['Picker', 'Regions', region_choice, country_choice])
                    if vpn_choice is None:
                        return None, False, False
                    if vpn_choice == 'back':
                        continue
                    if isinstance(vpn_choice, str):
                        continue
                    chosen = vpn_choice
                    break
                if chosen is not None:
                    break
        elif selected == 'favorite_profile':
            matches = [result for result in successful if result.filename in favorite_profiles]
            if not matches:
                print_warning('No favorite profiles are configured.')
                continue
            vpn_choice = prompt_for_result_choice('Choose a favorite profile', matches, preferences, ['Picker', 'Favorite profiles'])
            if vpn_choice is None:
                return None, False, False
            if vpn_choice == 'back':
                continue
            if isinstance(vpn_choice, str):
                continue
            chosen = vpn_choice
        elif selected == 'favorite_country':
            matches = [result for result in successful if (result.country_code or '') in favorite_countries]
            if not matches:
                print_warning('No favorite countries are configured.')
                continue
            while True:
                countries = sorted({result.country_name for result in matches})
                country_items = [
                    PickerMenuItem(country, country, f"{len([r for r in matches if r.country_name == country])} profiles")
                    for country in countries
                ]
                country_choice = prompt_menu_choice('Choose a favorite country', country_items, ['Picker', 'Favorite countries'])
                if country_choice == 'cancel':
                    return None, False, False
                if country_choice == 'back':
                    break
                grouped_matches = [result for result in matches if result.country_name == country_choice]
                vpn_choice = prompt_for_result_choice('Choose a VPN', grouped_matches, preferences, ['Picker', 'Favorite countries', country_choice])
                if vpn_choice is None:
                    return None, False, False
                if vpn_choice == 'back':
                    continue
                if isinstance(vpn_choice, str):
                    continue
                chosen = vpn_choice
                break
        elif selected == 'favorite_region':
            matches = [result for result in successful if result.region in favorite_regions]
            if not matches:
                print_warning('No favorite regions are configured.')
                continue
            while True:
                regions = sorted({result.region for result in matches})
                region_items = [
                    PickerMenuItem(region, region, f"{len([r for r in matches if r.region == region])} profiles")
                    for region in regions
                ]
                region_choice = prompt_menu_choice('Choose a favorite region', region_items, ['Picker', 'Favorite regions'])
                if region_choice == 'cancel':
                    return None, False, False
                if region_choice == 'back':
                    break
                region_matches = [result for result in matches if result.region == region_choice]
                countries = sorted({result.country_name for result in region_matches if result.country_code})
                while True:
                    country_items = [
                        PickerMenuItem(country, country, f"{len([r for r in region_matches if r.country_name == country])} profiles")
                        for country in countries
                    ]
                    country_choice = prompt_menu_choice('Choose a country in favorite region', country_items, ['Picker', 'Favorite regions', region_choice])
                    if country_choice == 'cancel':
                        return None, False, False
                    if country_choice == 'back':
                        break
                    grouped_matches = [result for result in region_matches if result.country_name == country_choice]
                    vpn_choice = prompt_for_result_choice('Choose a VPN', grouped_matches, preferences, ['Picker', 'Favorite regions', region_choice, country_choice])
                    if vpn_choice is None:
                        return None, False, False
                    if vpn_choice == 'back':
                        continue
                    if isinstance(vpn_choice, str):
                        continue
                    chosen = vpn_choice
                    break
                if chosen is not None:
                    break
        else:
            matches = [result for result in successful if result.city_name in favorite_cities]
            if not matches:
                print_warning('No favorite cities are configured.')
                continue
            while True:
                cities = sorted({result.city_name for result in matches if result.city_name != 'Unknown'})
                city_items = [
                    PickerMenuItem(city, city, f"{len([r for r in matches if r.city_name == city])} profiles • random on run")
                    for city in cities
                ]
                city_choice = prompt_menu_choice('Choose a favorite city', city_items, ['Picker', 'Favorite cities'])
                if city_choice == 'cancel':
                    return None, False, False
                if city_choice == 'back':
                    break
                grouped_matches = [result for result in matches if result.city_name == city_choice]
                chosen = choose_random_result(grouped_matches)
                break

        if chosen is None:
            continue

        console.clear()
        console.print(Panel(format_picker_choice(chosen), title='Picker Selection', border_style='bright_green', expand=False))
        prompt_picker_actions(chosen)
        should_run = prompt_yes_no('Run this VPN now?', default=False)
        use_killswitch = prompt_yes_no('Enable killswitch?', default=False) if should_run else False
        return chosen, should_run, use_killswitch


def prompt_startup_menu() -> str:
    items = [
        PickerMenuItem('scan', 'Run a new latency scan', 'Test all available VPN profiles'),
        PickerMenuItem('last_scan', 'View last scan results', 'Show saved results and last run time'),
        PickerMenuItem('pick', 'Open VPN picker', 'Choose by score, latency, favorites, country, or region'),
        PickerMenuItem('select', 'Select best VPN from saved scan', 'Display the lowest-latency saved result'),
        PickerMenuItem('run_default', 'Run VPN using saved default or best latency', 'Uses saved default preference when available'),
        PickerMenuItem('quit', 'Quit', 'Exit without doing anything'),
    ]
    return prompt_menu_choice('StealthSpanner Menu', items, ['Home'], allow_back=False, allow_cancel_in_legacy=True)


def maybe_select_and_run_vpn(args: argparse.Namespace, directory: Path, preferences: dict[str, str], privacy_config: dict) -> int | None:
    if args.killswitch and not args.run:
        print("Error: --killswitch can only be used with --run.", file=sys.stderr)
        return 1

    if args.print_only and args.run:
        print("Error: --print-only cannot be combined with --run.", file=sys.stderr)
        return 1

    if not (args.select_vpn or args.print_only or args.run or args.pick_vpn):
        return None

    script_dir = Path(__file__).resolve().parent
    if args.log:
        log_path = (script_dir / args.log).resolve() if not Path(args.log).is_absolute() else Path(args.log)
    else:
        log_path = get_last_scan_log_path()

    vpn_dir = directory.resolve()
    killswitch_path = (
        (script_dir / args.killswitch_script).resolve()
        if not Path(args.killswitch_script).is_absolute()
        else Path(args.killswitch_script)
    )
    creds_file = Path(args.creds_file).expanduser()

    try:
        parsed_results = parse_latency_log(log_path)
        picker_results = build_picker_results(parsed_results, privacy_config)
        successful = sorted(
            (result for result in picker_results if result.status.lower() == 'success' and result.latency_ms is not None),
            key=lambda result: result.latency_ms or float('inf'),
        )
        if args.pick_vpn:
            chosen, picker_run_now, picker_use_killswitch = run_interactive_picker(successful, preferences)
            if chosen is None:
                return 0
            if picker_run_now:
                args.run = True
                args.killswitch = picker_use_killswitch
            else:
                render_selection_summary(
                    VPNSelectionResult(chosen.filename, chosen.hostname, chosen.latency_ms or 0.0, chosen.status),
                    resolve_ovpn_path(chosen.filename, vpn_dir),
                    'display only',
                    log_path,
                    vpn_dir,
                )
                return 0
        elif args.run:
            chosen = run_with_default_preference(successful, preferences) or select_best_by_mode(successful, 'best_latency')
        else:
            chosen = select_best_by_mode(successful, 'best_latency')
        ovpn_path = resolve_ovpn_path(chosen.filename, vpn_dir)
    except (FileNotFoundError, ValueError) as exc:
        print_error(str(exc))
        return 1

    if args.print_only:
        print(ovpn_path)
        return 0

    top_count = max(args.top, 1)
    print_banner("StealthSpanner VPN Selection", "Choose from saved VPN scan results")
    render_selection_table([
        VPNSelectionResult(item.filename, item.hostname, item.latency_ms or 0.0, item.status)
        for item in successful[:top_count]
    ], top_count)

    mode = "display only"
    if args.run and args.killswitch:
        mode = "OpenVPN + killswitch"
    elif args.run:
        mode = "OpenVPN"
    render_selection_summary(
        VPNSelectionResult(chosen.filename, chosen.hostname, chosen.latency_ms or 0.0, chosen.status),
        ovpn_path,
        mode,
        log_path,
        vpn_dir,
    )

    if not args.run:
        return 0

    print()
    if args.killswitch:
        render_connection_panel("OpenVPN + killswitch", ovpn_path, killswitch_path=killswitch_path)
        print_info(f"Launching killswitch with: {ovpn_path}")
        try:
            return run_with_killswitch(ovpn_path, killswitch_path, verbose=args.verbose)
        except FileNotFoundError as exc:
            print_error(str(exc))
            return 1

    render_connection_panel("OpenVPN", ovpn_path, creds_file=creds_file)
    print_info(f"Launching OpenVPN with: {ovpn_path}")
    return run_openvpn(ovpn_path, creds_file, verbose=args.verbose)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Test latency for VPN servers from .ovpn files, or select and run the best result',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--pings', '-p',
        type=int,
        default=4,
        help='Number of ping attempts per host (default: 4)'
    )
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=20,
        help='Number of concurrent threads (default: 20)'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=float,
        default=3.0,
        help='Ping timeout in seconds (default: 3.0)'
    )
    parser.add_argument(
        '--directory', '-d',
        type=str,
        default=None,
        help='Directory containing .ovpn files (overrides config file setting)'
    )
    parser.add_argument(
        '--no-download',
        action='store_true',
        help='Skip downloading VPN config files (default: download if enabled in config)'
    )
    parser.add_argument(
        '--provider',
        type=str,
        default=None,
        help='VPN provider to use (overrides config file setting)'
    )
    parser.add_argument(
        '--last-scan',
        action='store_true',
        help='Show results from the last saved latency scan'
    )
    parser.add_argument(
        '--select-vpn',
        action='store_true',
        help='Select the best VPN from the latency log without rerunning latency tests'
    )
    parser.add_argument(
        '--log',
        default=None,
        help='Path to the latency log file (default: XDG state path, with legacy fallback)'
    )
    parser.add_argument(
        '--top',
        type=int,
        default=1,
        help='Show the top N successful log results before selecting the best one (default: 1)'
    )
    parser.add_argument(
        '--pick-vpn',
        action='store_true',
        help='Open the interactive TUI VPN picker'
    )
    parser.add_argument(
        '-r', '--run',
        action='store_true',
        help='Run the selected VPN configuration'
    )
    parser.add_argument(
        '-k', '--killswitch',
        action='store_true',
        help='Enable killswitch mode when running the selected VPN (off by default)'
    )
    parser.add_argument(
        '--killswitch-script',
        default=KILLSWITCH_DEFAULT,
        help=f'Path to the killswitch script (default: {KILLSWITCH_DEFAULT})'
    )
    parser.add_argument(
        '--creds-file',
        default=CREDS_FILE_DEFAULT,
        help=f'Path to the OpenVPN credentials file (default: {CREDS_FILE_DEFAULT})'
    )
    parser.add_argument(
        '--print-only',
        action='store_true',
        help='Print only the resolved .ovpn path'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose VPN connection output instead of concise status messages'
    )
    
    args = parser.parse_args()

    no_explicit_action = not any([
        args.last_scan,
        args.select_vpn,
        args.pick_vpn,
        args.run,
        args.print_only,
    ])

    if no_explicit_action:
        menu_choice = prompt_startup_menu()
        if menu_choice in {'cancel', 'quit'}:
            console.print('[bright_black]Goodbye.[/bright_black]')
            sys.exit(0)
        if menu_choice == 'last_scan':
            args.last_scan = True
        elif menu_choice == 'pick':
            args.pick_vpn = True
        elif menu_choice == 'select':
            args.select_vpn = True
        elif menu_choice == 'run_default':
            args.run = True
        elif menu_choice == 'scan':
            pass
    
    # Load configuration
    try:
        config = load_config()
    except (OSError, ValueError) as e:
        error_msg = colorize(f"Error loading configuration: {e}", Colors.RED, sys.stderr)
        print(error_msg, file=sys.stderr)
        sys.exit(1)
    
    # Load privacy configuration
    privacy_enabled = is_privacy_scoring_enabled(config)
    privacy_weight = get_privacy_weight(config)
    privacy_scores = get_privacy_scores(config)
    privacy_config = {
        'enabled': privacy_enabled,
        'weight': privacy_weight,
        'scores': privacy_scores
    }
    picker_preferences = get_picker_preferences(config)
    
    # Determine provider
    provider_name = args.provider if args.provider else get_default_provider(config)
    
    # Determine directory
    if args.directory:
        directory = Path(args.directory)
    else:
        directory_name = get_config_directory(config, provider_name)
        directory = Path(directory_name)
    
    script_dir = Path(__file__).resolve().parent
    selected_log_path = (script_dir / args.log).resolve() if args.log and not Path(args.log).is_absolute() else Path(args.log) if args.log else get_last_scan_log_path()

    if args.last_scan:
        sys.exit(show_last_scan(selected_log_path, privacy_config))

    selection_result = maybe_select_and_run_vpn(args, directory, picker_preferences, privacy_config)
    if selection_result is not None:
        sys.exit(selection_result)

    # Check if we should download configs
    should_download = not args.no_download and should_auto_download(config)
    
    # Download configs if needed
    if should_download:
        download_msg = colorize(
            f"Downloading {provider_name} VPN configurations...",
            Colors.BRIGHT_YELLOW
        )
        print(download_msg)
        
        try:
            download_vpn_configs(provider_name, config, directory)
            print()  # Blank line after download
        except (OSError, RuntimeError, ValueError) as e:
            print_warning(f"Failed to download configs: {e}. Continuing with existing configs.")
            print()
    
    # Set up log file in the XDG state directory
    log_file_path = get_state_log_path()
    ensure_directory(log_file_path.parent)

    try:
        with log_file_path.open('w', encoding='utf-8') as log_file:
            # Discover .ovpn files (progress to stdout only)
            files_to_hosts = discover_ovpn_files(directory)

            if not files_to_hosts:
                print_error("No valid .ovpn files found")
                sys.exit(1)

            print_banner("StealthSpanner", "Latency testing and smart VPN selection")
            print_info(f"Testing {len(files_to_hosts)} hosts with {args.pings} pings each")
            print_info(f"Using {args.workers} concurrent workers")
            print_info(f"Timeout: {args.timeout} seconds per ping")
            print()

            # Test hosts concurrently (progress to stdout only)
            results = []
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                future_to_host = {
                    executor.submit(
                        test_host_latency,
                        filename,
                        hostname,
                        country_code,
                        args.pings,
                        args.timeout,
                        privacy_config,
                    ): (filename, hostname, country_code)
                    for filename, (hostname, country_code) in files_to_hosts.items()
                }

                total = len(files_to_hosts)

                with Progress(
                    SpinnerColumn(style="bright_cyan"),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=None),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task_id = progress.add_task("Testing VPN endpoints", total=total)

                    for future in as_completed(future_to_host):
                        try:
                            result = future.result()
                            results.append(result)
                        except (OSError, RuntimeError, ValueError) as e:
                            filename, hostname, country_code = future_to_host[future]
                            print_error(f"Error testing {hostname} from {filename}: {e}")
                            results.append({
                                'filename': filename,
                                'hostname': hostname,
                                'country_code': country_code,
                                'country_name': get_country_name(country_code),
                                'privacy_score': 0,
                                'latency': None,
                                'status': f'Error: {e!s}',
                            })

                        progress.update(task_id, advance=1)

            format_output(results)
            write_parseable_log(results, log_file, log_file_path)
    finally:
        console.print(
            Panel(
                f"[bright_cyan]Results saved to:[/bright_cyan] {log_file_path}",
                title="Logs",
                border_style="bright_blue",
                expand=False,
            )
        )


if __name__ == '__main__':
    main()

