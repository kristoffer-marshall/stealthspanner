#!/usr/bin/env python3
"""In-process UFW killswitch apply, status, and restore helpers."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from xdg_paths import ensure_directory, get_killswitch_marker_path

LAN_SUBNET = "192.168.1.0/24"
DEFAULT_REMOTE_PORT = "443"
REMOTE_LINE_RE = re.compile(r"^remote\s+(\S+)(?:\s+(\S+))?")
DEFAULT_OUTGOING_RE = re.compile(
    r"^Default:\s+.*\b(deny|allow|reject)\s+\(outgoing\)",
    re.IGNORECASE | re.MULTILINE,
)
STATUS_ACTIVE_RE = re.compile(r"^Status:\s+(active|inactive)", re.IGNORECASE | re.MULTILINE)
TUN0_ALLOW_RE = re.compile(r"\bon\s+tun0\b.*\bALLOW\b|\bALLOW\b.*\bon\s+tun0\b", re.IGNORECASE)


class KillswitchError(RuntimeError):
    """Raised when a killswitch UFW operation fails."""


@dataclass(frozen=True)
class FirewallStatus:
    ufw_active: bool
    default_outgoing: str
    marker_present: bool
    tun0_allowed: bool
    raw_status: str

    @property
    def is_killswitch_active(self) -> bool:
        if self.default_outgoing != "deny":
            return False
        return self.marker_present or self.tun0_allowed


def parse_ovpn_remote(ovpn_path: Path) -> tuple[str, str]:
    """Return (host, port) from the first `remote` line. Port defaults to 443."""
    try:
        with ovpn_path.open(encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line.startswith("remote "):
                    continue
                match = REMOTE_LINE_RE.match(line)
                if match:
                    host = match.group(1)
                    port = match.group(2) or DEFAULT_REMOTE_PORT
                    return host, port
    except OSError as exc:
        raise KillswitchError(f"Could not read OpenVPN config {ovpn_path}: {exc}") from exc

    raise KillswitchError(f"No 'remote' line found in {ovpn_path}")


def _marker_path() -> Path:
    return get_killswitch_marker_path()


def write_killswitch_marker() -> None:
    path = _marker_path()
    ensure_directory(path.parent)
    path.write_text("active\n", encoding="utf-8")


def clear_killswitch_marker() -> None:
    path = _marker_path()
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise KillswitchError(f"Could not remove killswitch marker {path}: {exc}") from exc


def marker_exists() -> bool:
    return _marker_path().is_file()


def run_ufw(
    args: list[str],
    *,
    verbose: bool = False,
    noninteractive: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run `sudo ufw`. Stderr stays on the terminal so sudo can prompt for a password.

    `noninteractive=True` uses `sudo -n` and captures stderr. A missing cached
    credential fails immediately instead of hanging a latency scan.
    """
    command = ["sudo", *(["-n"] if noninteractive else []), "ufw", *args]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE if noninteractive else None,
        text=True,
        check=False,
    )
    if verbose and (result.stdout or "").strip():
        print(result.stdout.rstrip())
    if result.returncode != 0:
        captured = (result.stderr or result.stdout or "").strip()
        if captured:
            detail = captured
        elif noninteractive:
            detail = f"exit {result.returncode}"
        else:
            detail = f"exit {result.returncode} (see terminal output above)"
        raise KillswitchError(f"ufw {' '.join(args)} failed: {detail}")
    return result


def parse_ufw_status(raw: str, *, marker_present: bool) -> FirewallStatus:
    status_match = STATUS_ACTIVE_RE.search(raw)
    outgoing_match = DEFAULT_OUTGOING_RE.search(raw)
    default_outgoing = outgoing_match.group(1).lower() if outgoing_match else "unknown"
    ufw_active = bool(status_match and status_match.group(1).lower() == "active")
    return FirewallStatus(
        ufw_active=ufw_active,
        default_outgoing=default_outgoing,
        marker_present=marker_present,
        tun0_allowed=bool(TUN0_ALLOW_RE.search(raw)),
        raw_status=raw,
    )


def firewall_status(*, verbose: bool = False, noninteractive: bool = False) -> FirewallStatus:
    result = run_ufw(["status", "verbose"], verbose=verbose, noninteractive=noninteractive)
    return parse_ufw_status(result.stdout or "", marker_present=marker_exists())


def apply_killswitch(ovpn_path: Path, *, verbose: bool = False) -> tuple[str, str]:
    """Apply session killswitch UFW rules. Returns (remote_host, remote_port)."""
    host, port = parse_ovpn_remote(ovpn_path)
    commands = [
        ["--force", "reset"],
        ["default", "deny", "incoming"],
        ["default", "deny", "outgoing"],
        ["allow", "in", "to", LAN_SUBNET],
        ["allow", "out", "to", LAN_SUBNET],
        ["allow", "out", "53"],
        ["allow", "in", "53"],
        ["allow", "out", "67,68/udp"],
        ["allow", "in", "67,68/udp"],
        ["allow", "out", "on", "tun0", "from", "any", "to", "any"],
        ["allow", "in", "on", "tun0", "from", "any", "to", "any"],
        ["allow", "out", "to", "any", "port", port],
        ["--force", "enable"],
    ]
    changed = False
    try:
        for args in commands:
            run_ufw(args, verbose=verbose)
            changed = True
    except (KillswitchError, KeyboardInterrupt):
        if changed:
            try:
                restore_firewall(verbose=verbose, clear_marker=False)
            except KillswitchError:
                pass
        raise

    write_killswitch_marker()
    return host, port


def restore_firewall(*, verbose: bool = False, clear_marker: bool = True) -> None:
    """Reset UFW to default allow-outgoing / deny-incoming and optionally clear the marker."""
    run_ufw(["--force", "reset"], verbose=verbose)
    run_ufw(["default", "allow", "outgoing"], verbose=verbose)
    run_ufw(["default", "deny", "incoming"], verbose=verbose)
    run_ufw(["--force", "enable"], verbose=verbose)
    if clear_marker:
        clear_killswitch_marker()
