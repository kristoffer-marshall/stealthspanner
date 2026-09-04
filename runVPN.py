#!/usr/bin/env python3
"""Select the lowest-latency .ovpn file from vpn_latency_checker.log and optionally run it.

This helper reads the generated latency log, finds the best successful VPN
configuration, prints the selected .ovpn path, and can optionally connect to it.
By default it runs OpenVPN directly; when ``-k``/``--killswitch`` is supplied,
it delegates to the existing ``killswitch`` script.

The script is intentionally small and conservative so additional selection
features (for example favorite regions) can be added later without changing
its basic flow.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


LOG_DEFAULT = "vpn_latency_checker.log"
VPN_DIR_DEFAULT = "IPVanish"
KILLSWITCH_DEFAULT = "killswitch"
CREDS_FILE_DEFAULT = "~/.vpn_creds"


@dataclass(frozen=True)
class VPNResult:
    filename: str
    hostname: str
    latency_ms: float
    status: str


def parse_latency_log(log_path: Path) -> list[VPNResult]:
    if not log_path.is_file():
        raise FileNotFoundError(f"Latency log not found: {log_path}")

    results: list[VPNResult] = []
    line_pattern = re.compile(r"^(?P<filename>.+?\.ovpn)\s+(?P<hostname>\S+)\s+(?P<latency>\d+(?:\.\d+)?)\s+(?P<status>.+?)\s*$")

    for raw_line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("=", "Filename")):
            continue

        match = line_pattern.match(line)
        if not match:
            continue

        results.append(
            VPNResult(
                filename=match.group("filename"),
                hostname=match.group("hostname"),
                latency_ms=float(match.group("latency")),
                status=match.group("status").strip(),
            )
        )

    return results


def pick_best_result(results: Iterable[VPNResult]) -> VPNResult:
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


def ensure_credentials(creds_file: Path) -> Path:
    if creds_file.is_file():
        return creds_file

    print(f"VPN credentials not found at {creds_file}.")
    print("Let's set them up for future use.")
    vpn_user = input("Enter VPN Username: ").strip()
    vpn_pass = getpass.getpass("Enter VPN Password: ")

    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(f"{vpn_user}\n{vpn_pass}\n", encoding="utf-8")
    os.chmod(creds_file, stat.S_IRUSR | stat.S_IWUSR)
    print(f"Credentials saved securely to {creds_file}")
    return creds_file


def run_openvpn(ovpn_path: Path, creds_file: Path) -> int:
    creds_path = ensure_credentials(creds_file)
    completed = subprocess.run(
        [
            "sudo",
            "openvpn",
            "--mute-replay-warnings",
            "--config",
            str(ovpn_path),
            "--auth-user-pass",
            str(creds_path),
        ],
        check=False,
    )
    return completed.returncode


def run_with_killswitch(ovpn_path: Path, killswitch_path: Path) -> int:
    if not killswitch_path.is_file():
        raise FileNotFoundError(f"killswitch script not found: {killswitch_path}")

    completed = subprocess.run(
        ["bash", str(killswitch_path), str(ovpn_path)],
        check=False,
    )
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select the lowest-latency .ovpn file from vpn_latency_checker.log and optionally run it"
    )
    parser.add_argument(
        "--log",
        default=LOG_DEFAULT,
        help=f"Path to the latency log file (default: {LOG_DEFAULT})",
    )
    parser.add_argument(
        "--vpn-dir",
        default=VPN_DIR_DEFAULT,
        help=f"Directory containing .ovpn files (default: {VPN_DIR_DEFAULT})",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=1,
        help="Show the top N successful results before selecting the best one (default: 1)",
    )
    parser.add_argument(
        "-r",
        "--run",
        action="store_true",
        help="Run the selected VPN configuration",
    )
    parser.add_argument(
        "-k",
        "--killswitch",
        action="store_true",
        help="Enable killswitch mode when running the selected VPN (off by default)",
    )
    parser.add_argument(
        "--killswitch-script",
        default=KILLSWITCH_DEFAULT,
        help=f"Path to the killswitch script (default: {KILLSWITCH_DEFAULT})",
    )
    parser.add_argument(
        "--creds-file",
        default=CREDS_FILE_DEFAULT,
        help=f"Path to the OpenVPN credentials file (default: {CREDS_FILE_DEFAULT})",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print only the resolved .ovpn path",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    log_path = (script_dir / args.log).resolve() if not Path(args.log).is_absolute() else Path(args.log)
    vpn_dir = (script_dir / args.vpn_dir).resolve() if not Path(args.vpn_dir).is_absolute() else Path(args.vpn_dir)
    killswitch_path = (
        (script_dir / args.killswitch_script).resolve()
        if not Path(args.killswitch_script).is_absolute()
        else Path(args.killswitch_script)
    )
    creds_file = Path(args.creds_file).expanduser()

    try:
        results = parse_latency_log(log_path)
        successful = sorted(
            (result for result in results if result.status.lower() == "success"),
            key=lambda result: result.latency_ms,
        )
        best = pick_best_result(successful)
        ovpn_path = resolve_ovpn_path(best.filename, vpn_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.killswitch and not args.run:
        print("Error: --killswitch can only be used with --run.", file=sys.stderr)
        return 1

    if args.print_only and args.run:
        print("Error: --print-only cannot be combined with --run.", file=sys.stderr)
        return 1

    if args.print_only:
        print(ovpn_path)
        return 0

    top_count = max(args.top, 1)
    print(f"Latency log: {log_path}")
    print(f"VPN directory: {vpn_dir}")
    print()
    print(f"Top {min(top_count, len(successful))} successful result(s):")
    for index, result in enumerate(successful[:top_count], start=1):
        print(
            f"{index}. {result.filename} | {result.hostname} | "
            f"{result.latency_ms:.2f} ms | {result.status}"
        )

    print()
    print("Selected best config:")
    print(f"  File: {best.filename}")
    print(f"  Host: {best.hostname}")
    print(f"  Latency: {best.latency_ms:.2f} ms")
    print(f"  Path: {ovpn_path}")
    mode = "display only"
    if args.run and args.killswitch:
        mode = "OpenVPN + killswitch"
    elif args.run:
        mode = "OpenVPN"
    print(f"  Mode: {mode}")

    if not args.run:
        return 0

    print()
    if args.killswitch:
        print(f"Launching killswitch with: {ovpn_path}")
        try:
            return run_with_killswitch(ovpn_path, killswitch_path)
        except FileNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    print(f"Launching OpenVPN with: {ovpn_path}")
    return run_openvpn(ovpn_path, creds_file)


if __name__ == "__main__":
    raise SystemExit(main())
