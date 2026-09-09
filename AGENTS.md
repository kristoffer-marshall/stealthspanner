# AGENTS.md

## Project Overview

StealthSpanner is a Python CLI tool for testing VPN server latency from `.ovpn` files and selecting the best configuration to run. It currently supports automatic VPN config download, latency testing, and running the selected VPN directly or through an optional killswitch workflow. It has a beautiful, modern TUI interface with color-coded output and log file tracking. It uses the Python library 'beep' to play sound notifications. All funtionality is implemented in the industry standard way.

## Primary Entry Points

- `stealthspanner.py` — main latency testing workflow and optional VPN selection/launch entry point
- `killswitch` — shell-based optional killswitch launcher used by `stealthspanner.py -k`
- `config_manager.py` — user config loading and migration-aware path handling
- `xdg_paths.py` — centralized XDG and legacy path helpers

## Path Conventions

Preferred XDG-style paths:

- Config: `~/.config/stealthspanner/config.ini`
- Credentials: `~/.config/stealthspanner/vpn_creds`
- State logs: `~/.local/state/stealthspanner/`
- Scan results/log: `~/.local/state/stealthspanner/stealthspanner.log`

Legacy fallbacks currently supported and should not be broken unless explicitly requested:

- Config: `~/.stealthspanner.ini`
- Credentials: `~/.vpn_creds`
- Older scan log fallback: local `./vpn_latency_checker.log`

## Safety Rules

- Killswitch behavior must remain **opt-in**. Do not make it the default unless explicitly requested.
- Be careful when changing `killswitch`, OpenVPN invocation, firewall rules, or credential handling.
- Do not hardcode secrets, credentials, or machine-specific absolute paths.
- Preserve backward compatibility for legacy config and credential paths unless the task explicitly includes removing support.
- Prefer root-cause fixes over surface patches, but keep changes minimal and scoped.

## Development Workflow

- Use `uv`, not `pip`, for documented setup and command examples.
- Prefer updating existing code paths rather than creating overlapping duplicate scripts unless there is a clear reason.
- Keep CLI help text and `README.md` aligned with behavior changes.
- Reuse shared helpers in `xdg_paths.py` and `config_manager.py` rather than duplicating path logic.

## Validation Notes

- Run targeted validation for the files you changed when possible.
- Do not claim OpenVPN, `sudo`, `ufw`, or networking behavior was validated unless it was actually tested in a suitable environment.
- Sandbox environments may not support interactive VPN execution or firewall changes; say so clearly when relevant.

## Planned Enhancements

Likely future work includes:

- favorited regions / preferred countries
- excluded regions
- top-N or interactive VPN selection
- further consolidation of shell behavior into Python where appropriate

When implementing new selection features, keep the VPN selection logic in `stealthspanner.py` modular so selection logic stays separate from connection execution logic.
