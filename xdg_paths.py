#!/usr/bin/env python3
"""XDG-style paths for StealthSpanner."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "stealthspanner"
CONFIG_FILE_NAME = "config.ini"
CREDS_FILE_NAME = "vpn_creds"
STATE_LOG_FILE_NAME = "stealthspanner.log"
KILLSWITCH_MARKER_FILE_NAME = "killswitch.active"



def _expand_xdg_path(env_var: str, default_suffix: str) -> Path:
    value = os.environ.get(env_var)
    if value:
        return Path(value).expanduser()
    return Path.home() / default_suffix


def get_config_dir() -> Path:
    return _expand_xdg_path("XDG_CONFIG_HOME", ".config") / APP_NAME


def get_state_dir() -> Path:
    return _expand_xdg_path("XDG_STATE_HOME", ".local/state") / APP_NAME


def get_config_path() -> Path:
    return get_config_dir() / CONFIG_FILE_NAME


def get_credentials_path() -> Path:
    return get_config_dir() / CREDS_FILE_NAME


def get_state_log_path() -> Path:
    return get_state_dir() / STATE_LOG_FILE_NAME


def get_last_scan_log_path() -> Path:
    return get_state_log_path()


def get_killswitch_marker_path() -> Path:
    return get_state_dir() / KILLSWITCH_MARKER_FILE_NAME


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
