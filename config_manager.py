#!/usr/bin/env python3
"""
Configuration Manager for StealthSpanner

Handles loading and managing user configuration files.
"""

import configparser
import os
import shutil
import sys
from pathlib import Path

from xdg_paths import ensure_directory, get_config_dir, get_config_path, get_legacy_config_path


def warn_legacy_path(legacy_path: Path, new_path: Path, kind: str) -> None:
    print(
        f"Warning: Using legacy {kind} path at {legacy_path}. "
        f"Please migrate to {new_path}.",
        file=sys.stderr,
    )




def get_template_path() -> Path:
    """
    Get the path to the template configuration file.
    
    Returns:
        Path object pointing to config.template.ini in project root
    """
    # Get the directory where this module is located
    module_dir = Path(__file__).parent.absolute()
    return module_dir / 'config.template.ini'


def create_config_from_template() -> None:
    """
    Create user config file from template if it doesn't exist.
    
    Raises:
        FileNotFoundError: If template file doesn't exist
        OSError: If config file cannot be created
    """
    config_path = get_config_path()
    template_path = get_template_path()

    if config_path.exists():
        return

    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")

    ensure_directory(get_config_dir())
    shutil.copy2(template_path, config_path)
    os.chmod(config_path, 0o600)


def get_active_config_path() -> Path:
    config_path = get_config_path()
    legacy_config_path = get_legacy_config_path()

    if config_path.exists():
        return config_path
    if legacy_config_path.exists():
        warn_legacy_path(legacy_config_path, config_path, "config")
        return legacy_config_path

    create_config_from_template()
    return config_path


def load_config() -> configparser.ConfigParser:
    """
    Load user configuration file, creating from template if necessary.
    
    Returns:
        ConfigParser object with loaded configuration
        
    Raises:
        FileNotFoundError: If template file doesn't exist
        OSError: If config file cannot be created or read
        configparser.Error: If config file is invalid
    """
    path_to_load = get_active_config_path()

    config = configparser.ConfigParser()
    config.read(path_to_load)

    return config


def get_default_provider(config: configparser.ConfigParser) -> str:
    """
    Get the default VPN provider from configuration.
    
    Args:
        config: ConfigParser object with loaded configuration
        
    Returns:
        Provider name (default: 'ipvanish')
    """
    return config.get('DEFAULT', 'provider', fallback='ipvanish')


def should_auto_download(config: configparser.ConfigParser) -> bool:
    """
    Check if auto-download is enabled in configuration.
    
    Args:
        config: ConfigParser object with loaded configuration
        
    Returns:
        True if auto-download is enabled, False otherwise (default: True)
    """
    return config.getboolean('DEFAULT', 'auto_download', fallback=True)


def get_provider_config(config: configparser.ConfigParser, provider_name: str) -> dict[str, str] | None:
    """
    Get configuration for a specific VPN provider.
    
    Args:
        config: ConfigParser object with loaded configuration
        provider_name: Name of the provider (e.g., 'ipvanish')
        
    Returns:
        Dictionary with provider configuration (enabled, base_url, directory)
        or None if provider section doesn't exist
    """
    if not config.has_section(provider_name):
        return None
    
    provider_config = {
        'enabled': config.getboolean(provider_name, 'enabled', fallback=False),
        'base_url': config.get(provider_name, 'base_url', fallback=''),
        'directory': config.get(provider_name, 'directory', fallback=provider_name.capitalize())
    }
    
    return provider_config


def get_config_directory(config: configparser.ConfigParser, provider_name: str | None = None) -> str:
    """
    Get the directory path for VPN config files.
    
    Args:
        config: ConfigParser object with loaded configuration
        provider_name: Optional provider name to get provider-specific directory
        
    Returns:
        Directory name/path for config files
    """
    if provider_name:
        provider_config = get_provider_config(config, provider_name)
        if provider_config:
            return provider_config['directory']
    
    # Fall back to DEFAULT config_directory or provider's directory
    default_provider = get_default_provider(config)
    provider_config = get_provider_config(config, default_provider)
    if provider_config:
        return provider_config['directory']
    
    return config.get('DEFAULT', 'config_directory', fallback='IPVanish')


def get_default_privacy_scores() -> dict[str, int]:
    """
    Return default privacy scores for common countries.
    
    Returns:
        Dictionary mapping country codes to privacy scores (0-100)
    """
    return {
        'CH': 100, 'PA': 95, 'RO': 90, 'IS': 90,
        'VG': 85, 'LI': 85, 'SC': 80, 'AD': 80, 'MC': 80,
        'MD': 75, 'SM': 75, 'VA': 70, 'CY': 65, 'IE': 60,
        'NO': 50, 'PT': 50, 'SE': 45, 'IT': 45, 'ES': 45,
        'DE': 40, 'FR': 40, 'NL': 40,
        'NZ': 35, 'BE': 35, 'DK': 35,
        'CA': 30, 'AU': 30,
        'UK': 25,
        'US': 20,
    }


def is_privacy_scoring_enabled(config: configparser.ConfigParser) -> bool:
    """
    Check if privacy scoring is enabled in configuration.
    
    Args:
        config: ConfigParser object with loaded configuration
        
    Returns:
        True if privacy scoring is enabled, False otherwise (default: True)
    """
    if not config.has_section('PRIVACY'):
        return True  # Default to enabled
    return config.getboolean('PRIVACY', 'enabled', fallback=True)


def get_privacy_weight(config: configparser.ConfigParser) -> float:
    """
    Get the weight of privacy in composite score.
    
    Args:
        config: ConfigParser object with loaded configuration
        
    Returns:
        Weight value (0.0-1.0) for privacy in score (default: 0.35)
    """
    if not config.has_section('PRIVACY'):
        return 0.35
    return config.getfloat('PRIVACY', 'weight', fallback=0.35)


def get_picker_preferences(config: configparser.ConfigParser) -> dict[str, str]:
    if not config.has_section('PICKER'):
        return {
            'default_mode': '',
            'default_value': '',
            'favorite_profiles': '',
            'favorite_countries': '',
            'favorite_regions': '',
            'favorite_cities': '',
        }

    return {
        'default_mode': config.get('PICKER', 'default_mode', fallback='').strip(),
        'default_value': config.get('PICKER', 'default_value', fallback='').strip(),
        'favorite_profiles': config.get('PICKER', 'favorite_profiles', fallback='').strip(),
        'favorite_countries': config.get('PICKER', 'favorite_countries', fallback='').strip(),
        'favorite_regions': config.get('PICKER', 'favorite_regions', fallback='').strip(),
        'favorite_cities': config.get('PICKER', 'favorite_cities', fallback='').strip(),
    }


def merge_csv_value(existing: str, new_value: str) -> str:
    items = [item.strip() for item in existing.split(',') if item.strip()]
    if new_value not in items:
        items.append(new_value)
    return ','.join(items)


def update_picker_preferences(updates: dict[str, str], append_keys: set[str] | None = None) -> Path:
    config_path = get_active_config_path()
    config = configparser.ConfigParser()
    config.read(config_path)

    if not config.has_section('PICKER'):
        config.add_section('PICKER')

    append_keys = append_keys or set()
    for key, value in updates.items():
        if key in append_keys:
            current_value = config.get('PICKER', key, fallback='').strip()
            value = merge_csv_value(current_value, value)
        config.set('PICKER', key, value)

    with config_path.open('w', encoding='utf-8') as config_file:
        config.write(config_file)
    os.chmod(config_path, 0o600)
    return config_path


def get_privacy_scores(config: configparser.ConfigParser) -> dict[str, int]:
    """
    Get privacy scores for countries from configuration.
    
    Args:
        config: ConfigParser object with loaded configuration
        
    Returns:
        Dictionary mapping country codes to privacy scores (0-100)
        Merges config scores with defaults (config takes precedence)
    """
    default_scores = get_default_privacy_scores()
    
    if not config.has_section('PRIVACY'):
        return default_scores
    
    # Get privacy_scores from config
    privacy_scores_str = config.get('PRIVACY', 'privacy_scores', fallback='')
    
    if not privacy_scores_str:
        return default_scores
    
    # Parse comma-separated COUNTRY=SCORE format
    config_scores = {}
    for item in privacy_scores_str.split(','):
        item = item.strip()
        if '=' in item:
            try:
                country_code, score_str = item.split('=', 1)
                country_code = country_code.strip().upper()
                score = int(score_str.strip())
                # Clamp score to 0-100 range
                score = max(0, min(100, score))
                config_scores[country_code] = score
            except (ValueError, AttributeError):
                # Skip invalid entries
                continue
    
    # Merge: config scores override defaults
    merged_scores = default_scores.copy()
    merged_scores.update(config_scores)
    
    return merged_scores

