#!/usr/bin/env python3
"""
StealthSpanner - VPN Latency Checker

Tests latency for VPN servers by reading .ovpn configuration files
and pinging each server concurrently. Supports multiple VPN providers
with automatic configuration download.
"""

import argparse
import configparser
import math
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import ping3
    import ping3.errors
    # Enable exceptions mode for better error detection
    ping3.EXCEPTIONS = True
except ImportError:
    print("Error: ping3 library is required. Install it with: pip install ping3")
    sys.exit(1)

# Import our modules
from config_manager import (
    load_config,
    get_default_provider,
    should_auto_download,
    get_config_directory,
    is_privacy_scoring_enabled,
    get_privacy_weight,
    get_privacy_scores
)
from vpn_config_downloader import download_vpn_configs


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


def get_country_name(country_code: Optional[str]) -> str:
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
    import os
    if os.environ.get('NO_COLOR'):
        return False
    
    return True


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
    """
    Print a progress bar showing completion status with Unicode blocks and colors.
    
    Args:
        completed: Number of items completed
        total: Total number of items
        file: File object to write to (default: stdout)
        bar_length: Length of the progress bar in characters
    """
    if total == 0:
        return
    
    percent = (completed / total) * 100
    filled_length = int(bar_length * completed // total)
    
    # Unicode block characters
    filled_char = '█'  # Full block
    empty_char = '░'   # Light shade
    
    # Create the bar with colors
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
    
    # Print progress bar (using \r to overwrite the same line)
    print(f'\r[{bar}] {percent_text} {count_text}', end='', flush=True, file=file)
    
    # Print newline when complete
    if completed == total:
        print(file=file)


def extract_country_code(filename: str) -> Optional[str]:
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


def parse_ovpn_file(file_path: Path) -> Optional[str]:
    """
    Parse an .ovpn file to extract the hostname from the 'remote' line.
    
    Args:
        file_path: Path to the .ovpn file
        
    Returns:
        Hostname if found, None otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('remote'):
                    # Format: remote <hostname> <port>
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]  # Return hostname
    except Exception as e:
        warning_msg = colorize(f"Warning: Could not read {file_path}: {e}", Colors.YELLOW, sys.stderr)
        print(warning_msg, file=sys.stderr)
    return None


def discover_ovpn_files(directory: Path) -> Dict[str, Tuple[str, Optional[str]]]:
    """
    Discover all .ovpn files in the directory and extract hostnames and country codes.
    
    Args:
        directory: Directory containing .ovpn files
        
    Returns:
        Dictionary mapping filename to (hostname, country_code) tuple
    """
    files_to_hosts = {}
    
    if not directory.exists():
        error_msg = colorize(f"Error: Directory {directory} does not exist", Colors.RED, sys.stderr)
        print(error_msg, file=sys.stderr)
        return files_to_hosts
    
    ovpn_files = list(directory.glob('*.ovpn'))
    found_msg = colorize(f"Found {len(ovpn_files)} .ovpn files", Colors.BRIGHT_CYAN)
    print(found_msg)
    
    for ovpn_file in ovpn_files:
        hostname = parse_ovpn_file(ovpn_file)
        country_code = extract_country_code(ovpn_file.name)
        if hostname:
            files_to_hosts[ovpn_file.name] = (hostname, country_code)
        else:
            warning_msg = colorize(f"Warning: No 'remote' line found in {ovpn_file.name}", Colors.YELLOW, sys.stderr)
            print(warning_msg, file=sys.stderr)
    
    return files_to_hosts


def ping_host(hostname: str, count: int = 4, timeout: float = 3.0) -> Tuple[Optional[float], Optional[Dict[str, Optional[float]]], float, str]:
    """
    Ping a host multiple times and calculate average latency, jitter, and packet loss.
    
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
    except Exception as e:
        # Other socket errors
        return (None, None, 100.0, f"Resolution Error: {str(e)}")
    
    latencies = []
    dns_errors = 0
    timeout_errors = 0
    
    for i in range(count):
        try:
            latency = ping3.ping(hostname, timeout=timeout, unit='ms')
            if latency is not None and latency >= 0:
                # ping3 can return 0.0 for very fast responses, but legitimate 0ms pings are extremely rare
                # If we get 0.0, it might indicate a problem. Verify with another ping.
                if latency == 0.0:
                    # Double-check: try another ping to verify legitimacy
                    verify_latency = ping3.ping(hostname, timeout=timeout, unit='ms')
                    if verify_latency is None:
                        # Verification failed - likely an issue
                        continue
                    elif verify_latency == 0.0:
                        # Both returned 0.0 - could be legitimate (very fast) or an error
                        # Accept it but note that 0.0 is suspicious
                        latencies.append(0.0)
                    else:
                        # Verification returned a real value - use that instead
                        latencies.append(verify_latency)
                else:
                    latencies.append(latency)
        except ping3.errors.HostUnknown:
            dns_errors += 1
        except ping3.errors.Timeout:
            timeout_errors += 1
        except ping3.errors.PingError as e:
            # Check if it's a DNS-related error
            error_str = str(e).lower()
            if 'cannot resolve' in error_str or 'unknown host' in error_str or 'name or service not known' in error_str:
                dns_errors += 1
            else:
                timeout_errors += 1
        except Exception as e:
            # Check error message for DNS-related issues
            error_str = str(e).lower()
            if 'cannot resolve' in error_str or 'unknown host' in error_str or 'name or service not known' in error_str or 'nodename nor servname provided' in error_str:
                dns_errors += 1
            else:
                timeout_errors += 1
    
    # Calculate packet loss percentage
    successful_pings = len(latencies)
    failed_pings = count - successful_pings
    packet_loss_percent = (failed_pings / count) * 100.0 if count > 0 else 100.0
    
    # If we got DNS errors for all attempts, report DNS failure
    if dns_errors == count and len(latencies) == 0:
        return (None, None, packet_loss_percent, "DNS Resolution Failed")
    
    # If we got some successful pings, calculate average and jitter
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        
        # Calculate jitter metrics if we have at least 2 measurements
        if len(latencies) >= 2:
            # Standard deviation
            variance = sum((x - avg_latency) ** 2 for x in latencies) / len(latencies)
            std_dev = math.sqrt(variance)
            
            # Mean deviation
            mean_dev = sum(abs(x - avg_latency) for x in latencies) / len(latencies)
            
            # Min/Max range
            min_max_range = max(latencies) - min(latencies)
            
            jitter_metrics = {
                'std_dev': std_dev,
                'mean_dev': mean_dev,
                'min_max_range': min_max_range
            }
        else:
            # Not enough data for meaningful jitter
            jitter_metrics = {
                'std_dev': None,
                'mean_dev': None,
                'min_max_range': None
            }
        
        return (avg_latency, jitter_metrics, packet_loss_percent, "Success")
    
    # If all attempts failed but not all were DNS errors
    if timeout_errors > 0:
        return (None, None, packet_loss_percent, "Timeout/Unreachable")
    
    # If we had some DNS errors but not all
    if dns_errors > 0:
        return (None, None, packet_loss_percent, "DNS Resolution Failed")
    
    return (None, None, packet_loss_percent, "Failed")


def calculate_score(
    latency: Optional[float], 
    jitter: Optional[Dict[str, Optional[float]]], 
    packet_loss: float,
    country_code: Optional[str],
    privacy_config: Dict
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


def test_host_latency(filename: str, hostname: str, country_code: Optional[str], pings: int, timeout: float, privacy_config: Dict) -> Dict:
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


def format_output(results: List[Dict]) -> None:
    """
    Format and display results as a table sorted by composite score.
    
    Args:
        results: List of result dictionaries
    """
    # Separate successful and failed pings
    successful = [r for r in results if r['latency'] is not None]
    failed = [r for r in results if r['latency'] is None]
    
    # Sort successful by score (best to worst, highest score first)
    successful.sort(key=lambda x: x.get('score', 0.0), reverse=True)
    
    # Sort failed by score (they should all be 0.0, but keep them together)
    failed.sort(key=lambda x: x.get('score', 0.0), reverse=True)
    
    # Combine: successful first (sorted by score), then failed
    sorted_results = successful + failed
    
    # Print header with colors
    separator = "=" * 150
    header = f"{'Filename':<40} {'Country':<25} {'Score':<8} {'Latency (ms)':<15} {'Jitter (ms)':<25} {'Loss %':<10} {'Status':<15}"
    print("\n" + separator)
    # Use bold cyan for header
    header_colored = colorize(header, Colors.BOLD + Colors.BRIGHT_CYAN)
    print(header_colored)
    print(separator)
    
    # Print results with colors
    for result in sorted_results:
        filename = result['filename']
        country_name = result.get('country_name', 'Unknown')
        privacy_score = result.get('privacy_score', 0)
        score = result.get('score', 0.0)
        latency = result['latency']
        jitter = result.get('jitter', None)
        packet_loss = result.get('packet_loss', 100.0)
        status = result['status']
        
        # Format and colorize country with privacy score
        if privacy_score >= 80:
            country_display = f"{country_name} ({privacy_score}) ★"
            country_color = Colors.BRIGHT_GREEN
        elif privacy_score >= 60:
            country_display = f"{country_name} ({privacy_score})"
            country_color = Colors.GREEN
        elif privacy_score >= 40:
            country_display = f"{country_name} ({privacy_score})"
            country_color = Colors.YELLOW
        else:
            country_display = f"{country_name} ({privacy_score})"
            country_color = Colors.RED
        
        # Format and colorize score
        score_str = f"{score:.1f}"
        if score >= 80:  # Excellent score
            score_color = Colors.BRIGHT_GREEN
        elif score >= 60:  # Good score
            score_color = Colors.GREEN
        elif score >= 40:  # Fair score
            score_color = Colors.YELLOW
        else:  # Poor score
            score_color = Colors.RED
        
        if latency is not None:
            latency_str = f"{latency:.2f}"
        else:
            latency_str = "N/A"
        
        # Format jitter metrics
        if jitter and jitter.get('std_dev') is not None:
            std_dev = jitter['std_dev']
            mean_dev = jitter['mean_dev']
            min_max_range = jitter['min_max_range']
            jitter_str = f"{std_dev:.2f} / {mean_dev:.2f} / {min_max_range:.2f}"
            
            # Determine jitter color based on severity (using std_dev as primary metric)
            if std_dev < 10:  # Low jitter
                jitter_color = Colors.BRIGHT_GREEN
            elif std_dev < 30:  # Medium jitter
                jitter_color = Colors.YELLOW
            else:  # High jitter
                jitter_color = Colors.RED
        else:
            jitter_str = "N/A"
            jitter_color = Colors.GRAY
        
        # Format and colorize packet loss
        if packet_loss is not None:
            packet_loss_str = f"{packet_loss:.1f}%"
            # Determine packet loss color based on severity
            if packet_loss == 0.0:  # No packet loss
                packet_loss_color = Colors.BRIGHT_GREEN
            elif packet_loss < 5.0:  # Low packet loss
                packet_loss_color = Colors.GREEN
            elif packet_loss < 25.0:  # Medium packet loss
                packet_loss_color = Colors.YELLOW
            else:  # High packet loss
                packet_loss_color = Colors.RED
        else:
            packet_loss_str = "N/A"
            packet_loss_color = Colors.GRAY
        
        # Determine status and latency colors
        if latency is None:
            # Failed - color in red
            status_color = Colors.RED
            latency_color = Colors.RED
        else:
            # Success - keep default or subtle green for very low latency
            status_color = Colors.BRIGHT_GREEN
            if latency < 50:  # Very good latency
                latency_color = Colors.BRIGHT_GREEN
            elif latency < 100:  # Good latency
                latency_color = Colors.GREEN
            else:  # Higher latency
                latency_color = None  # No color
        
        # Use pad_and_colorize for proper column alignment
        country_colored = pad_and_colorize(country_display, 25, country_color)
        score_colored = pad_and_colorize(score_str, 8, score_color)
        latency_colored = pad_and_colorize(latency_str, 15, latency_color) if latency_color else f"{latency_str:<15}"
        jitter_colored = pad_and_colorize(jitter_str, 25, jitter_color)
        packet_loss_colored = pad_and_colorize(packet_loss_str, 10, packet_loss_color)
        status_colored = pad_and_colorize(status, 15, status_color)
        
        print(f"{filename:<40} {country_colored} {score_colored} {latency_colored} {jitter_colored} {packet_loss_colored} {status_colored}")
    
    print(separator)
    
    # Count different failure types
    dns_failures = [r for r in failed if 'DNS' in r['status']]
    other_failures = [r for r in failed if 'DNS' not in r['status']]
    
    # Colorize summary statistics
    total_msg = colorize(f"Total: {len(results)} servers", Colors.BRIGHT_CYAN)
    successful_msg = colorize(f"Successful: {len(successful)}", Colors.BRIGHT_GREEN)
    failed_msg = colorize(f"Failed: {len(failed)}", Colors.RED)
    
    print(f"\n{total_msg}")
    print(successful_msg)
    print(failed_msg)
    if dns_failures:
        dns_msg = colorize(f"  - DNS Resolution Failed: {len(dns_failures)}", Colors.RED)
        print(dns_msg)
    if other_failures:
        other_msg = colorize(f"  - Other failures: {len(other_failures)}", Colors.YELLOW)
        print(other_msg)
    
    if successful:
        # Results are already sorted by score, so first is best, last is worst
        best_score_msg = colorize(
            f"\nBest score: {successful[0]['hostname']} (Score: {successful[0].get('score', 0.0):.1f})",
            Colors.BRIGHT_GREEN
        )
        worst_score_msg = colorize(
            f"Worst score: {successful[-1]['hostname']} (Score: {successful[-1].get('score', 0.0):.1f})",
            Colors.RED
        )
        print(best_score_msg)
        print(worst_score_msg)
        
        best_msg = colorize(
            f"Best latency: {successful[0]['hostname']} ({successful[0]['latency']:.2f} ms)",
            Colors.BRIGHT_GREEN
        )
        worst_msg = colorize(
            f"Worst latency: {successful[-1]['hostname']} ({successful[-1]['latency']:.2f} ms)",
            Colors.RED
        )
        print(best_msg)
        print(worst_msg)
        
        # Find best and worst jitter (by std_dev)
        successful_with_jitter = [r for r in successful if r.get('jitter') and r['jitter'].get('std_dev') is not None]
        if successful_with_jitter:
            # Sort by jitter (std_dev)
            best_jitter = min(successful_with_jitter, key=lambda x: x['jitter']['std_dev'])
            worst_jitter = max(successful_with_jitter, key=lambda x: x['jitter']['std_dev'])
            
            best_jitter_msg = colorize(
                f"Best jitter: {best_jitter['hostname']} (std_dev: {best_jitter['jitter']['std_dev']:.2f} ms)",
                Colors.BRIGHT_GREEN
            )
            worst_jitter_msg = colorize(
                f"Worst jitter: {worst_jitter['hostname']} (std_dev: {worst_jitter['jitter']['std_dev']:.2f} ms)",
                Colors.RED
            )
            print(best_jitter_msg)
            print(worst_jitter_msg)
        
        # Find best and worst packet loss
        successful_with_loss = [r for r in successful if r.get('packet_loss') is not None]
        if successful_with_loss:
            best_loss = min(successful_with_loss, key=lambda x: x['packet_loss'])
            worst_loss = max(successful_with_loss, key=lambda x: x['packet_loss'])
            
            best_loss_msg = colorize(
                f"Best packet loss: {best_loss['hostname']} ({best_loss['packet_loss']:.1f}%)",
                Colors.BRIGHT_GREEN
            )
            worst_loss_msg = colorize(
                f"Worst packet loss: {worst_loss['hostname']} ({worst_loss['packet_loss']:.1f}%)",
                Colors.RED
            )
            print(best_loss_msg)
            print(worst_loss_msg)
        
        # Find best and worst privacy scores
        successful_with_privacy = [r for r in successful if r.get('privacy_score') is not None]
        if successful_with_privacy:
            best_privacy = max(successful_with_privacy, key=lambda x: x['privacy_score'])
            worst_privacy = min(successful_with_privacy, key=lambda x: x['privacy_score'])
            
            best_privacy_msg = colorize(
                f"Best privacy: {best_privacy['hostname']} ({best_privacy.get('country_name', 'Unknown')}, score: {best_privacy['privacy_score']})",
                Colors.BRIGHT_GREEN
            )
            worst_privacy_msg = colorize(
                f"Worst privacy: {worst_privacy['hostname']} ({worst_privacy.get('country_name', 'Unknown')}, score: {worst_privacy['privacy_score']})",
                Colors.RED
            )
            print(best_privacy_msg)
            print(worst_privacy_msg)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Test latency for VPN servers from .ovpn files',
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
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_config()
    except Exception as e:
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
    
    # Determine provider
    provider_name = args.provider if args.provider else get_default_provider(config)
    
    # Determine directory
    if args.directory:
        directory = Path(args.directory)
    else:
        directory_name = get_config_directory(config, provider_name)
        directory = Path(directory_name)
    
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
        except Exception as e:
            warning_msg = colorize(
                f"Warning: Failed to download configs: {e}. Continuing with existing configs.",
                Colors.YELLOW,
                sys.stderr
            )
            print(warning_msg, file=sys.stderr)
            print()
    
    # Set up log file in the same directory as the script
    script_dir = Path(__file__).parent.absolute()
    log_file_path = script_dir / 'stealthspanner.log'
    
    # Open log file
    log_file = open(log_file_path, 'w', encoding='utf-8')
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    
    try:
        # Discover .ovpn files (progress to stdout only)
        files_to_hosts = discover_ovpn_files(directory)
        
        if not files_to_hosts:
            error_msg = colorize("Error: No valid .ovpn files found", Colors.RED, original_stderr)
            print(error_msg, file=original_stderr)
            sys.exit(1)
        
        testing_msg = colorize(
            f"Testing {len(files_to_hosts)} hosts with {args.pings} pings each...",
            Colors.BRIGHT_YELLOW
        )
        workers_msg = colorize(
            f"Using {args.workers} concurrent workers",
            Colors.BRIGHT_YELLOW
        )
        timeout_msg = colorize(
            f"Timeout: {args.timeout} seconds per ping",
            Colors.BRIGHT_YELLOW
        )
        print(testing_msg)
        print(workers_msg)
        print(timeout_msg + "\n")
        
        # Test hosts concurrently (progress to stdout only)
        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            # Submit all tasks
            future_to_host = {
                executor.submit(
                    test_host_latency,
                    filename,
                    hostname,
                    country_code,
                    args.pings,
                    args.timeout,
                    privacy_config
                ): (filename, hostname, country_code)
                for filename, (hostname, country_code) in files_to_hosts.items()
            }
            
            # Collect results as they complete
            completed = 0
            total = len(files_to_hosts)
            
            # Print initial progress bar
            print_progress_bar(0, total, file=original_stdout)
            
            for future in as_completed(future_to_host):
                completed += 1
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    filename, hostname, country_code = future_to_host[future]
                    error_msg = colorize(
                        f"Error testing {hostname} from {filename}: {e}",
                        Colors.RED,
                        original_stderr
                    )
                    print(f"\n{error_msg}", file=original_stderr)
                    results.append({
                        'filename': filename,
                        'hostname': hostname,
                        'country_code': country_code,
                        'country_name': get_country_name(country_code),
                        'privacy_score': 0,
                        'latency': None,
                        'status': f'Error: {str(e)}'
                    })
                
                # Update progress bar
                print_progress_bar(completed, total, file=original_stdout)
        
        # Redirect stdout/stderr to Tee (both console and log) for results only
        tee_stdout = Tee(original_stdout, log_file)
        tee_stderr = Tee(original_stderr, log_file)
        sys.stdout = tee_stdout
        sys.stderr = tee_stderr
        
        # Display results (goes to both stdout and log file)
        format_output(results)
        
        # Restore original stdout/stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr
    
    finally:
        # Close log file
        log_file.close()
        saved_msg = colorize(
            f"Results saved to: {log_file_path}",
            Colors.BRIGHT_CYAN,
            original_stdout
        )
        print(saved_msg, file=original_stdout)


if __name__ == '__main__':
    main()

