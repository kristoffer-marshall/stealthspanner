#!/usr/bin/env python3
"""
StealthSpanner - VPN Latency Checker

Tests latency for VPN servers by reading .ovpn configuration files
and pinging each server concurrently. Supports multiple VPN providers
with automatic configuration download.
"""

import argparse
import configparser
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
    get_config_directory
)
from vpn_config_downloader import download_vpn_configs


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


def discover_ovpn_files(directory: Path) -> Dict[str, str]:
    """
    Discover all .ovpn files in the directory and extract hostnames.
    
    Args:
        directory: Directory containing .ovpn files
        
    Returns:
        Dictionary mapping filename to hostname
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
        if hostname:
            files_to_hosts[ovpn_file.name] = hostname
        else:
            warning_msg = colorize(f"Warning: No 'remote' line found in {ovpn_file.name}", Colors.YELLOW, sys.stderr)
            print(warning_msg, file=sys.stderr)
    
    return files_to_hosts


def ping_host(hostname: str, count: int = 4, timeout: float = 3.0) -> Tuple[Optional[float], str]:
    """
    Ping a host multiple times and calculate average latency.
    
    Args:
        hostname: Hostname or IP address to ping
        count: Number of ping attempts
        timeout: Timeout in seconds for each ping
        
    Returns:
        Tuple of (average_latency_ms, status_message)
        If all pings fail, returns (None, error_message)
    """
    # First, try to resolve the hostname to detect DNS failures
    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        return (None, "DNS Resolution Failed")
    except Exception as e:
        # Other socket errors
        return (None, f"Resolution Error: {str(e)}")
    
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
    
    # If we got DNS errors for all attempts, report DNS failure
    if dns_errors == count and len(latencies) == 0:
        return (None, "DNS Resolution Failed")
    
    # If we got some successful pings, return average
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        return (avg_latency, "Success")
    
    # If all attempts failed but not all were DNS errors
    if timeout_errors > 0:
        return (None, "Timeout/Unreachable")
    
    # If we had some DNS errors but not all
    if dns_errors > 0:
        return (None, "DNS Resolution Failed")
    
    return (None, "Failed")


def test_host_latency(filename: str, hostname: str, pings: int, timeout: float) -> Dict:
    """
    Test latency for a single host (wrapper for threading).
    
    Args:
        filename: Name of the .ovpn file
        hostname: Hostname to ping
        pings: Number of ping attempts
        timeout: Timeout in seconds
        
    Returns:
        Dictionary with results
    """
    latency, status = ping_host(hostname, count=pings, timeout=timeout)
    
    return {
        'filename': filename,
        'hostname': hostname,
        'latency': latency,
        'status': status
    }


def format_output(results: List[Dict]) -> None:
    """
    Format and display results as a table sorted by latency.
    
    Args:
        results: List of result dictionaries
    """
    # Separate successful and failed pings
    successful = [r for r in results if r['latency'] is not None]
    failed = [r for r in results if r['latency'] is None]
    
    # Sort successful by latency (best to worst)
    successful.sort(key=lambda x: x['latency'])
    
    # Combine: successful first, then failed
    sorted_results = successful + failed
    
    # Print header with colors
    separator = "=" * 100
    header = f"{'Filename':<45} {'Hostname':<30} {'Latency (ms)':<15} {'Status':<15}"
    print("\n" + separator)
    # Use bold cyan for header
    header_colored = colorize(header, Colors.BOLD + Colors.BRIGHT_CYAN)
    print(header_colored)
    print(separator)
    
    # Print results with colors
    for result in sorted_results:
        filename = result['filename']
        hostname = result['hostname']
        latency = result['latency']
        status = result['status']
        
        if latency is not None:
            latency_str = f"{latency:.2f}"
        else:
            latency_str = "N/A"
        
        # Colorize based on status
        if latency is None:
            # Failed - color in red
            status_colored = colorize(status, Colors.RED)
            latency_colored = colorize(latency_str, Colors.RED)
        else:
            # Success - keep default or subtle green for very low latency
            status_colored = colorize(status, Colors.BRIGHT_GREEN)
            if latency < 50:  # Very good latency
                latency_colored = colorize(latency_str, Colors.BRIGHT_GREEN)
            elif latency < 100:  # Good latency
                latency_colored = colorize(latency_str, Colors.GREEN)
            else:  # Higher latency
                latency_colored = latency_str
        
        print(f"{filename:<45} {hostname:<30} {latency_colored:<15} {status_colored:<15}")
    
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
        best_msg = colorize(
            f"\nBest latency: {successful[0]['hostname']} ({successful[0]['latency']:.2f} ms)",
            Colors.BRIGHT_GREEN
        )
        worst_msg = colorize(
            f"Worst latency: {successful[-1]['hostname']} ({successful[-1]['latency']:.2f} ms)",
            Colors.RED
        )
        print(best_msg)
        print(worst_msg)


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
                    args.pings,
                    args.timeout
                ): (filename, hostname)
                for filename, hostname in files_to_hosts.items()
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
                    filename, hostname = future_to_host[future]
                    error_msg = colorize(
                        f"Error testing {hostname} from {filename}: {e}",
                        Colors.RED,
                        original_stderr
                    )
                    print(f"\n{error_msg}", file=original_stderr)
                    results.append({
                        'filename': filename,
                        'hostname': hostname,
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

