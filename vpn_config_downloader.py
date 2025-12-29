#!/usr/bin/env python3
"""
VPN Configuration Downloader

Modular system for downloading VPN configuration files from various providers.
Supports multiple VPN providers through a plugin-like architecture.
"""

import configparser
import re
import shutil
import sys
import zipfile
from abc import ABC, abstractmethod
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("Error: requests library is required. Install it with: pip install requests", file=sys.stderr)
    sys.exit(1)


class BaseVPNDownloader(ABC):
    """Abstract base class for VPN configuration downloaders."""
    
    @abstractmethod
    def download_configs(self, directory: Path, base_url: str) -> int:
        """
        Download VPN configuration files.
        
        Args:
            directory: Target directory to save config files
            base_url: Base URL for downloading configs
            
        Returns:
            Number of files downloaded/extracted
            
        Raises:
            requests.RequestException: If network request fails
            OSError: If file operations fail
            ValueError: If download data is invalid
        """
        pass
    
    def download_file(self, url: str, filepath: Path) -> None:
        """
        Download a file from URL with progress indication.
        
        Args:
            url: URL to download from
            filepath: Local path to save the file
            
        Raises:
            requests.RequestException: If download fails
        """
        print(f"Downloading {url}...")
        
        try:
            response = requests.get(url, stream=True, timeout=60)
            response.raise_for_status()
            
            # Get file size for progress indication
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Show progress
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\rProgress: {percent:.1f}% ({downloaded}/{total_size} bytes)", end='', flush=True)
            
            print()  # New line after progress
            print(f"Download complete: {filepath}")
            
        except requests.RequestException as e:
            if filepath.exists():
                filepath.unlink()  # Clean up partial download
            raise requests.RequestException(f"Failed to download file: {e}")
    
    def purge_directory(self, directory: Path) -> None:
        """
        Remove directory and all its contents if it exists.
        
        Args:
            directory: Path to directory to purge
            
        Raises:
            OSError: If directory cannot be removed
        """
        if directory.exists():
            print(f"Purging existing {directory} directory...")
            try:
                shutil.rmtree(directory)
                print(f"Removed {directory}")
            except OSError as e:
                raise OSError(f"Failed to remove directory {directory}: {e}")
        else:
            print(f"Directory {directory} does not exist, skipping purge")
    
    def extract_zip(self, zip_path: Path, extract_to: Path) -> int:
        """
        Extract zip file to destination directory.
        
        Args:
            zip_path: Path to zip file
            extract_to: Destination directory
            
        Returns:
            Number of files extracted
            
        Raises:
            zipfile.BadZipFile: If zip file is invalid
            OSError: If extraction fails
        """
        print(f"Extracting {zip_path} to {extract_to}...")
        
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Count files before extraction
                file_list = zip_ref.namelist()
                file_count = len([f for f in file_list if not f.endswith('/')])
                
                # Extract all files
                zip_ref.extractall(extract_to)
                
                print(f"Extracted {file_count} file(s)")
                return file_count
                
        except zipfile.BadZipFile as e:
            raise zipfile.BadZipFile(f"Invalid zip file: {e}")
        except Exception as e:
            raise OSError(f"Failed to extract zip file: {e}")


class IPVanishDirectoryListingParser(HTMLParser):
    """Parse HTML directory listing to extract version directories."""
    
    def __init__(self):
        super().__init__()
        self.directories = []
        self.in_table = False
        self.in_row = False
        self.current_row_data = {}
        self.current_link = None
        
    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            self.in_table = True
        elif tag == 'tr' and self.in_table:
            self.in_row = True
            self.current_row_data = {}
        elif tag == 'a' and self.in_row:
            # Extract href from anchor tag
            for attr_name, attr_value in attrs:
                if attr_name == 'href':
                    self.current_link = attr_value
                    break
    
    def handle_endtag(self, tag):
        if tag == 'tr' and self.in_row:
            # Check if this row has a directory link
            if self.current_link and self.current_link not in ['..', '../']:
                # Clean up the link: remove /index.html, trailing slashes, and extract directory name
                clean_link = self.current_link.rstrip('/')
                # Remove /index.html if present
                if clean_link.endswith('/index.html'):
                    clean_link = clean_link[:-11]  # Remove '/index.html'
                # Extract just the directory name (last component of path)
                directory_name = clean_link.split('/')[-1]
                # Check if it looks like a version directory (starts with 'v' and has version-like pattern)
                if re.match(r'^v\d+\.\d+\.\d+', directory_name):
                    self.directories.append(directory_name)
            self.in_row = False
            self.current_link = None
        elif tag == 'table':
            self.in_table = False
    
    def handle_data(self, data):
        pass


def parse_version(version_str: str) -> Tuple[int, int, int, int]:
    """
    Parse version string like 'v2.6.0-0' into tuple for comparison.
    
    Args:
        version_str: Version string (e.g., 'v2.6.0-0')
        
    Returns:
        Tuple of (major, minor, patch, build) for comparison
    """
    # Remove 'v' prefix and split
    version_str = version_str.lstrip('v')
    # Split by '-' to separate version and build number
    parts = version_str.split('-')
    version_part = parts[0]
    build_part = int(parts[1]) if len(parts) > 1 else 0
    
    # Split version into major.minor.patch
    version_numbers = [int(x) for x in version_part.split('.')]
    while len(version_numbers) < 3:
        version_numbers.append(0)
    
    return (version_numbers[0], version_numbers[1], version_numbers[2], build_part)


class IPVanishDownloader(BaseVPNDownloader):
    """Downloader for IPVanish VPN configuration files."""
    
    def find_latest_version(self, base_url: str) -> str:
        """
        Find the latest version directory from the IPVanish config server.
        
        Args:
            base_url: Base URL for the openvpn directory listing
            
        Returns:
            Latest version string (e.g., 'v2.6.0-0')
            
        Raises:
            requests.RequestException: If network request fails
            ValueError: If no version directories found
        """
        print(f"Fetching directory listing from {base_url}...")
        
        try:
            response = requests.get(base_url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise requests.RequestException(f"Failed to fetch directory listing: {e}")
        
        # Parse HTML to find version directories
        parser = IPVanishDirectoryListingParser()
        parser.feed(response.text)
        
        if not parser.directories:
            raise ValueError("No version directories found in directory listing")
        
        # Sort versions to find latest
        sorted_versions = sorted(parser.directories, key=parse_version, reverse=True)
        latest_version = sorted_versions[0]
        
        print(f"Found {len(parser.directories)} version directory(ies)")
        print(f"Latest version: {latest_version}")
        
        return latest_version
    
    def download_configs(self, directory: Path, base_url: str) -> int:
        """
        Download IPVanish VPN configuration files.
        
        Args:
            directory: Target directory to save config files
            base_url: Base URL for IPVanish configs
            
        Returns:
            Number of files extracted
            
        Raises:
            requests.RequestException: If network request fails
            OSError: If file operations fail
            ValueError: If download data is invalid
        """
        zip_path = Path('configs.zip')
        base_url = base_url.rstrip('/') + '/'
        
        try:
            # Step 1: Find latest version
            latest_version = self.find_latest_version(base_url)
            
            # Step 2: Construct download URL
            configs_url = urljoin(base_url, f"{latest_version}/configs.zip")
            
            # Step 3: Download configs.zip
            self.download_file(configs_url, zip_path)
            
            # Step 4: Purge existing directory
            self.purge_directory(directory)
            
            # Step 5: Create target directory
            directory.mkdir(parents=True, exist_ok=True)
            
            # Step 6: Extract zip file
            file_count = self.extract_zip(zip_path, directory)
            
            # Step 7: Cleanup
            print(f"Removing temporary file {zip_path}...")
            zip_path.unlink()
            print("Cleanup complete")
            
            # Summary
            print("\n" + "=" * 60)
            print("Download Summary")
            print("=" * 60)
            print(f"Version: {latest_version}")
            print(f"Files extracted: {file_count}")
            print(f"Target directory: {directory.absolute()}")
            print("=" * 60)
            print("Success!")
            
            return file_count
            
        except requests.RequestException as e:
            if zip_path.exists():
                zip_path.unlink()  # Clean up on error
            raise requests.RequestException(f"Network error: {e}")
        except (OSError, ValueError) as e:
            if zip_path.exists():
                zip_path.unlink()  # Clean up on error
            raise


class VPNDownloaderFactory:
    """Factory for creating VPN downloader instances."""
    
    @staticmethod
    def get_downloader(provider_name: str) -> Optional[BaseVPNDownloader]:
        """
        Get a downloader instance for the specified provider.
        
        Args:
            provider_name: Name of the VPN provider (e.g., 'ipvanish')
            
        Returns:
            Downloader instance or None if provider is not supported
        """
        provider_name_lower = provider_name.lower()
        
        if provider_name_lower == 'ipvanish':
            return IPVanishDownloader()
        else:
            # Provider not yet implemented
            print(f"Warning: Provider '{provider_name}' is not yet implemented", file=sys.stderr)
            return None


def download_vpn_configs(provider_name: str, config: configparser.ConfigParser, directory_override: Optional[Path] = None) -> bool:
    """
    Download VPN configuration files for the specified provider.
    
    Args:
        provider_name: Name of the VPN provider
        config: ConfigParser object with provider configuration
        directory_override: Optional directory path override
        
    Returns:
        True if download was successful, False otherwise
    """
    # Import here to avoid circular dependencies (config_manager doesn't import this module)
    try:
        from config_manager import get_provider_config, get_config_directory
    except ImportError:
        # Fallback if config_manager is not available (shouldn't happen in normal usage)
        print(f"Error: config_manager module not found", file=sys.stderr)
        return False
    
    provider_config = get_provider_config(config, provider_name)
    if not provider_config:
        print(f"Error: Provider '{provider_name}' not found in configuration", file=sys.stderr)
        return False
    
    if not provider_config['enabled']:
        print(f"Error: Provider '{provider_name}' is disabled in configuration", file=sys.stderr)
        return False
    
    base_url = provider_config['base_url']
    if not base_url:
        print(f"Error: No base_url configured for provider '{provider_name}'", file=sys.stderr)
        return False
    
    # Determine target directory
    if directory_override:
        target_dir = directory_override
    else:
        target_dir = Path(provider_config['directory'])
    
    # Get downloader instance
    downloader = VPNDownloaderFactory.get_downloader(provider_name)
    if not downloader:
        return False
    
    # Download configs
    try:
        downloader.download_configs(target_dir, base_url)
        return True
    except requests.RequestException as e:
        print(f"Error: Network error while downloading {provider_name} configs: {e}", file=sys.stderr)
        return False
    except (OSError, ValueError) as e:
        print(f"Error: Failed to download {provider_name} configs: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: Unexpected error while downloading {provider_name} configs: {e}", file=sys.stderr)
        return False

