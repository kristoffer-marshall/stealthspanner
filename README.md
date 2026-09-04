# StealthSpanner

A Python tool to test latency for VPN servers by reading OpenVPN configuration files and pinging each server concurrently. Supports multiple VPN providers with automatic configuration download.

## Features

- 🔍 **Automatic Discovery**: Automatically discovers all `.ovpn` files in a directory
- ⚡ **Concurrent Testing**: Tests multiple servers simultaneously using thread pools
- 📊 **Sorted Results**: Displays results sorted by latency (best to worst)
- 🎨 **Colorized Output**: Beautiful terminal output with color-coded status
- 📝 **Logging**: Automatically saves results to a log file
- 📈 **Progress Bar**: Real-time progress indication during testing
- 🔄 **Auto-Download**: Automatically downloads latest VPN configurations (configurable)
- 🎯 **Multi-Provider**: Supports multiple VPN providers (IPVanish, NordVPN, ProtonVPN, PIA)
- ⚙️ **Configurable**: User configuration file for customizing behavior

## Requirements

- `uv`
- Python 3.14+
- `openvpn` and `sudo` if you want to connect using `runVPN.py`
- `ufw` if you want to use killswitch mode

## Installation

Install project dependencies with `uv`:

```bash
uv sync
```

If you want to run commands without activating a virtual environment manually, use `uv run` in the examples below.

## Configuration

On first run, StealthSpanner will create a configuration file at `~/.stealthspanner.ini` from a template. You can edit this file to customize settings:

### Configuration File Location
- **User Config**: `~/.stealthspanner.ini` (created automatically on first run)
- **Template**: `config.template.ini` (in project directory)

### Configuration Options

```ini
[DEFAULT]
provider = ipvanish          # Default VPN provider
auto_download = true         # Automatically download configs on startup

[ipvanish]
enabled = true               # Enable IPVanish support
base_url = https://configs.ipvanish.com/openvpn/
directory = IPVanish         # Directory where configs are stored
```

You can enable/disable providers, change the default provider, or disable auto-download in the config file.

## Usage

### Basic Usage

Test latency for all `.ovpn` files (configs are downloaded automatically by default):

```bash
uv run python stealthspanner.py
```

### Command-Line Options

```
-h, --help          Show help message and exit
-p, --pings N       Number of ping attempts per host (default: 4)
-w, --workers N     Number of concurrent threads (default: 20)
-t, --timeout N     Ping timeout in seconds (default: 3.0)
-d, --directory DIR Directory containing .ovpn files (overrides config)
--no-download       Skip downloading VPN config files
--provider PROVIDER VPN provider to use (overrides config file)
```

### Examples

Test with 10 pings per server:
```bash
uv run python stealthspanner.py --pings 10
```

Select the lowest-latency `.ovpn` file from `vpn_latency_checker.log`:
```bash
uv run python runVPN.py
```

Print only the resolved `.ovpn` path (useful for scripting):
```bash
uv run python runVPN.py --print-only
```

Run the selected VPN without killswitch:
```bash
uv run python runVPN.py -r
```

Run the selected VPN with killswitch enabled:
```bash
uv run python runVPN.py -r -k
```

Skip downloading configs and use existing files:
```bash
uv run python stealthspanner.py --no-download
```

Use a specific provider:
```bash
uv run python stealthspanner.py --provider ipvanish
```

Use a custom directory:
```bash
uv run python stealthspanner.py --directory /path/to/ovpn/files
```

Combine options:
```bash
uv run python stealthspanner.py --pings 5 --workers 30 --timeout 4.0 --no-download
```

### VPN Provider Selection

StealthSpanner supports multiple VPN providers:

- **IPVanish** (default, fully implemented)
- **NordVPN** (placeholder - implementation needed)
- **ProtonVPN** (placeholder - implementation needed)
- **PIA** (Private Internet Access, placeholder - implementation needed)

Currently, only IPVanish is fully implemented. Other providers can be added by implementing the download logic in `vpn_config_downloader.py`.

## Output

The tool provides:

1. **Progress Bar**: Real-time progress during testing
2. **Results Table**: Formatted table showing:
   - Filename (`.ovpn` file name)
   - Hostname (server address)
   - Latency (average in milliseconds)
   - Status (Success/Failed/DNS Resolution Failed/Timeout)
3. **Summary Statistics**:
   - Total servers tested
   - Successful tests
   - Failed tests (with breakdown by failure type)
   - Best and worst latency

4. **Log File**: Results are automatically saved to `stealthspanner.log`

### Output Colors

- 🟢 **Green**: Successful pings with good latency (<100ms)
- 🔵 **Bright Green**: Excellent latency (<50ms)
- 🔴 **Red**: Failed pings or DNS errors
- 🟡 **Yellow**: Warnings or timeout errors

Note: Colors are automatically disabled if output is redirected to a file or if `NO_COLOR` environment variable is set.

## How It Works

1. **Configuration**: Loads user config file (creates from template if needed)
2. **Download** (if enabled): Downloads latest VPN configuration files for the selected provider
3. **Discovery**: Scans the specified directory for `.ovpn` files
4. **Parsing**: Extracts hostnames from the `remote` directive in each `.ovpn` file
5. **Testing**: Pings each hostname multiple times concurrently using a thread pool
6. **Analysis**: Calculates average latency for successful pings
7. **Reporting**: Displays sorted results and saves to log file

## File Structure

```
stealthspanner/
├── stealthspanner.py          # Main entry point
├── runVPN.py                  # Picks the best .ovpn and can run it
├── config_manager.py          # Configuration file management
├── vpn_config_downloader.py   # VPN config downloader (multi-provider)
├── config.template.ini        # Configuration template
├── requirements.txt           # Python dependencies
├── setup.sh                   # Setup script
├── README.md                  # This file
├── .gitignore                 # Git ignore rules
├── LICENSE                    # License file
├── IPVanish/                  # Directory containing IPVanish .ovpn files
├── stealthspanner.log         # Log file (generated on run)
└── ~/.stealthspanner.ini      # User configuration file (created on first run)
```

## Adding New VPN Providers

To add support for a new VPN provider:

1. Add a new section in `config.template.ini`:
```ini
[newprovider]
enabled = false
base_url = https://example.com/configs/
directory = NewProvider
```

2. Create a new downloader class in `vpn_config_downloader.py`:
```python
class NewProviderDownloader(BaseVPNDownloader):
    def download_configs(self, directory: Path, base_url: str) -> int:
        # Implement provider-specific download logic
        pass
```

3. Register it in `VPNDownloaderFactory.get_downloader()`:
```python
if provider_name_lower == 'newprovider':
    return NewProviderDownloader()
```

## Troubleshooting

### "ping3 library is required" Error

Make sure you've installed dependencies:
```bash
uv sync
```

### "No valid .ovpn files found" Error

- Ensure the directory path is correct
- Verify that `.ovpn` files exist in the directory
- Check that `.ovpn` files contain a valid `remote` directive
- Try running with `--no-download` if download failed

### Configuration File Issues

If you need to reset your configuration:
```bash
rm ~/.stealthspanner.ini
# Run `uv run python stealthspanner.py` again to recreate from template
```

### DNS Resolution Failures

Some servers may be temporarily unavailable or have DNS issues. This is normal and will be reported in the results.

### Permission Errors

If you encounter permission errors, ensure you have:
- Read access to the `.ovpn` files
- Write access to create the log file
- Write access to create/update the config directory

### Download Failures

If config downloads fail, StealthSpanner will continue with existing config files (if available). Check:
- Internet connection
- VPN provider's config server availability
- Firewall/proxy settings

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

See [LICENSE](LICENSE) file for details.

## Author

Created for testing VPN server latency and finding the best server for your location.
