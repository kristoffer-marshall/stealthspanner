# StealthSpanner

A Python tool to test latency for VPN servers by reading OpenVPN configuration files and pinging each server concurrently. Supports multiple VPN providers with automatic configuration download.

## Features

- 🔍 **Automatic Discovery**: Automatically discovers all `.ovpn` files in a directory
- ⚡ **Concurrent Testing**: Tests multiple servers simultaneously using thread pools
- 📊 **Sorted Results**: Displays results sorted by latency (best to worst)
- 🎨 **Modern TUI Output**: Rich panels, progress bars, tables, and color-coded status
- 📝 **Logging**: Automatically saves results to a log file
- 📈 **Progress Bar**: Real-time progress indication during testing
- 🔄 **Auto-Download**: Automatically downloads latest VPN configurations (configurable)
- 🎯 **Multi-Provider**: Supports multiple VPN providers (IPVanish, NordVPN, ProtonVPN, PIA)
- ⚙️ **Configurable**: User configuration file for customizing behavior

## Requirements

- `uv`
- Python 3.14+
- `openvpn` and `sudo` if you want StealthSpanner to connect using the selected `.ovpn`
- `ufw` if you want to use killswitch mode

## Installation

Install project dependencies with `uv`:

```bash
uv sync
```

If you want to run commands without activating a virtual environment manually, use `uv run` in the examples below.

## Configuration

On first run, StealthSpanner will create a configuration file at `~/.config/stealthspanner/config.ini` from a template. If a legacy config exists at `~/.stealthspanner.ini`, it will still be used with a warning until you migrate it.

### Configuration File Location
- **User Config**: `~/.config/stealthspanner/config.ini`
- **Legacy Config Fallback**: `~/.stealthspanner.ini`
- **VPN Credentials**: `~/.config/stealthspanner/vpn_creds`
- **Legacy Credentials Fallback**: `~/.vpn_creds`
- **Scan Log**: `~/.local/state/stealthspanner/stealthspanner.log`
- **Legacy Scan Log Fallback for older data**: `./vpn_latency_checker.log`
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

Run StealthSpanner with no options to open the startup menu:

```bash
uv run python stealthspanner.py
```

The startup menu lets you:
- run a new latency scan
- view the last saved scan
- open the VPN picker
- select the best VPN from the saved scan
- run the saved default VPN choice (or best latency if no default is saved)

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

Run a new latency scan directly with 10 pings per server:
```bash
uv run python stealthspanner.py --pings 10
```

Show the results from the last saved latency scan:
```bash
uv run python stealthspanner.py --last-scan
```

Select the lowest-latency `.ovpn` file from the default latency log location:
```bash
uv run python stealthspanner.py --select-vpn
```

Open the interactive TUI VPN picker:
```bash
uv run python stealthspanner.py --pick-vpn
```

The picker lets you choose a VPN by:
- best score
- best latency
- best packet loss
- best privacy
- country
- city
- region
- saved favorites

Picker navigation:
- `↑` / `↓` arrow keys to move
- `Enter` to select
- `b` or `←` to go back
- `q` to cancel
- `j` / `k` also work for movement
- large menus automatically scroll to fit the current terminal height
- the selected row stays within the visible window as you move through long lists

Location drill-down supports:
- country → VPN
- city → random profile from that city
- region → country → VPN

Print only the resolved `.ovpn` path (useful for scripting):
```bash
uv run python stealthspanner.py --select-vpn --print-only
```

Run the selected VPN without killswitch:
```bash
uv run python stealthspanner.py --select-vpn -r
```

By default, StealthSpanner keeps OpenVPN output concise and shows a success message once connected, along with your public IP and FQDN before and after the VPN comes up.

Run using the saved default preference if one exists:
```bash
uv run python stealthspanner.py -r
```

If the saved default is a specific profile, that exact `.ovpn` is used.
If the saved default is a country, city, or region, StealthSpanner chooses a random successful profile from that location when `-r` or `--run` is used.

Run the selected VPN with killswitch enabled:
```bash
uv run python stealthspanner.py --select-vpn -r -k
```

Show full OpenVPN / killswitch connection logs:
```bash
uv run python stealthspanner.py --select-vpn -r --verbose
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

### Picker Favorites and Defaults

While using `--pick-vpn`, after selecting a VPN you can optionally:
- save the individual VPN as a favorite
- save its country as a favorite
- save its city as a favorite
- save its region as a favorite
- set the individual VPN as the default
- set its country as the default
- set its city as the default
- set its region as the default

The TUI now supports back/forward-style drill-down navigation through picker menus, including browsing regions first and then narrowing to countries within that region.

These preferences are stored in the `[PICKER]` section of `~/.config/stealthspanner/config.ini` or your legacy config if you are still using it.

### VPN Provider Selection

StealthSpanner supports multiple VPN providers:

- **IPVanish** (default, fully implemented)
- **NordVPN** (placeholder - implementation needed)
- **ProtonVPN** (placeholder - implementation needed)
- **PIA** (Private Internet Access, placeholder - implementation needed)

Currently, only IPVanish is fully implemented. Other providers can be added by implementing the download logic in `vpn_config_downloader.py`.

## Output

The tool provides:

1. **TUI Progress View**: Real-time progress during testing
2. **Results Table**: Rich-formatted table showing:
   - Filename (`.ovpn` file name)
   - Hostname (server address)
   - Country / privacy score
   - Score, latency, jitter, packet loss, and status
3. **Summary Statistics**:
   - Total servers tested
   - Successful tests
   - Failed tests (with breakdown by failure type)
   - Best and worst score
   - Best and worst latency
   - Best and worst jitter
   - Best and worst packet loss
   - Best and worst privacy

4. **Last Scan View**:
   - shows when the last scan was run
   - re-renders saved results from `stealthspanner.log`

5. **Managed VPN Connection View**:
   - concise connection messages by default
   - full OpenVPN noise only with `-v` / `--verbose`
   - Ctrl+C disconnects gracefully
   - shows the public IP and FQDN before and after the VPN connects
   - reminds the user to press Ctrl+C to disconnect

6. **Parseable Log File**: Results are automatically saved to:
   - `~/.local/state/stealthspanner/stealthspanner.log`
   - the saved log contains a machine-readable scan section with hostname, latency, score, packet loss, and status
   - `--last-scan`, `--select-vpn`, and `--pick-vpn` read from this log

### Output Style

StealthSpanner now uses a modern terminal UI with:

- panels for summaries, connection details, and saved paths
- progress bars during testing
- rich tables for latency and VPN selection results
- an interactive TUI picker for score, latency, packet loss, privacy, country, favorites, and region→country drill-down
- cleaner truncation for long filenames and paths
- color-coded latency, score, status, and warnings

If your terminal does not support color, the output still remains readable.

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
├── stealthspanner.py          # Main entry point for testing and optional VPN launch
├── config_manager.py          # Configuration file management
├── vpn_config_downloader.py   # VPN config downloader (multi-provider)
├── config.template.ini        # Configuration template
├── requirements.txt           # Python dependencies
├── setup.sh                   # Setup script
├── README.md                  # This file
├── .gitignore                 # Git ignore rules
├── LICENSE                    # License file
├── IPVanish/                  # Directory containing IPVanish .ovpn files
└── ~/.config/stealthspanner/  # User config and credentials (created on first run)

~/.local/state/stealthspanner/
└── stealthspanner.log         # Runtime log file and last-scan source
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
rm ~/.config/stealthspanner/config.ini
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
