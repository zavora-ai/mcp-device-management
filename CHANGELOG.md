# Changelog

## [1.4.0] - 2026-05-24

### Added
- 7 new tools from Endpoint Security + Network scope (total: 44)
- `get_patch_status` — pending OS patches with severity
- `get_encryption_status` — detailed FileVault/BitLocker/LUKS info
- `list_security_findings` — aggregate security issues with severity and remediation
- `check_vpn_status` — VPN connection state and details
- `check_firewall_rule` — inspect specific firewall rules by port/service
- `get_network_outages` — multi-host reachability check (outage detection)
- `test_connectivity` — comprehensive DNS+ping+HTTP diagnosis with explanation

### Changed
- Now covers inventory items #18 (Device), #19 (Endpoint Security), #20 (Network)

## [1.3.0] - 2026-05-24

### Added
- MCP elicitation for destructive actions (kill_process, enable_firewall, restart_machine)
- User gets confirmation prompt before dangerous operations
- Falls back gracefully if client doesn't support elicitation
- Uses `Peer<RoleServer>` extractor in tool functions

## [1.2.0] - 2026-05-24

### Added
- Cross-platform support via `platform.rs` dispatch module
- macOS, Linux, Windows commands for all 37 tools
- Package manager auto-detection: brew (macOS), apt (Linux), choco (Windows)

### Changed
- All tools dispatch to correct OS commands automatically
- Removed all hardcoded/seeded data

## [1.1.0] - 2026-05-24

### Added
- 20 new tools (8 diagnose + 12 act) — total 37
- Diagnose: ping, traceroute, DNS, test URL, disk health, crashes, battery, USB
- Act: kill, restart service, flush DNS, renew DHCP, empty trash, purge caches, enable firewall, brew install/upgrade/uninstall, lock screen, restart machine
- Enterprise MDM backends: Intune, Jamf, Fleet, Kandji (feature-gated)
- Local backend reads real system info (no seeds)

## [1.0.0] - 2026-05-24

### Added
- Initial release with 7 tools
- lookup_device, list_user_devices, get_device_posture
- get_installed_apps, collect_device_logs, run_health_check
- create_device_remediation_task
