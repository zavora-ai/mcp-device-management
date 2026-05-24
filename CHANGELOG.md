# Changelog

## [1.1.0] - 2026-05-24

### Added
- Cross-platform support: macOS, Linux, Windows (platform.rs dispatch module)
- 20 new tools (8 diagnose + 12 act) — total 37 tools
- Diagnose: ping_host, traceroute, dns_lookup, test_url, check_disk_health, get_recent_crashes, get_battery_status, get_usb_devices
- Act: kill_process, restart_service, flush_dns, renew_dhcp, empty_trash, purge_caches, enable_firewall, brew_install, brew_upgrade, brew_uninstall, lock_screen, restart_machine
- Package manager auto-detection: brew (macOS), apt (Linux), choco (Windows)
- Enterprise MDM backends: Intune, Jamf, Fleet, Kandji (feature-gated)
- restart_machine requires force=true confirmation (safety gate)

### Changed
- All tools now dispatch to correct OS commands via platform module
- Removed all hardcoded/seeded data — local backend reads real system info
- Local backend auto-detects on startup (no SEED_DATA env needed)

## [1.0.0] - 2026-05-24

### Added
- 17 MCP tools: observe (16) + remediation task (1)
- Local system backend reading real macOS data
- Device posture, compliance, health checks
