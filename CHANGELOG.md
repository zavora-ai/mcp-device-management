# Changelog

## [1.0.0] - 2026-05-24

### Added
- 7 MCP tools: lookup_device, list_user_devices, get_device_posture, get_installed_apps, collect_device_logs, run_health_check, create_device_remediation_task
- Device posture with compliance state, encryption, firewall, AV, OS patches, risk score
- Health check computing overall device health (healthy/degraded/critical)
- Remediation task creation for non-compliant devices
- Seeded demo data via SEED_DATA env var
