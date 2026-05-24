# Device Management MCP Server

[![Crates.io](https://img.shields.io/crates/v/mcp-device-management.svg)](https://crates.io/crates/mcp-device-management)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![ADK-Rust Enterprise](https://img.shields.io/badge/ADK--Rust-Enterprise-purple.svg)](https://enterprise.adk-rust.com)

Full device management for [ADK-Rust Enterprise](https://enterprise.adk-rust.com) agents. 37 MCP tools that **observe**, **diagnose**, and **act** on real devices — no mocks, no hardcoded data. Auto-detects the local machine on startup. Enterprise backends (Intune, Jamf, Fleet, Kandji) via feature flags.

## What It Does

Your AI agent becomes a sysadmin. It can check what's wrong, troubleshoot the problem, and fix it — all from natural language.

```
"Why is my machine slow?"     → get_system_stats + list_running_processes → kill_process
"Can I reach the server?"     → ping_host + dns_lookup + test_url
"Free up disk space"          → get_disk_usage + find_large_files + empty_trash + purge_caches
"Is my machine secure?"       → get_security_status → enable_firewall
"Update my packages"          → list_brew_packages(outdated) → brew_upgrade
```

## Architecture

<p align="center">
  <img src="https://raw.githubusercontent.com/zavora-ai/mcp-device-management/main/docs/architecture.svg" alt="Device Management MCP Architecture" width="700"/>
</p>

## Tools (37)

### Observe (16) — see what's happening

| Tool | What It Does |
|------|-------------|
| `lookup_device` | Find device by name/serial/ID |
| `list_user_devices` | All devices for a user |
| `get_device_posture` | Compliance, encryption, firewall, AV, risk score |
| `get_installed_apps` | Applications installed |
| `get_security_status` | FileVault, firewall, SIP, Gatekeeper |
| `get_system_stats` | Live CPU, memory, disk, load average |
| `list_running_processes` | Top processes by CPU or memory |
| `get_network_info` | IP, WiFi, VPN, active connections |
| `get_open_ports` | Listening ports and processes |
| `collect_device_logs` | System info, storage, posture summary |
| `run_health_check` | Overall health assessment (healthy/degraded/critical) |
| `get_disk_usage` | Per-directory size breakdown |
| `find_large_files` | Files over N MB |
| `list_brew_packages` | Homebrew installed or outdated |
| `check_os_updates` | Pending system updates |
| `list_login_items` | Startup items and launch agents |

### Diagnose (8) — troubleshoot problems

| Tool | What It Does |
|------|-------------|
| `ping_host` | Ping with latency and packet loss |
| `traceroute` | Network path to a host |
| `dns_lookup` | Resolve hostname to IP |
| `test_url` | HTTP GET with status code and response time |
| `check_disk_health` | SMART status via diskutil |
| `get_recent_crashes` | Recent crash reports |
| `get_battery_status` | Charge, cycle count, condition |
| `get_usb_devices` | Connected USB/Thunderbolt peripherals |

### Act (13) — fix things

| Tool | What It Does | Risk |
|------|-------------|------|
| `kill_process` | Kill by PID or name | Medium |
| `restart_service` | Restart a launchd service | Medium |
| `flush_dns` | Clear DNS cache | Low |
| `renew_dhcp` | Get fresh IP address | Low |
| `empty_trash` | Reclaim disk space | Low |
| `purge_caches` | Clear system + Xcode caches | Medium |
| `enable_firewall` | Turn on macOS firewall | Low |
| `brew_install` | Install a Homebrew package | Medium |
| `brew_upgrade` | Upgrade packages (all or specific) | Medium |
| `brew_uninstall` | Remove a package | Medium |
| `lock_screen` | Lock screen immediately | Low |
| `restart_machine` | Restart (requires force=true) | Critical |
| `create_device_remediation_task` | Create a tracked remediation task | Low |

## Verified Output (Real System)

```
> get_system_stats()
  load: { 6.37 6.46 6.69 }, mem: 87%, disk: 52%

> list_running_processes(limit: 3)
  Kiro.app — cpu=284.9% mem=0.2%
  node — cpu=88.8% mem=0.9%
  VirtualBuddy — cpu=11.2% mem=3.4%

> get_network_info()
  ip=192.168.100.45, vpn=false, connections=59

> get_security_status()
  filevault=true, firewall=false, sip=true, gatekeeper=true

> ping_host(host: "google.com")
  reachable=true, "round-trip min/avg/max = 5.2/8.1/12.3 ms"

> list_brew_packages(outdated_only: true)
  3 outdated: node@22, python@3.12, rust

> get_open_ports()
  20 listening: rapportd:49152, node:3000, postgres:5432
```

## Installation

```bash
git clone https://github.com/zavora-ai/mcp-device-management
cd mcp-device-management
cargo build --release
```

No configuration needed — auto-detects the local machine.

### MCP client config

```json
{
  "mcpServers": {
    "device": {
      "command": "/path/to/mcp-device-management"
    }
  }
}
```

## Enterprise Backends

| Backend | Feature Flag | Env Vars |
|---------|-------------|----------|
| **Local** (default) | `local` | None — auto-detects |
| **Intune** | `intune` | `INTUNE_TENANT_ID`, `INTUNE_CLIENT_ID`, `INTUNE_CLIENT_SECRET` |
| **Jamf** | `jamf` | `JAMF_URL`, `JAMF_API_TOKEN` |
| **Fleet** | `fleet` | `FLEET_URL`, `FLEET_API_TOKEN` |
| **Kandji** | `kandji` | `KANDJI_URL`, `KANDJI_API_TOKEN` |

```bash
cargo build --release --features all-backends
```

## Governance

| Risk | Tools | Notes |
|------|-------|-------|
| Read-only | All Observe + Diagnose tools | Safe anytime |
| Low | flush_dns, renew_dhcp, empty_trash, enable_firewall, lock_screen | Reversible, no data loss |
| Medium | kill_process, purge_caches, brew_install/upgrade/uninstall, restart_service | May affect running work |
| Critical | restart_machine | Requires `force=true` confirmation |

## MCP Server Manifest

```toml
server_id = "mcp_device_management"
display_name = "Device Management MCP"
version = "1.1.0"
domain = "it_operations"
risk_level = "medium"
writes_allowed = "gated"
transports = ["stdio"]
governance_gates = ["critical_actions_require_confirmation"]
```

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START -->
| [<img src="https://github.com/jkmaina.png" width="80px;" alt=""/><br /><sub><b>James Karanja Maina</b></sub>](https://github.com/jkmaina) |
|:---:|
<!-- ALL-CONTRIBUTORS-LIST:END -->

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

---

Part of the [ADK-Rust Enterprise](https://enterprise.adk-rust.com) MCP server ecosystem.
