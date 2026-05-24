# API Reference

## Observe Tools

### get_system_stats
Get live CPU, memory, disk usage, and load average.

**Parameters:** None

**Returns:**
```json
{ "os": "macos", "load": "{ 5.95 6.21 6.24 }", "memory_total_gb": 24, "disk": { "total": "460Gi", "free": "10Gi", "used_pct": "63%" } }
```

### list_running_processes
List top processes sorted by CPU or memory.

**Parameters:** `sort_by` (optional: "cpu" or "mem"), `limit` (optional, default 10)

**Returns:** Array of processes with user, pid, cpu%, mem%, command.

### get_network_info
Get IP address, WiFi SSID, VPN status, active connection count.

**Parameters:** None

### get_security_status
Full security posture: FileVault/BitLocker, firewall, SIP/SELinux, Gatekeeper/Defender.

**Parameters:** None

### get_open_ports
List all listening TCP ports with process names.

**Parameters:** None

### get_disk_usage
Per-directory size breakdown.

**Parameters:** `path` (optional, default "~")

### find_large_files
Find files over a given size.

**Parameters:** `path` (optional), `min_size_mb` (optional, default 100)

### list_brew_packages
List installed packages or only outdated ones.

**Parameters:** `outdated_only` (optional bool)

---

## Diagnose Tools

### ping_host
Ping a host with latency and packet loss stats.

**Parameters:** `host` (required), `count` (optional, default 4)

### test_connectivity
Comprehensive check: DNS resolution + ping + HTTP GET. Returns diagnosis.

**Parameters:** `host` (required)

**Returns:**
```json
{ "host": "github.com", "dns": true, "ping": true, "http": true, "diagnosis": "All checks passed — connectivity is healthy" }
```

### get_network_outages
Check multiple hosts for reachability. Detects outages.

**Parameters:** `hosts` (optional, default: google.com, github.com, 1.1.1.1, 8.8.8.8)

### list_security_findings
Aggregate all security issues: firewall, encryption, ports, disk space.

**Parameters:** None

**Returns:**
```json
{ "count": 2, "risk_level": "high", "findings": [{ "severity": "high", "finding": "Firewall is disabled", "remediation": "enable_firewall" }] }
```

### get_patch_status
Show pending OS patches.

**Parameters:** None

### get_encryption_status
Detailed encryption info: method, enabled, volumes.

**Parameters:** None

### check_vpn_status
VPN connection state and active connections.

**Parameters:** None

---

## Act Tools

### kill_process ⚠️ Elicitation
Kill a process. Prompts for confirmation.

**Parameters:** `pid` (optional), `name` (optional) — provide one

### enable_firewall ⚠️ Elicitation
Enable the system firewall. Prompts for confirmation.

**Parameters:** None

### restart_machine ⚠️ Elicitation
Restart the machine. Prompts for confirmation unless `force: true`.

**Parameters:** `force` (optional bool)

### flush_dns
Clear DNS cache. Fixes stale resolution.

**Parameters:** None

### brew_install
Install a package via brew/apt/choco.

**Parameters:** `package` (required)

### brew_upgrade
Upgrade all or specific packages.

**Parameters:** `package` (optional — all if omitted)

### empty_trash
Empty Trash/Recycle Bin.

**Parameters:** None

---

## Elicitation Protocol

Tools marked with ⚠️ use MCP elicitation (MCP 2025-06-18 spec):

1. Tool is called
2. Server sends `elicitation/create` request to client
3. Client shows confirmation UI to user
4. User accepts or declines
5. Tool executes or aborts

If the client doesn't support elicitation, the tool proceeds with a warning in the description.
