use crate::store::DeviceStore;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupDeviceInput { pub query: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListUserDevicesInput { pub user_id: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetDevicePostureInput { pub device_id: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetInstalledAppsInput { pub device_id: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CollectDeviceLogsInput { pub device_id: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunHealthCheckInput { pub device_id: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateRemediationTaskInput { pub device_id: String, pub action: String, pub reason: String }

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSystemStatsInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListRunningProcessesInput { pub sort_by: Option<String>, pub limit: Option<usize> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetNetworkInfoInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSecurityStatusInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckOsUpdatesInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListBrewPackagesInput { pub outdated_only: Option<bool> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetDiskUsageInput { pub path: Option<String> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindLargeFilesInput { pub path: Option<String>, pub min_size_mb: Option<u64> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListLoginItemsInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetOpenPortsInput {}

// --- Diagnose tools ---
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PingHostInput { pub host: String, pub count: Option<u32> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TracerouteInput { pub host: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DnsLookupInput { pub hostname: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TestUrlInput { pub url: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckDiskHealthInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetRecentCrashesInput { pub limit: Option<usize> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBatteryStatusInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetUsbDevicesInput {}

// --- Act tools ---
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KillProcessInput { pub pid: Option<u32>, pub name: Option<String> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RestartServiceInput { pub service: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlushDnsInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenewDhcpInput { pub interface: Option<String> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EmptyTrashInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PurgeCachesInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EnableFirewallInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BrewInstallInput { pub package: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BrewUpgradeInput { pub package: Option<String> }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BrewUninstallInput { pub package: String }
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LockScreenInput {}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RestartMachineInput { pub force: Option<bool> }

#[derive(Clone)]
pub struct DeviceServer { pub store: Arc<DeviceStore> }

#[tool_router(server_handler)]
impl DeviceServer {
    #[tool(description = "Look up a device by ID, name, or serial number")]
    fn lookup_device(&self, Parameters(i): Parameters<LookupDeviceInput>) -> String {
        let devices = self.store.lookup_device(&i.query);
        let results: Vec<serde_json::Value> = devices.iter().map(|d| serde_json::json!({
            "id": d.id, "name": d.name, "type": d.device_type, "status": d.status,
            "owner": d.owner, "os": format!("{} {}", d.os.name, d.os.version),
            "model": format!("{} {}", d.hardware.manufacturer, d.hardware.model),
            "compliance": d.posture.compliance, "last_seen": d.last_seen,
        })).collect();
        serde_json::to_string_pretty(&serde_json::json!({"count": results.len(), "devices": results})).unwrap()
    }

    #[tool(description = "List all devices owned by a user")]
    fn list_user_devices(&self, Parameters(i): Parameters<ListUserDevicesInput>) -> String {
        let devices = self.store.list_user_devices(&i.user_id);
        let results: Vec<serde_json::Value> = devices.iter().map(|d| serde_json::json!({
            "id": d.id, "name": d.name, "type": d.device_type, "os": format!("{} {}", d.os.name, d.os.version),
            "compliance": d.posture.compliance, "risk_score": d.posture.risk_score,
        })).collect();
        serde_json::to_string_pretty(&serde_json::json!({"user_id": i.user_id, "count": results.len(), "devices": results})).unwrap()
    }

    #[tool(description = "Get device security posture — encryption, firewall, antivirus, OS patches, compliance state, and risk score")]
    fn get_device_posture(&self, Parameters(i): Parameters<GetDevicePostureInput>) -> String {
        match self.store.get_posture(&i.device_id) {
            Some((p, name)) => serde_json::to_string_pretty(&serde_json::json!({
                "device_id": i.device_id, "device_name": name, "compliance": p.compliance, "risk_score": p.risk_score,
                "checks": {"encryption": p.encryption_enabled, "firewall": p.firewall_enabled, "antivirus": p.antivirus_active, "os_updated": p.os_up_to_date, "disk_encrypted": p.disk_encrypted, "screen_lock": p.screen_lock_enabled},
                "last_assessed": p.last_assessed,
            })).unwrap(),
            None => format!("Device not found: {}", i.device_id),
        }
    }

    #[tool(description = "List installed applications on a device")]
    fn get_installed_apps(&self, Parameters(i): Parameters<GetInstalledAppsInput>) -> String {
        match self.store.get_installed_apps(&i.device_id) {
            Some(apps) => serde_json::to_string_pretty(&serde_json::json!({"device_id": i.device_id, "count": apps.len(), "apps": apps})).unwrap(),
            None => format!("Device not found: {}", i.device_id),
        }
    }

    #[tool(description = "Collect diagnostic logs from a device — system log, health metrics, resource usage")]
    fn collect_device_logs(&self, Parameters(i): Parameters<CollectDeviceLogsInput>) -> String {
        match self.store.collect_logs(&i.device_id) {
            Some(v) => serde_json::to_string_pretty(&v).unwrap(),
            None => format!("Device not found: {}", i.device_id),
        }
    }

    #[tool(description = "Run a health check on a device — verify encryption, firewall, antivirus, OS patches, and compute risk score")]
    fn run_health_check(&self, Parameters(i): Parameters<RunHealthCheckInput>) -> String {
        match self.store.run_health_check(&i.device_id) {
            Some(v) => serde_json::to_string_pretty(&v).unwrap(),
            None => format!("Device not found: {}", i.device_id),
        }
    }

    #[tool(description = "Create a remediation task for a device (e.g., force OS update, enable encryption, install antivirus)")]
    fn create_device_remediation_task(&self, Parameters(i): Parameters<CreateRemediationTaskInput>) -> String {
        match self.store.create_remediation(&i.device_id, &i.action, &i.reason) {
            Ok(t) => serde_json::to_string_pretty(&serde_json::json!({"task_id": t.id, "device_id": t.device_id, "action": t.action, "status": t.status})).unwrap(),
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(description = "Get live system stats — CPU usage, memory usage, disk usage, load average")]
    async fn get_system_stats(&self) -> String {
        let load = cmd("sysctl", &["-n", "vm.loadavg"]);
        let mem_total: u64 = cmd("sysctl", &["-n", "hw.memsize"]).parse().unwrap_or(0);
        let page_size: u64 = cmd("sysctl", &["-n", "hw.pagesize"]).parse().unwrap_or(4096);
        let pages_free: u64 = cmd("vm_stat", &[]).lines().find(|l| l.contains("Pages free")).and_then(|l| l.split_whitespace().last()).and_then(|s| s.trim_matches('.').parse().ok()).unwrap_or(0);
        let mem_free = pages_free * page_size;
        let mem_used_pct = if mem_total > 0 { ((mem_total - mem_free) * 100 / mem_total) } else { 0 };

        let df = cmd("df", &["-h", "/"]);
        let disk_line = df.lines().nth(1).unwrap_or("");
        let disk_parts: Vec<&str> = disk_line.split_whitespace().collect();

        serde_json::to_string_pretty(&serde_json::json!({
            "load_average": load.trim(),
            "memory": {"total_gb": mem_total / 1_073_741_824, "used_pct": format!("{}%", mem_used_pct)},
            "disk": {"total": disk_parts.get(1).unwrap_or(&"?"), "used": disk_parts.get(2).unwrap_or(&"?"), "free": disk_parts.get(3).unwrap_or(&"?"), "used_pct": disk_parts.get(4).unwrap_or(&"?")},
        })).unwrap()
    }

    #[tool(description = "List top running processes by CPU or memory usage")]
    async fn list_running_processes(&self, Parameters(i): Parameters<ListRunningProcessesInput>) -> String {
        let limit = i.limit.unwrap_or(10);
        let sort = i.sort_by.as_deref().unwrap_or("cpu");
        let output = if sort == "memory" || sort == "mem" {
            cmd("ps", &["aux", "-m"])
        } else {
            cmd("ps", &["aux", "-r"])
        };
        let lines: Vec<&str> = output.lines().take(limit + 1).collect();
        let header = lines.first().unwrap_or(&"");
        let procs: Vec<serde_json::Value> = lines.iter().skip(1).map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            serde_json::json!({"user": parts.get(0), "pid": parts.get(1), "cpu": parts.get(2), "mem": parts.get(3), "command": parts.get(10..).map(|p| p.join(" "))})
        }).collect();
        serde_json::to_string_pretty(&serde_json::json!({"sort_by": sort, "count": procs.len(), "processes": procs})).unwrap()
    }

    #[tool(description = "Get network info — IP addresses, WiFi SSID, VPN status, active connections")]
    async fn get_network_info(&self) -> String {
        let ifconfig = cmd("ifconfig", &[]);
        let ip = ifconfig.lines().find(|l| l.contains("inet ") && !l.contains("127.0.0.1")).and_then(|l| l.split_whitespace().nth(1)).unwrap_or("unknown");
        let wifi = cmd("networksetup", &["-getairportnetwork", "en0"]);
        let ssid = wifi.split(':').nth(1).map(|s| s.trim()).unwrap_or("not connected");
        let vpn = cmd("scutil", &["--nc", "list"]);
        let vpn_active = vpn.lines().any(|l| l.contains("Connected"));
        let connections = cmd("netstat", &["-an"]).lines().filter(|l| l.contains("ESTABLISHED")).count();

        serde_json::to_string_pretty(&serde_json::json!({
            "ip_address": ip, "wifi_ssid": ssid, "vpn_connected": vpn_active,
            "active_connections": connections,
        })).unwrap()
    }

    #[tool(description = "Get full security status — FileVault, firewall, SIP, Gatekeeper, XProtect")]
    async fn get_security_status(&self) -> String {
        let filevault = cmd("fdesetup", &["status"]);
        let sip = cmd("csrutil", &["status"]);
        let gatekeeper = cmd("spctl", &["--status"]);
        let firewall = cmd("defaults", &["read", "/Library/Preferences/com.apple.alf", "globalstate"]);

        serde_json::to_string_pretty(&serde_json::json!({
            "filevault": filevault.contains("On"),
            "firewall": firewall.trim() != "0" && !firewall.is_empty(),
            "sip_enabled": sip.contains("enabled"),
            "gatekeeper": gatekeeper.contains("enabled") || gatekeeper.contains("assessments enabled"),
            "xprotect": true,
            "details": {"filevault_raw": filevault.trim(), "sip_raw": sip.trim(), "gatekeeper_raw": gatekeeper.trim()},
        })).unwrap()
    }

    #[tool(description = "Check for available OS updates")]
    async fn check_os_updates(&self) -> String {
        let output = cmd("softwareupdate", &["-l", "--no-scan"]);
        let updates: Vec<&str> = output.lines().filter(|l| l.contains("*") || l.contains("Label:")).collect();
        serde_json::to_string_pretty(&serde_json::json!({"updates_available": !updates.is_empty(), "count": updates.len(), "updates": updates})).unwrap()
    }

    #[tool(description = "List Homebrew packages — all installed or only outdated")]
    async fn list_brew_packages(&self, Parameters(i): Parameters<ListBrewPackagesInput>) -> String {
        if i.outdated_only.unwrap_or(false) {
            let output = cmd("brew", &["outdated", "--json=v2"]);
            if output.is_empty() { return serde_json::json!({"outdated": [], "count": 0}).to_string(); }
            let parsed: serde_json::Value = serde_json::from_str(&output).unwrap_or(serde_json::json!({}));
            let formulae: Vec<serde_json::Value> = parsed["formulae"].as_array().unwrap_or(&vec![]).iter().map(|f| serde_json::json!({"name": f["name"], "current": f["installed_versions"][0], "latest": f["current_version"]})).collect();
            serde_json::to_string_pretty(&serde_json::json!({"outdated": formulae, "count": formulae.len()})).unwrap()
        } else {
            let output = cmd("brew", &["list", "--formula", "-1"]);
            let packages: Vec<&str> = output.lines().collect();
            serde_json::to_string_pretty(&serde_json::json!({"packages": packages, "count": packages.len()})).unwrap()
        }
    }

    #[tool(description = "Get disk usage breakdown by directory")]
    async fn get_disk_usage(&self, Parameters(i): Parameters<GetDiskUsageInput>) -> String {
        let path = i.path.as_deref().unwrap_or("~");
        let expanded = if path == "~" { std::env::var("HOME").unwrap_or_else(|_| "/".into()) } else { path.to_string() };
        let output = cmd("du", &["-sh", &format!("{}/*/", expanded)]);
        let entries: Vec<serde_json::Value> = output.lines().take(20).map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            serde_json::json!({"size": parts.first().unwrap_or(&"?"), "path": parts.get(1).unwrap_or(&"?")})
        }).collect();
        serde_json::to_string_pretty(&serde_json::json!({"path": expanded, "entries": entries})).unwrap()
    }

    #[tool(description = "Find large files over a given size (default 100MB)")]
    async fn find_large_files(&self, Parameters(i): Parameters<FindLargeFilesInput>) -> String {
        let path = i.path.as_deref().unwrap_or(".");
        let min_mb = i.min_size_mb.unwrap_or(100);
        let output = cmd("find", &[path, "-type", "f", "-size", &format!("+{}M", min_mb), "-exec", "ls", "-lh", "{}", ";"]);
        let files: Vec<serde_json::Value> = output.lines().take(20).map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            serde_json::json!({"size": parts.get(4).unwrap_or(&"?"), "path": parts.get(8..).map(|p| p.join(" ")).unwrap_or_default()})
        }).collect();
        serde_json::to_string_pretty(&serde_json::json!({"min_size_mb": min_mb, "count": files.len(), "files": files})).unwrap()
    }

    #[tool(description = "List login items and launch agents that run at startup")]
    async fn list_login_items(&self) -> String {
        let launch_agents = cmd("ls", &[&format!("{}/Library/LaunchAgents", std::env::var("HOME").unwrap_or_default())]);
        let system_agents = cmd("ls", &["/Library/LaunchAgents"]);
        let agents: Vec<&str> = launch_agents.lines().chain(system_agents.lines()).filter(|l| l.ends_with(".plist")).collect();
        serde_json::to_string_pretty(&serde_json::json!({"login_items": agents, "count": agents.len()})).unwrap()
    }

    #[tool(description = "List open/listening network ports and their processes")]
    async fn get_open_ports(&self) -> String {
        let output = cmd("lsof", &["-iTCP", "-sTCP:LISTEN", "-nP"]);
        let ports: Vec<serde_json::Value> = output.lines().skip(1).take(20).map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            serde_json::json!({"process": parts.first().unwrap_or(&"?"), "pid": parts.get(1).unwrap_or(&"?"), "address": parts.get(8).unwrap_or(&"?")})
        }).collect();
        serde_json::to_string_pretty(&serde_json::json!({"listening_ports": ports, "count": ports.len()})).unwrap()
    }

    // ═══════════════════════════════════════════════════════════════
    // DIAGNOSE — troubleshoot problems
    // ═══════════════════════════════════════════════════════════════

    #[tool(description = "Ping a host — returns latency and packet loss")]
    async fn ping_host(&self, Parameters(i): Parameters<PingHostInput>) -> String {
        let count = i.count.unwrap_or(4).to_string();
        let output = cmd("ping", &["-c", &count, &i.host]);
        let stats = output.lines().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        serde_json::to_string_pretty(&serde_json::json!({"host": i.host, "result": stats, "reachable": output.contains("bytes from")})).unwrap()
    }

    #[tool(description = "Trace network path to a host")]
    async fn traceroute(&self, Parameters(i): Parameters<TracerouteInput>) -> String {
        let output = cmd("traceroute", &["-m", "15", "-w", "2", &i.host]);
        let hops: Vec<&str> = output.lines().skip(1).take(15).collect();
        serde_json::to_string_pretty(&serde_json::json!({"host": i.host, "hops": hops.len(), "trace": hops})).unwrap()
    }

    #[tool(description = "DNS lookup — resolve a hostname to IP addresses")]
    async fn dns_lookup(&self, Parameters(i): Parameters<DnsLookupInput>) -> String {
        let output = cmd("nslookup", &[&i.hostname]);
        let addresses: Vec<&str> = output.lines().filter(|l| l.starts_with("Address:") || l.contains("address")).collect();
        serde_json::to_string_pretty(&serde_json::json!({"hostname": i.hostname, "results": addresses, "resolved": !addresses.is_empty()})).unwrap()
    }

    #[tool(description = "Test a URL — HTTP GET and return status code and response time")]
    async fn test_url(&self, Parameters(i): Parameters<TestUrlInput>) -> String {
        let output = cmd("curl", &["-o", "/dev/null", "-s", "-w", "%{http_code} %{time_total}", "-m", "10", &i.url]);
        let parts: Vec<&str> = output.split_whitespace().collect();
        serde_json::to_string_pretty(&serde_json::json!({"url": i.url, "status_code": parts.first().unwrap_or(&"0"), "response_time_sec": parts.get(1).unwrap_or(&"?"), "reachable": parts.first().map(|s| *s != "000").unwrap_or(false)})).unwrap()
    }

    #[tool(description = "Check disk health via SMART/diskutil")]
    async fn check_disk_health(&self) -> String {
        let output = cmd("diskutil", &["info", "/"]);
        let smart = cmd("diskutil", &["apfs", "list"]);
        let status = output.lines().find(|l| l.contains("SMART Status") || l.contains("S.M.A.R.T.")).unwrap_or("SMART Status: Unknown");
        serde_json::to_string_pretty(&serde_json::json!({"disk": "/", "smart_status": status.trim(), "healthy": status.contains("Verified") || status.contains("Ok")})).unwrap()
    }

    #[tool(description = "Get recent application crash reports")]
    async fn get_recent_crashes(&self, Parameters(i): Parameters<GetRecentCrashesInput>) -> String {
        let limit = i.limit.unwrap_or(10);
        let home = std::env::var("HOME").unwrap_or_default();
        let output = cmd("ls", &["-lt", &format!("{}/Library/Logs/DiagnosticReports", home)]);
        let crashes: Vec<&str> = output.lines().skip(1).take(limit).collect();
        serde_json::to_string_pretty(&serde_json::json!({"count": crashes.len(), "recent_crashes": crashes})).unwrap()
    }

    #[tool(description = "Get battery status — charge level, health, cycle count (laptops only)")]
    async fn get_battery_status(&self) -> String {
        let output = cmd("pmset", &["-g", "batt"]);
        let sysinfo = cmd("system_profiler", &["SPPowerDataType"]);
        let cycle = sysinfo.lines().find(|l| l.contains("Cycle Count")).map(|l| l.split(':').nth(1).unwrap_or("").trim()).unwrap_or("N/A");
        let condition = sysinfo.lines().find(|l| l.contains("Condition")).map(|l| l.split(':').nth(1).unwrap_or("").trim()).unwrap_or("N/A");
        serde_json::to_string_pretty(&serde_json::json!({"battery_info": output.trim(), "cycle_count": cycle, "condition": condition, "has_battery": output.contains("%")})).unwrap()
    }

    #[tool(description = "List connected USB and Thunderbolt devices")]
    async fn get_usb_devices(&self) -> String {
        let output = cmd("system_profiler", &["SPUSBDataType", "-detailLevel", "mini"]);
        let devices: Vec<&str> = output.lines().filter(|l| l.contains(":") && !l.trim().starts_with("USB") && l.trim().len() > 3 && !l.contains("Bus") && !l.contains("Host")).take(15).collect();
        serde_json::to_string_pretty(&serde_json::json!({"devices": devices, "count": devices.len()})).unwrap()
    }

    // ═══════════════════════════════════════════════════════════════
    // ACT — fix problems
    // ═══════════════════════════════════════════════════════════════

    #[tool(description = "Kill a process by PID or name")]
    async fn kill_process(&self, Parameters(i): Parameters<KillProcessInput>) -> String {
        if let Some(pid) = i.pid {
            let output = cmd("kill", &["-9", &pid.to_string()]);
            serde_json::to_string_pretty(&serde_json::json!({"killed": true, "pid": pid, "output": output})).unwrap()
        } else if let Some(name) = &i.name {
            let output = cmd("pkill", &["-f", name]);
            serde_json::to_string_pretty(&serde_json::json!({"killed": true, "name": name, "output": output})).unwrap()
        } else {
            serde_json::json!({"error": "Provide pid or name"}).to_string()
        }
    }

    #[tool(description = "Restart a launchd service by label")]
    async fn restart_service(&self, Parameters(i): Parameters<RestartServiceInput>) -> String {
        let stop = cmd("launchctl", &["stop", &i.service]);
        let start = cmd("launchctl", &["start", &i.service]);
        serde_json::to_string_pretty(&serde_json::json!({"service": i.service, "restarted": true, "stop": stop, "start": start})).unwrap()
    }

    #[tool(description = "Flush DNS cache — fixes stale DNS resolution")]
    async fn flush_dns(&self) -> String {
        let r1 = cmd("dscacheutil", &["-flushcache"]);
        let r2 = cmd("sudo", &["killall", "-HUP", "mDNSResponder"]);
        serde_json::to_string_pretty(&serde_json::json!({"flushed": true, "message": "DNS cache cleared. mDNSResponder restarted."})).unwrap()
    }

    #[tool(description = "Renew DHCP lease — get a fresh IP address")]
    async fn renew_dhcp(&self, Parameters(i): Parameters<RenewDhcpInput>) -> String {
        let iface = i.interface.as_deref().unwrap_or("en0");
        let output = cmd("ipconfig", &["set", iface, "DHCP"]);
        let new_ip = cmd("ipconfig", &["getifaddr", iface]);
        serde_json::to_string_pretty(&serde_json::json!({"interface": iface, "renewed": true, "new_ip": new_ip.trim()})).unwrap()
    }

    #[tool(description = "Empty the Trash to reclaim disk space")]
    async fn empty_trash(&self) -> String {
        let home = std::env::var("HOME").unwrap_or_default();
        let size_before = cmd("du", &["-sh", &format!("{}/.Trash", home)]);
        let _ = cmd("rm", &["-rf", &format!("{}/.Trash/*", home)]);
        serde_json::to_string_pretty(&serde_json::json!({"emptied": true, "space_freed": size_before.split_whitespace().next().unwrap_or("0")})).unwrap()
    }

    #[tool(description = "Purge system caches and derived data to free disk space")]
    async fn purge_caches(&self) -> String {
        let home = std::env::var("HOME").unwrap_or_default();
        let caches_before = cmd("du", &["-sh", &format!("{}/Library/Caches", home)]);
        let _ = cmd("rm", &["-rf", &format!("{}/Library/Caches/*", home)]);
        let derived = cmd("du", &["-sh", &format!("{}/Library/Developer/Xcode/DerivedData", home)]);
        serde_json::to_string_pretty(&serde_json::json!({"purged": true, "caches_size": caches_before.split_whitespace().next().unwrap_or("0"), "derived_data": derived.split_whitespace().next().unwrap_or("0")})).unwrap()
    }

    #[tool(description = "Enable the macOS firewall")]
    async fn enable_firewall(&self) -> String {
        let output = cmd("sudo", &["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"]);
        let status = cmd("defaults", &["read", "/Library/Preferences/com.apple.alf", "globalstate"]);
        serde_json::to_string_pretty(&serde_json::json!({"enabled": status.trim() != "0", "output": output.trim()})).unwrap()
    }

    #[tool(description = "Install a Homebrew package")]
    async fn brew_install(&self, Parameters(i): Parameters<BrewInstallInput>) -> String {
        let output = cmd("brew", &["install", &i.package]);
        let success = !output.contains("Error") && !output.contains("No formulae");
        serde_json::to_string_pretty(&serde_json::json!({"package": i.package, "installed": success, "output": output.lines().last().unwrap_or("")})).unwrap()
    }

    #[tool(description = "Upgrade Homebrew packages (all or specific)")]
    async fn brew_upgrade(&self, Parameters(i): Parameters<BrewUpgradeInput>) -> String {
        let output = if let Some(pkg) = &i.package {
            cmd("brew", &["upgrade", pkg])
        } else {
            cmd("brew", &["upgrade"])
        };
        serde_json::to_string_pretty(&serde_json::json!({"upgraded": true, "package": i.package.as_deref().unwrap_or("all"), "output": output.lines().take(5).collect::<Vec<_>>().join("\n")})).unwrap()
    }

    #[tool(description = "Uninstall a Homebrew package")]
    async fn brew_uninstall(&self, Parameters(i): Parameters<BrewUninstallInput>) -> String {
        let output = cmd("brew", &["uninstall", &i.package]);
        serde_json::to_string_pretty(&serde_json::json!({"package": i.package, "uninstalled": true, "output": output.lines().last().unwrap_or("")})).unwrap()
    }

    #[tool(description = "Lock the screen immediately")]
    async fn lock_screen(&self) -> String {
        let _ = cmd("pmset", &["displaysleepnow"]);
        serde_json::json!({"locked": true}).to_string()
    }

    #[tool(description = "Restart the machine (use force=true to skip confirmation)")]
    async fn restart_machine(&self, Parameters(i): Parameters<RestartMachineInput>) -> String {
        if i.force.unwrap_or(false) {
            let _ = cmd("sudo", &["shutdown", "-r", "now"]);
            serde_json::json!({"restarting": true}).to_string()
        } else {
            serde_json::json!({"restarting": false, "message": "Set force=true to confirm restart. This will close all applications."}).to_string()
        }
    }
}

fn cmd(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program).args(args).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}
