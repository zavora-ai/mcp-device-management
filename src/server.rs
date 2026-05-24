use crate::platform;
use crate::store::DeviceStore;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CreateElicitationRequestParams, ElicitationAction, ElicitationSchema},
    schemars, tool, tool_router,
    service::Peer, RoleServer,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

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
        serde_json::to_string_pretty(&platform::system_stats()).unwrap()
    }

    #[tool(description = "List top running processes by CPU or memory usage")]
    async fn list_running_processes(&self, Parameters(i): Parameters<ListRunningProcessesInput>) -> String {
        serde_json::to_string_pretty(&platform::running_processes(i.limit.unwrap_or(10), i.sort_by.as_deref().unwrap_or("cpu"))).unwrap()
    }

    #[tool(description = "Get network info — IP addresses, WiFi SSID, VPN status, active connections")]
    async fn get_network_info(&self) -> String {
        serde_json::to_string_pretty(&platform::network_info()).unwrap()
    }

    #[tool(description = "Get full security status — FileVault/BitLocker, firewall, SIP/SELinux, Gatekeeper/Defender")]
    async fn get_security_status(&self) -> String {
        serde_json::to_string_pretty(&platform::security_status()).unwrap()
    }

    #[tool(description = "Check for available OS updates")]
    async fn check_os_updates(&self) -> String {
        let output = platform::cmd(if platform::os() == "windows" { "powershell" } else { "softwareupdate" }, if platform::os() == "windows" { &["-Command", "Get-WindowsUpdate"] } else { &["-l", "--no-scan"] });
        serde_json::to_string_pretty(&serde_json::json!({"os": platform::os(), "output": output.lines().take(10).collect::<Vec<_>>()})).unwrap()
    }

    #[tool(description = "List installed packages — Homebrew (macOS), apt (Linux), Chocolatey (Windows)")]
    async fn list_brew_packages(&self, Parameters(i): Parameters<ListBrewPackagesInput>) -> String {
        let action = if i.outdated_only.unwrap_or(false) { "outdated" } else { "list" };
        serde_json::to_string_pretty(&platform::brew_cmd(action, None)).unwrap()
    }

    #[tool(description = "Get disk usage breakdown by directory")]
    async fn get_disk_usage(&self, Parameters(i): Parameters<GetDiskUsageInput>) -> String {
        let path = i.path.as_deref().unwrap_or("~");
        let expanded = if path == "~" { std::env::var("HOME").unwrap_or_else(|_| "/".into()) } else { path.to_string() };
        let output = platform::cmd("du", &["-sh", &format!("{}/*/", expanded)]);
        let entries: Vec<serde_json::Value> = output.lines().take(20).map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            serde_json::json!({"size": parts.first(), "path": parts.get(1)})
        }).collect();
        serde_json::to_string_pretty(&serde_json::json!({"path": expanded, "entries": entries})).unwrap()
    }

    #[tool(description = "Find large files over a given size (default 100MB)")]
    async fn find_large_files(&self, Parameters(i): Parameters<FindLargeFilesInput>) -> String {
        let path = i.path.as_deref().unwrap_or(".");
        let min_mb = i.min_size_mb.unwrap_or(100);
        let output = if platform::os() == "windows" {
            platform::cmd("powershell", &["-Command", &format!("Get-ChildItem -Path '{}' -Recurse -File | Where-Object {{ $_.Length -gt {}MB }} | Select-Object FullName,Length -First 20", path, min_mb)])
        } else {
            platform::cmd("find", &[path, "-type", "f", "-size", &format!("+{}M", min_mb), "-exec", "ls", "-lh", "{}", ";"])
        };
        let files: Vec<&str> = output.lines().take(20).collect();
        serde_json::to_string_pretty(&serde_json::json!({"min_size_mb": min_mb, "count": files.len(), "files": files})).unwrap()
    }

    #[tool(description = "List login items and launch agents that run at startup")]
    async fn list_login_items(&self) -> String {
        let items: Vec<String> = match platform::os() {
            "macos" => {
                let home = std::env::var("HOME").unwrap_or_default();
                let user = platform::cmd("ls", &[&format!("{}/Library/LaunchAgents", home)]);
                let sys = platform::cmd("ls", &["/Library/LaunchAgents"]);
                user.lines().chain(sys.lines()).filter(|l| l.ends_with(".plist")).map(|s| s.to_string()).collect()
            }
            "linux" => platform::cmd("systemctl", &["list-unit-files", "--type=service", "--state=enabled"]).lines().take(20).map(|s| s.to_string()).collect(),
            "windows" => platform::cmd("wmic", &["startup", "get", "Name,Command"]).lines().skip(1).filter(|l| !l.trim().is_empty()).map(|s| s.trim().to_string()).collect(),
            _ => vec![],
        };
        serde_json::to_string_pretty(&serde_json::json!({"os": platform::os(), "count": items.len(), "items": items})).unwrap()
    }

    #[tool(description = "List open/listening network ports and their processes")]
    async fn get_open_ports(&self) -> String {
        serde_json::to_string_pretty(&platform::open_ports()).unwrap()
    }

    // ═══════════════════════════════════════════════════════════════
    // DIAGNOSE — troubleshoot problems
    // ═══════════════════════════════════════════════════════════════

    #[tool(description = "Ping a host — returns latency and packet loss")]
    async fn ping_host(&self, Parameters(i): Parameters<PingHostInput>) -> String {
        serde_json::to_string_pretty(&platform::ping(&i.host, i.count.unwrap_or(4))).unwrap()
    }

    #[tool(description = "Trace network path to a host")]
    async fn traceroute(&self, Parameters(i): Parameters<TracerouteInput>) -> String {
        serde_json::to_string_pretty(&platform::traceroute_host(&i.host)).unwrap()
    }

    #[tool(description = "DNS lookup — resolve a hostname to IP addresses")]
    async fn dns_lookup(&self, Parameters(i): Parameters<DnsLookupInput>) -> String {
        serde_json::to_string_pretty(&platform::dns_resolve(&i.hostname)).unwrap()
    }

    #[tool(description = "Test a URL — HTTP GET and return status code and response time")]
    async fn test_url(&self, Parameters(i): Parameters<TestUrlInput>) -> String {
        serde_json::to_string_pretty(&platform::test_url_cmd(&i.url)).unwrap()
    }

    #[tool(description = "Check disk health via SMART/diskutil")]
    async fn check_disk_health(&self) -> String {
        serde_json::to_string_pretty(&platform::disk_health()).unwrap()
    }

    #[tool(description = "Get recent application crash reports")]
    async fn get_recent_crashes(&self, Parameters(i): Parameters<GetRecentCrashesInput>) -> String {
        serde_json::to_string_pretty(&platform::recent_crashes(i.limit.unwrap_or(10))).unwrap()
    }

    #[tool(description = "Get battery status — charge level, health, cycle count")]
    async fn get_battery_status(&self) -> String {
        serde_json::to_string_pretty(&platform::battery_status()).unwrap()
    }

    #[tool(description = "List connected USB and Thunderbolt devices")]
    async fn get_usb_devices(&self) -> String {
        serde_json::to_string_pretty(&platform::usb_devices()).unwrap()
    }

    // ═══════════════════════════════════════════════════════════════
    // ACT — fix problems (cross-platform)
    // ═══════════════════════════════════════════════════════════════

    #[tool(description = "Kill a process by PID or name (requires user confirmation via elicitation)")]
    async fn kill_process(&self, Parameters(i): Parameters<KillProcessInput>, peer: Peer<RoleServer>) -> String {
        let target = i.name.clone().unwrap_or_else(|| i.pid.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()));
        let confirmed = elicit_confirmation(&peer, &format!("Kill process '{}'? This may cause data loss if the process has unsaved state.", target)).await;
        if !confirmed {
            return serde_json::json!({"killed": false, "message": "User declined or cancelled."}).to_string();
        }
        serde_json::to_string_pretty(&platform::kill(i.pid, i.name.as_deref())).unwrap()
    }

    #[tool(description = "Restart a launchd/systemd/Windows service")]
    async fn restart_service(&self, Parameters(i): Parameters<RestartServiceInput>) -> String {
        let output = match platform::os() {
            "macos" => { platform::cmd("launchctl", &["stop", &i.service]); platform::cmd("launchctl", &["start", &i.service]) }
            "linux" => platform::cmd("sudo", &["systemctl", "restart", &i.service]),
            "windows" => platform::cmd("powershell", &["-Command", &format!("Restart-Service '{}'", i.service)]),
            _ => return serde_json::json!({"error": "Unsupported OS"}).to_string(),
        };
        serde_json::to_string_pretty(&serde_json::json!({"service": i.service, "restarted": true, "os": platform::os()})).unwrap()
    }

    #[tool(description = "Flush DNS cache — fixes stale DNS resolution")]
    async fn flush_dns(&self) -> String {
        serde_json::to_string_pretty(&platform::flush_dns_cmd()).unwrap()
    }

    #[tool(description = "Renew DHCP lease — get a fresh IP address")]
    async fn renew_dhcp(&self, Parameters(i): Parameters<RenewDhcpInput>) -> String {
        serde_json::to_string_pretty(&platform::renew_dhcp_cmd(i.interface.as_deref().unwrap_or("en0"))).unwrap()
    }

    #[tool(description = "Empty the Trash/Recycle Bin to reclaim disk space")]
    async fn empty_trash(&self) -> String {
        serde_json::to_string_pretty(&platform::empty_trash_cmd()).unwrap()
    }

    #[tool(description = "Purge system caches to free disk space")]
    async fn purge_caches(&self) -> String {
        let home = std::env::var("HOME").unwrap_or_default();
        let output = match platform::os() {
            "macos" => { platform::cmd("rm", &["-rf", &format!("{}/Library/Caches/*", home)]); "Caches purged" }
            "linux" => { platform::cmd("sudo", &["apt-get", "clean"]); "apt cache cleaned" }
            "windows" => { platform::cmd("powershell", &["-Command", "Remove-Item -Path $env:TEMP\\* -Recurse -Force"]); "Temp files purged" }
            _ => "Unsupported",
        };
        serde_json::to_string_pretty(&serde_json::json!({"purged": true, "os": platform::os(), "message": output})).unwrap()
    }

    #[tool(description = "Enable the system firewall (requires user confirmation via elicitation)")]
    async fn enable_firewall(&self, peer: Peer<RoleServer>) -> String {
        let confirmed = elicit_confirmation(&peer, "Enable the system firewall? This requires admin privileges and may block some network connections.").await;
        if !confirmed {
            return serde_json::json!({"enabled": false, "message": "User declined or cancelled."}).to_string();
        }
        serde_json::to_string_pretty(&platform::enable_firewall_cmd()).unwrap()
    }

    #[tool(description = "Install a package (brew/apt/choco)")]
    async fn brew_install(&self, Parameters(i): Parameters<BrewInstallInput>) -> String {
        serde_json::to_string_pretty(&platform::brew_cmd("install", Some(&i.package))).unwrap()
    }

    #[tool(description = "Upgrade packages (brew/apt/choco) — all or specific")]
    async fn brew_upgrade(&self, Parameters(i): Parameters<BrewUpgradeInput>) -> String {
        serde_json::to_string_pretty(&platform::brew_cmd("upgrade", i.package.as_deref())).unwrap()
    }

    #[tool(description = "Uninstall a package (brew/apt/choco)")]
    async fn brew_uninstall(&self, Parameters(i): Parameters<BrewUninstallInput>) -> String {
        serde_json::to_string_pretty(&platform::brew_cmd("uninstall", Some(&i.package))).unwrap()
    }

    #[tool(description = "Lock the screen immediately")]
    async fn lock_screen(&self) -> String {
        serde_json::to_string_pretty(&platform::lock_screen_cmd()).unwrap()
    }

    #[tool(description = "Restart the machine (requires user confirmation via elicitation)")]
    async fn restart_machine(&self, Parameters(i): Parameters<RestartMachineInput>, peer: Peer<RoleServer>) -> String {
        if !i.force.unwrap_or(false) {
            let confirmed = elicit_confirmation(&peer, "Restart this machine? All unsaved work will be lost and running applications will close.").await;
            if !confirmed {
                return serde_json::json!({"restarting": false, "message": "User declined or cancelled."}).to_string();
            }
        }
        serde_json::to_string_pretty(&platform::restart_cmd(true)).unwrap()
    }
}

/// Request user confirmation via MCP elicitation protocol.
/// Falls back to auto-approve if client doesn't support elicitation.
async fn elicit_confirmation(peer: &Peer<RoleServer>, message: &str) -> bool {
    let schema = match ElicitationSchema::builder()
        .required_bool("confirm")
        .build() {
        Ok(s) => s,
        Err(_) => return true,
    };

    let result = peer.create_elicitation_with_timeout(
        CreateElicitationRequestParams::FormElicitationParams {
            meta: None,
            message: message.to_string(),
            requested_schema: schema,
        },
        Some(Duration::from_secs(120)),
    ).await;

    match result {
        Ok(r) => r.action == ElicitationAction::Accept,
        Err(_) => true, // Client doesn't support elicitation — proceed
    }
}
