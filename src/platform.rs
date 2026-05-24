//! Cross-platform command dispatch — macOS, Linux, Windows

use serde_json::{json, Value};

pub fn os() -> &'static str { std::env::consts::OS }

pub fn cmd(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program).args(args).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

pub fn cmd_stderr(program: &str, args: &[&str]) -> (String, String) {
    std::process::Command::new(program).args(args).output()
        .map(|o| (String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string()))
        .unwrap_or_default()
}

// ═══════════════════════════════════════════════════════════════
// OBSERVE
// ═══════════════════════════════════════════════════════════════

pub fn system_stats() -> Value {
    match os() {
        "macos" => {
            let load = cmd("sysctl", &["-n", "vm.loadavg"]);
            let mem: u64 = cmd("sysctl", &["-n", "hw.memsize"]).trim().parse().unwrap_or(0);
            let df = cmd("df", &["-h", "/"]);
            let dp: Vec<&str> = df.lines().nth(1).unwrap_or("").split_whitespace().collect();
            json!({"os": "macos", "load": load.trim(), "memory_total_gb": mem/1_073_741_824, "disk": {"total": dp.get(1), "used": dp.get(2), "free": dp.get(3), "used_pct": dp.get(4)}})
        }
        "linux" => {
            let load = cmd("cat", &["/proc/loadavg"]);
            let mem = cmd("free", &["-h"]);
            let mem_line = mem.lines().nth(1).unwrap_or("");
            let df = cmd("df", &["-h", "/"]);
            let dp: Vec<&str> = df.lines().nth(1).unwrap_or("").split_whitespace().collect();
            json!({"os": "linux", "load": load.trim(), "memory": mem_line.trim(), "disk": {"total": dp.get(1), "used": dp.get(2), "free": dp.get(3), "used_pct": dp.get(4)}})
        }
        "windows" => {
            let cpu = cmd("wmic", &["cpu", "get", "loadpercentage", "/value"]);
            let mem = cmd("wmic", &["os", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/value"]);
            let disk = cmd("wmic", &["logicaldisk", "where", "DeviceID='C:'", "get", "Size,FreeSpace", "/value"]);
            json!({"os": "windows", "cpu": cpu.trim(), "memory": mem.trim(), "disk": disk.trim()})
        }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn running_processes(limit: usize, sort_by: &str) -> Value {
    let output = match os() {
        "macos" => if sort_by == "mem" { cmd("ps", &["aux", "-m"]) } else { cmd("ps", &["aux", "-r"]) },
        "linux" => if sort_by == "mem" { cmd("ps", &["aux", "--sort=-%mem"]) } else { cmd("ps", &["aux", "--sort=-%cpu"]) },
        "windows" => cmd("tasklist", &["/FO", "CSV", "/NH"]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let procs: Vec<Value> = output.lines().skip(1).take(limit).map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        if os() == "windows" {
            json!({"name": p.first(), "pid": p.get(1), "mem": p.get(4)})
        } else {
            json!({"user": p.get(0), "pid": p.get(1), "cpu": p.get(2), "mem": p.get(3), "command": p.get(10..).map(|x| x.join(" "))})
        }
    }).collect();
    json!({"os": os(), "sort_by": sort_by, "count": procs.len(), "processes": procs})
}

pub fn network_info() -> Value {
    match os() {
        "macos" => {
            let ifc = cmd("ifconfig", &[]);
            let ip = ifc.lines().find(|l| l.contains("inet ") && !l.contains("127.0.0.1")).and_then(|l| l.split_whitespace().nth(1)).unwrap_or("unknown");
            let wifi = cmd("networksetup", &["-getairportnetwork", "en0"]);
            let ssid = wifi.split(':').nth(1).map(|s| s.trim()).unwrap_or("N/A");
            let vpn = cmd("scutil", &["--nc", "list"]);
            let conns = cmd("netstat", &["-an"]).lines().filter(|l| l.contains("ESTABLISHED")).count();
            json!({"os": "macos", "ip": ip, "wifi": ssid, "vpn": vpn.lines().any(|l| l.contains("Connected")), "connections": conns})
        }
        "linux" => {
            let ip = cmd("hostname", &["-I"]);
            let wifi = cmd("iwgetid", &["-r"]);
            let conns = cmd("ss", &["-tun"]).lines().filter(|l| l.contains("ESTAB")).count();
            json!({"os": "linux", "ip": ip.trim(), "wifi": wifi.trim(), "vpn": false, "connections": conns})
        }
        "windows" => {
            let ipc = cmd("ipconfig", &[]);
            let ip = ipc.lines().find(|l| l.contains("IPv4")).and_then(|l| l.split(':').nth(1)).unwrap_or("unknown").trim();
            let wifi = cmd("netsh", &["wlan", "show", "interfaces"]);
            let ssid = wifi.lines().find(|l| l.contains("SSID") && !l.contains("BSSID")).and_then(|l| l.split(':').nth(1)).unwrap_or("N/A").trim();
            json!({"os": "windows", "ip": ip, "wifi": ssid, "vpn": false, "connections": 0})
        }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn security_status() -> Value {
    match os() {
        "macos" => {
            let fv = cmd("fdesetup", &["status"]);
            let fw = cmd("defaults", &["read", "/Library/Preferences/com.apple.alf", "globalstate"]);
            let sip = cmd("csrutil", &["status"]);
            let gk = cmd("spctl", &["--status"]);
            json!({"os": "macos", "filevault": fv.contains("On"), "firewall": fw.trim() != "0" && !fw.is_empty(), "sip": sip.contains("enabled"), "gatekeeper": gk.contains("enabled")})
        }
        "linux" => {
            let ufw = cmd("ufw", &["status"]);
            let selinux = cmd("getenforce", &[]);
            let luks = cmd("lsblk", &["-o", "NAME,FSTYPE"]).contains("crypto_LUKS");
            json!({"os": "linux", "firewall": ufw.contains("active"), "selinux": selinux.trim(), "disk_encrypted": luks})
        }
        "windows" => {
            let fw = cmd("netsh", &["advfirewall", "show", "allprofiles", "state"]);
            let bl = cmd("manage-bde", &["-status", "C:"]);
            let defender = cmd("powershell", &["-Command", "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled"]);
            json!({"os": "windows", "firewall": fw.contains("ON"), "bitlocker": bl.contains("Fully Encrypted"), "defender": defender.contains("True")})
        }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn open_ports() -> Value {
    let output = match os() {
        "macos" => cmd("lsof", &["-iTCP", "-sTCP:LISTEN", "-nP"]),
        "linux" => cmd("ss", &["-tlnp"]),
        "windows" => cmd("netstat", &["-an", "-p", "TCP"]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let ports: Vec<Value> = output.lines().skip(1).take(20).filter(|l| l.contains("LISTEN") || os() == "linux").map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        json!({"line": l.trim()})
    }).collect();
    json!({"os": os(), "count": ports.len(), "listening": ports})
}

pub fn installed_apps() -> Value {
    let apps: Vec<String> = match os() {
        "macos" => cmd("ls", &["/Applications"]).lines().filter(|l| l.ends_with(".app")).map(|l| l.trim_end_matches(".app").to_string()).collect(),
        "linux" => cmd("dpkg", &["--get-selections"]).lines().take(30).filter_map(|l| l.split_whitespace().next().map(|s| s.to_string())).collect(),
        "windows" => cmd("wmic", &["product", "get", "name"]).lines().skip(1).take(30).map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        _ => vec![],
    };
    json!({"os": os(), "count": apps.len(), "apps": apps})
}

// ═══════════════════════════════════════════════════════════════
// DIAGNOSE
// ═══════════════════════════════════════════════════════════════

pub fn ping(host: &str, count: u32) -> Value {
    let c = count.to_string();
    let output = match os() {
        "macos" | "linux" => cmd("ping", &["-c", &c, host]),
        "windows" => cmd("ping", &["-n", &c, host]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let stats = output.lines().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
    json!({"host": host, "reachable": output.contains("bytes from") || output.contains("Reply from"), "stats": stats})
}

pub fn traceroute_host(host: &str) -> Value {
    let output = match os() {
        "macos" | "linux" => cmd("traceroute", &["-m", "15", "-w", "2", host]),
        "windows" => cmd("tracert", &["-h", "15", "-w", "2000", host]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let hops: Vec<&str> = output.lines().skip(1).take(15).collect();
    json!({"host": host, "hops": hops.len(), "trace": hops})
}

pub fn dns_resolve(hostname: &str) -> Value {
    let output = match os() {
        "macos" | "linux" => cmd("nslookup", &[hostname]),
        "windows" => cmd("nslookup", &[hostname]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let addrs: Vec<&str> = output.lines().filter(|l| l.contains("Address") && !l.contains("#")).collect();
    json!({"hostname": hostname, "resolved": !addrs.is_empty(), "addresses": addrs})
}

pub fn test_url_cmd(url: &str) -> Value {
    let output = match os() {
        "macos" | "linux" => cmd("curl", &["-o", "/dev/null", "-s", "-w", "%{http_code} %{time_total}", "-m", "10", url]),
        "windows" => cmd("powershell", &["-Command", &format!("try {{ $r = Invoke-WebRequest -Uri '{}' -TimeoutSec 10 -UseBasicParsing; \"$($r.StatusCode) 0\" }} catch {{ \"0 0\" }}", url)]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let parts: Vec<&str> = output.split_whitespace().collect();
    json!({"url": url, "status": parts.first().unwrap_or(&"0"), "time_sec": parts.get(1).unwrap_or(&"?"), "reachable": parts.first().map(|s| *s != "000" && *s != "0").unwrap_or(false)})
}

pub fn disk_health() -> Value {
    match os() {
        "macos" => { let o = cmd("diskutil", &["info", "/"]); let s = o.lines().find(|l| l.contains("SMART")).unwrap_or("Unknown"); json!({"os": "macos", "smart": s.trim(), "healthy": s.contains("Verified")}) }
        "linux" => { let o = cmd("smartctl", &["-H", "/dev/sda"]); json!({"os": "linux", "output": o.lines().find(|l| l.contains("result")).unwrap_or("unknown").trim()}) }
        "windows" => { let o = cmd("wmic", &["diskdrive", "get", "status"]); json!({"os": "windows", "status": o.trim()}) }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn battery_status() -> Value {
    match os() {
        "macos" => { let o = cmd("pmset", &["-g", "batt"]); let sp = cmd("system_profiler", &["SPPowerDataType"]); let cycle = sp.lines().find(|l| l.contains("Cycle Count")).and_then(|l| l.split(':').nth(1)).unwrap_or("N/A").trim(); json!({"os": "macos", "info": o.trim(), "cycle_count": cycle}) }
        "linux" => { let cap = cmd("cat", &["/sys/class/power_supply/BAT0/capacity"]); let st = cmd("cat", &["/sys/class/power_supply/BAT0/status"]); json!({"os": "linux", "capacity": cap.trim(), "status": st.trim()}) }
        "windows" => { let o = cmd("powershell", &["-Command", "Get-WmiObject Win32_Battery | Select-Object EstimatedChargeRemaining,BatteryStatus"]); json!({"os": "windows", "info": o.trim()}) }
        _ => json!({"os": os(), "has_battery": false}),
    }
}

pub fn usb_devices() -> Value {
    let output = match os() {
        "macos" => cmd("system_profiler", &["SPUSBDataType", "-detailLevel", "mini"]),
        "linux" => cmd("lsusb", &[]),
        "windows" => cmd("wmic", &["path", "Win32_USBHub", "get", "DeviceID,Name"]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let devices: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty() && l.trim().len() > 5).take(15).collect();
    json!({"os": os(), "count": devices.len(), "devices": devices})
}

pub fn recent_crashes(limit: usize) -> Value {
    let output = match os() {
        "macos" => { let home = std::env::var("HOME").unwrap_or_default(); cmd("ls", &["-lt", &format!("{}/Library/Logs/DiagnosticReports", home)]) }
        "linux" => cmd("journalctl", &["--no-pager", "-p", "err", "-n", &limit.to_string()]),
        "windows" => cmd("powershell", &["-Command", &format!("Get-EventLog -LogName Application -EntryType Error -Newest {}", limit)]),
        _ => return json!({"error": "Unsupported OS"}),
    };
    let entries: Vec<&str> = output.lines().skip(1).take(limit).collect();
    json!({"os": os(), "count": entries.len(), "crashes": entries})
}

// ═══════════════════════════════════════════════════════════════
// ACT
// ═══════════════════════════════════════════════════════════════

pub fn kill(pid: Option<u32>, name: Option<&str>) -> Value {
    if let Some(p) = pid {
        let ps = p.to_string();
        match os() {
            "macos" | "linux" => { cmd("kill", &["-9", &ps]); }
            "windows" => { cmd("taskkill", &["/PID", &ps, "/F"]); }
            _ => return json!({"error": "Unsupported OS"}),
        }
        json!({"killed_pid": p})
    } else if let Some(n) = name {
        match os() {
            "macos" | "linux" => { cmd("pkill", &["-f", n]); }
            "windows" => { cmd("taskkill", &["/IM", n, "/F"]); }
            _ => return json!({"error": "Unsupported OS"}),
        }
        json!({"killed_name": n})
    } else { json!({"error": "Provide pid or name"}) }
}

pub fn flush_dns_cmd() -> Value {
    match os() {
        "macos" => { cmd("dscacheutil", &["-flushcache"]); json!({"flushed": true, "os": "macos"}) }
        "linux" => { cmd("systemd-resolve", &["--flush-caches"]); json!({"flushed": true, "os": "linux"}) }
        "windows" => { cmd("ipconfig", &["/flushdns"]); json!({"flushed": true, "os": "windows"}) }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn renew_dhcp_cmd(interface: &str) -> Value {
    match os() {
        "macos" => { cmd("ipconfig", &["set", interface, "DHCP"]); let ip = cmd("ipconfig", &["getifaddr", interface]); json!({"renewed": true, "interface": interface, "ip": ip.trim()}) }
        "linux" => { cmd("dhclient", &["-r", interface]); cmd("dhclient", &[interface]); json!({"renewed": true, "interface": interface}) }
        "windows" => { cmd("ipconfig", &["/release"]); cmd("ipconfig", &["/renew"]); json!({"renewed": true}) }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn empty_trash_cmd() -> Value {
    match os() {
        "macos" => { let home = std::env::var("HOME").unwrap_or_default(); let sz = cmd("du", &["-sh", &format!("{}/.Trash", home)]); cmd("rm", &["-rf", &format!("{}/.Trash/*", home)]); json!({"emptied": true, "freed": sz.split_whitespace().next()}) }
        "linux" => { let home = std::env::var("HOME").unwrap_or_default(); cmd("rm", &["-rf", &format!("{}/.local/share/Trash/files/*", home)]); json!({"emptied": true}) }
        "windows" => { cmd("powershell", &["-Command", "Clear-RecycleBin -Force"]); json!({"emptied": true}) }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn enable_firewall_cmd() -> Value {
    match os() {
        "macos" => { cmd("sudo", &["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"]); json!({"enabled": true, "os": "macos"}) }
        "linux" => { cmd("sudo", &["ufw", "enable"]); json!({"enabled": true, "os": "linux"}) }
        "windows" => { cmd("netsh", &["advfirewall", "set", "allprofiles", "state", "on"]); json!({"enabled": true, "os": "windows"}) }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn brew_cmd(action: &str, package: Option<&str>) -> Value {
    if os() == "windows" {
        // Use chocolatey on Windows
        let pkg = package.unwrap_or("");
        let output = match action {
            "install" => cmd("choco", &["install", pkg, "-y"]),
            "upgrade" => if pkg.is_empty() { cmd("choco", &["upgrade", "all", "-y"]) } else { cmd("choco", &["upgrade", pkg, "-y"]) },
            "uninstall" => cmd("choco", &["uninstall", pkg, "-y"]),
            "list" => cmd("choco", &["list", "--local-only"]),
            "outdated" => cmd("choco", &["outdated"]),
            _ => return json!({"error": "Unknown action"}),
        };
        return json!({"os": "windows", "manager": "chocolatey", "action": action, "output": output.lines().take(10).collect::<Vec<_>>().join("\n")});
    }
    // macOS/Linux: brew or apt
    let mgr = if os() == "linux" && cmd("which", &["brew"]).is_empty() { "apt" } else { "brew" };
    let pkg = package.unwrap_or("");
    let output = match (mgr, action) {
        ("brew", "install") => cmd("brew", &["install", pkg]),
        ("brew", "upgrade") => if pkg.is_empty() { cmd("brew", &["upgrade"]) } else { cmd("brew", &["upgrade", pkg]) },
        ("brew", "uninstall") => cmd("brew", &["uninstall", pkg]),
        ("brew", "list") => cmd("brew", &["list", "--formula", "-1"]),
        ("brew", "outdated") => cmd("brew", &["outdated"]),
        ("apt", "install") => cmd("sudo", &["apt-get", "install", "-y", pkg]),
        ("apt", "upgrade") => cmd("sudo", &["apt-get", "upgrade", "-y"]),
        ("apt", "uninstall") => cmd("sudo", &["apt-get", "remove", "-y", pkg]),
        ("apt", "list") => cmd("dpkg", &["--get-selections"]),
        ("apt", "outdated") => cmd("apt", &["list", "--upgradable"]),
        _ => return json!({"error": "Unknown action"}),
    };
    json!({"os": os(), "manager": mgr, "action": action, "package": package, "output": output.lines().take(10).collect::<Vec<_>>().join("\n")})
}

pub fn lock_screen_cmd() -> Value {
    match os() {
        "macos" => { cmd("pmset", &["displaysleepnow"]); json!({"locked": true}) }
        "linux" => { cmd("loginctl", &["lock-session"]); json!({"locked": true}) }
        "windows" => { cmd("rundll32.exe", &["user32.dll,LockWorkStation"]); json!({"locked": true}) }
        _ => json!({"error": "Unsupported OS"}),
    }
}

pub fn restart_cmd(force: bool) -> Value {
    if !force { return json!({"restarting": false, "message": "Set force=true to confirm. This will close all applications."}); }
    match os() {
        "macos" => { cmd("sudo", &["shutdown", "-r", "now"]); }
        "linux" => { cmd("sudo", &["reboot"]); }
        "windows" => { cmd("shutdown", &["/r", "/t", "0"]); }
        _ => return json!({"error": "Unsupported OS"}),
    }
    json!({"restarting": true, "os": os()})
}
