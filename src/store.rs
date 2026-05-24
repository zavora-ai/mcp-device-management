use crate::types::*;
use crate::local::LocalBackend;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

pub struct DeviceStore {
    devices: Mutex<HashMap<String, Device>>,
    tasks: Mutex<Vec<RemediationTask>>,
}

impl DeviceStore {
    pub fn new() -> Self { Self { devices: Mutex::new(HashMap::new()), tasks: Mutex::new(Vec::new()) } }

    /// Auto-detect local device and add to inventory
    pub fn detect_local(&self) {
        let backend = LocalBackend::new();
        let device = backend.get_device();
        self.add_device(device);
    }

    pub fn add_device(&self, device: Device) { self.devices.lock().unwrap().insert(device.id.clone(), device); }

    pub fn lookup_device(&self, query: &str) -> Vec<Device> {
        let q = query.to_lowercase();
        self.devices.lock().unwrap().values()
            .filter(|d| d.id.to_lowercase().contains(&q) || d.name.to_lowercase().contains(&q) || d.hardware.serial_number.to_lowercase().contains(&q) || d.hardware.model.to_lowercase().contains(&q))
            .cloned().collect()
    }

    pub fn list_user_devices(&self, owner: &str) -> Vec<Device> {
        self.devices.lock().unwrap().values().filter(|d| d.owner == owner).cloned().collect()
    }

    pub fn get_posture(&self, device_id: &str) -> Option<(DevicePosture, String)> {
        self.devices.lock().unwrap().get(device_id).map(|d| (d.posture.clone(), d.name.clone()))
    }

    pub fn get_installed_apps(&self, device_id: &str) -> Option<Vec<InstalledApp>> {
        self.devices.lock().unwrap().get(device_id).map(|d| d.installed_apps.clone())
    }

    pub fn collect_logs(&self, device_id: &str) -> Option<serde_json::Value> {
        let devices = self.devices.lock().unwrap();
        let d = devices.get(device_id)?;
        let disk_pct = if d.hardware.storage_gb > 0 { ((d.hardware.storage_gb - d.hardware.storage_free_gb) * 100 / d.hardware.storage_gb) } else { 0 };
        Some(serde_json::json!({
            "device_id": d.id, "device_name": d.name, "collected_at": Utc::now(),
            "os": format!("{} {} ({})", d.os.name, d.os.version, d.os.build),
            "hardware": format!("{} {} — {} — {} GB RAM", d.hardware.manufacturer, d.hardware.model, d.hardware.cpu, d.hardware.ram_gb),
            "storage": {"total_gb": d.hardware.storage_gb, "free_gb": d.hardware.storage_free_gb, "used_pct": format!("{}%", disk_pct)},
            "posture_summary": {"compliance": d.posture.compliance, "encryption": d.posture.encryption_enabled, "firewall": d.posture.firewall_enabled, "risk_score": d.posture.risk_score},
        }))
    }

    pub fn run_health_check(&self, device_id: &str) -> Option<serde_json::Value> {
        let devices = self.devices.lock().unwrap();
        let d = devices.get(device_id)?;
        let health = if d.posture.compliance == ComplianceState::Compliant && d.posture.risk_score < 3.0 {
            HealthState::Healthy
        } else if d.posture.risk_score < 6.0 { HealthState::Degraded } else { HealthState::Critical };
        Some(serde_json::json!({
            "device_id": d.id, "device_name": d.name, "health": health,
            "checks": {"os_updated": d.posture.os_up_to_date, "encryption": d.posture.encryption_enabled, "firewall": d.posture.firewall_enabled, "antivirus": d.posture.antivirus_active, "disk_encrypted": d.posture.disk_encrypted, "screen_lock": d.posture.screen_lock_enabled},
            "risk_score": d.posture.risk_score, "compliance": d.posture.compliance, "checked_at": Utc::now(),
        }))
    }

    pub fn create_remediation(&self, device_id: &str, action: &str, reason: &str) -> Result<RemediationTask, String> {
        if !self.devices.lock().unwrap().contains_key(device_id) { return Err(format!("Device not found: {}", device_id)); }
        let task = RemediationTask {
            id: format!("REM-{}", Uuid::new_v4().simple().to_string()[..8].to_uppercase()),
            device_id: device_id.to_string(), action: action.to_string(), reason: reason.to_string(),
            status: "pending".to_string(), created_at: Utc::now(),
        };
        self.tasks.lock().unwrap().push(task.clone());
        Ok(task)
    }

}
