//! Kandji backend — Apple device management platform.
//! Requires: KANDJI_URL, KANDJI_API_TOKEN

#[cfg(feature = "kandji")]
use crate::types::*;

#[cfg(feature = "kandji")]
pub struct KandjiBackend {
    base_url: String,
    token: String,
    client: reqwest::Client,
}

#[cfg(feature = "kandji")]
impl KandjiBackend {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            base_url: std::env::var("KANDJI_URL").ok()?,
            token: std::env::var("KANDJI_API_TOKEN").ok()?,
            client: reqwest::Client::new(),
        })
    }

    pub async fn list_devices(&self) -> Result<Vec<Device>, String> {
        // GET /api/v1/devices
        let resp = self.client.get(&format!("{}/api/v1/devices", self.base_url))
            .bearer_auth(&self.token)
            .send().await.map_err(|e| e.to_string())?
            .json::<serde_json::Value>().await.map_err(|e| e.to_string())?;

        let devices = resp.as_array().unwrap_or(&vec![]).iter().map(|d| {
            Device {
                id: d["device_id"].as_str().unwrap_or("").to_string(),
                name: d["device_name"].as_str().unwrap_or("").to_string(),
                device_type: DeviceType::Laptop,
                status: DeviceStatus::Active,
                owner: d["user"]["email"].as_str().unwrap_or("").to_string(),
                os: OsInfo { name: "macOS".into(), version: d["os_version"].as_str().unwrap_or("").to_string(), build: "".into(), patch_level: "".into(), last_updated: chrono::Utc::now() },
                hardware: HardwareInfo { manufacturer: "Apple".into(), model: d["model"].as_str().unwrap_or("").to_string(), serial_number: d["serial_number"].as_str().unwrap_or("").to_string(), cpu: "".into(), ram_gb: 0, storage_gb: 0, storage_free_gb: 0 },
                posture: DevicePosture { compliance: if d["blueprint_status"].as_str() == Some("success") { ComplianceState::Compliant } else { ComplianceState::NonCompliant }, encryption_enabled: d["filevault_enabled"].as_bool().unwrap_or(false), firewall_enabled: d["firewall_enabled"].as_bool().unwrap_or(false), antivirus_active: true, os_up_to_date: true, disk_encrypted: d["filevault_enabled"].as_bool().unwrap_or(false), screen_lock_enabled: true, risk_score: 2.0, last_assessed: chrono::Utc::now() },
                installed_apps: Vec::new(),
                last_seen: chrono::Utc::now(),
                enrolled_at: chrono::Utc::now(),
            }
        }).collect();
        Ok(devices)
    }
}
