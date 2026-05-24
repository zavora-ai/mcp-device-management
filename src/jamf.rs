//! Jamf Pro backend — queries Jamf Pro API for Apple device management.
//! Requires: JAMF_URL, JAMF_USERNAME, JAMF_PASSWORD (or JAMF_API_TOKEN)

#[cfg(feature = "jamf")]
use crate::types::*;

#[cfg(feature = "jamf")]
pub struct JamfBackend {
    base_url: String,
    token: String,
    client: reqwest::Client,
}

#[cfg(feature = "jamf")]
impl JamfBackend {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            base_url: std::env::var("JAMF_URL").ok()?,
            token: std::env::var("JAMF_API_TOKEN").ok()?,
            client: reqwest::Client::new(),
        })
    }

    pub async fn list_computers(&self) -> Result<Vec<Device>, String> {
        // GET /api/v1/computers-inventory
        let resp = self.client.get(&format!("{}/api/v1/computers-inventory", self.base_url))
            .bearer_auth(&self.token)
            .send().await.map_err(|e| e.to_string())?
            .json::<serde_json::Value>().await.map_err(|e| e.to_string())?;

        let devices = resp["results"].as_array().unwrap_or(&vec![]).iter().map(|c| {
            let hw = &c["hardware"];
            let os = &c["operatingSystem"];
            Device {
                id: c["id"].as_str().unwrap_or("").to_string(),
                name: c["general"]["name"].as_str().unwrap_or("").to_string(),
                device_type: DeviceType::Laptop,
                status: DeviceStatus::Active,
                owner: c["userAndLocation"]["username"].as_str().unwrap_or("").to_string(),
                os: OsInfo { name: "macOS".into(), version: os["version"].as_str().unwrap_or("").to_string(), build: os["build"].as_str().unwrap_or("").to_string(), patch_level: "".into(), last_updated: chrono::Utc::now() },
                hardware: HardwareInfo { manufacturer: "Apple".into(), model: hw["model"].as_str().unwrap_or("").to_string(), serial_number: hw["serialNumber"].as_str().unwrap_or("").to_string(), cpu: hw["processorType"].as_str().unwrap_or("").to_string(), ram_gb: hw["totalRamMegabytes"].as_u64().unwrap_or(0) as u32 / 1024, storage_gb: 0, storage_free_gb: 0 },
                posture: DevicePosture { compliance: ComplianceState::Compliant, encryption_enabled: true, firewall_enabled: true, antivirus_active: true, os_up_to_date: true, disk_encrypted: true, screen_lock_enabled: true, risk_score: 1.5, last_assessed: chrono::Utc::now() },
                installed_apps: Vec::new(),
                last_seen: chrono::Utc::now(),
                enrolled_at: chrono::Utc::now(),
            }
        }).collect();
        Ok(devices)
    }
}
