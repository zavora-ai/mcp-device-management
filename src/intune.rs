//! Microsoft Intune backend — queries Microsoft Graph API for managed devices.
//! Requires: INTUNE_TENANT_ID, INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET

#[cfg(feature = "intune")]
use crate::types::*;

#[cfg(feature = "intune")]
pub struct IntuneBackend {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    client: reqwest::Client,
}

#[cfg(feature = "intune")]
impl IntuneBackend {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            tenant_id: std::env::var("INTUNE_TENANT_ID").ok()?,
            client_id: std::env::var("INTUNE_CLIENT_ID").ok()?,
            client_secret: std::env::var("INTUNE_CLIENT_SECRET").ok()?,
            client: reqwest::Client::new(),
        })
    }

    pub async fn list_devices(&self) -> Result<Vec<Device>, String> {
        // POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        // GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices
        let token = self.get_token().await?;
        let resp = self.client.get("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices")
            .bearer_auth(&token)
            .send().await.map_err(|e| e.to_string())?
            .json::<serde_json::Value>().await.map_err(|e| e.to_string())?;

        let devices = resp["value"].as_array().unwrap_or(&vec![]).iter().map(|d| {
            Device {
                id: d["id"].as_str().unwrap_or("").to_string(),
                name: d["deviceName"].as_str().unwrap_or("").to_string(),
                device_type: match d["deviceType"].as_str().unwrap_or("") { "macMDM" => DeviceType::Laptop, "windowsRT" => DeviceType::Laptop, _ => DeviceType::Desktop },
                status: if d["complianceState"].as_str() == Some("compliant") { DeviceStatus::Active } else { DeviceStatus::Active },
                owner: d["userPrincipalName"].as_str().unwrap_or("").to_string(),
                os: OsInfo { name: d["operatingSystem"].as_str().unwrap_or("").to_string(), version: d["osVersion"].as_str().unwrap_or("").to_string(), build: "".into(), patch_level: "".into(), last_updated: chrono::Utc::now() },
                hardware: HardwareInfo { manufacturer: d["manufacturer"].as_str().unwrap_or("").to_string(), model: d["model"].as_str().unwrap_or("").to_string(), serial_number: d["serialNumber"].as_str().unwrap_or("").to_string(), cpu: "".into(), ram_gb: 0, storage_gb: (d["totalStorageSpaceInBytes"].as_u64().unwrap_or(0) / 1_073_741_824) as u32, storage_free_gb: (d["freeStorageSpaceInBytes"].as_u64().unwrap_or(0) / 1_073_741_824) as u32 },
                posture: DevicePosture { compliance: if d["complianceState"].as_str() == Some("compliant") { ComplianceState::Compliant } else { ComplianceState::NonCompliant }, encryption_enabled: d["isEncrypted"].as_bool().unwrap_or(false), firewall_enabled: true, antivirus_active: true, os_up_to_date: true, disk_encrypted: d["isEncrypted"].as_bool().unwrap_or(false), screen_lock_enabled: true, risk_score: 2.0, last_assessed: chrono::Utc::now() },
                installed_apps: Vec::new(),
                last_seen: chrono::Utc::now(),
                enrolled_at: chrono::Utc::now(),
            }
        }).collect();
        Ok(devices)
    }

    async fn get_token(&self) -> Result<String, String> {
        let resp = self.client.post(&format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", self.tenant_id))
            .form(&[("grant_type", "client_credentials"), ("client_id", &self.client_id), ("client_secret", &self.client_secret), ("scope", "https://graph.microsoft.com/.default")])
            .send().await.map_err(|e| e.to_string())?
            .json::<serde_json::Value>().await.map_err(|e| e.to_string())?;
        resp["access_token"].as_str().map(|s| s.to_string()).ok_or("Failed to get token".into())
    }
}
