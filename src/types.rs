use chrono::{DateTime, Utc};
use rmcp::schemars;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType { Laptop, Desktop, Mobile, Tablet, Server, Virtual }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus { Active, Inactive, Lost, Retired, PendingWipe }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceState { Compliant, NonCompliant, Unknown, GracePeriod }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState { Healthy, Degraded, Critical, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub status: DeviceStatus,
    pub owner: String,
    pub os: OsInfo,
    pub hardware: HardwareInfo,
    pub posture: DevicePosture,
    pub installed_apps: Vec<InstalledApp>,
    pub last_seen: DateTime<Utc>,
    pub enrolled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub build: String,
    pub patch_level: String,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub cpu: String,
    pub ram_gb: u32,
    pub storage_gb: u32,
    pub storage_free_gb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePosture {
    pub compliance: ComplianceState,
    pub encryption_enabled: bool,
    pub firewall_enabled: bool,
    pub antivirus_active: bool,
    pub os_up_to_date: bool,
    pub disk_encrypted: bool,
    pub screen_lock_enabled: bool,
    pub risk_score: f64,
    pub last_assessed: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationTask {
    pub id: String,
    pub device_id: String,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}
