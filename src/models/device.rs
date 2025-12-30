use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Uuid,
    Machine,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Uuid => "uuid",
            DeviceType::Machine => "machine",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "uuid" => Some(DeviceType::Uuid),
            "machine" => Some(DeviceType::Machine),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub license_key_id: String,
    pub device_id: String,
    pub device_type: DeviceType,
    pub name: Option<String>,
    pub jti: String,
    pub activated_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct DeactivateDevice {
    pub project_id: String,
    pub key: String,
    pub device_id: String,
}
