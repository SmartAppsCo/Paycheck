use serde::{Deserialize, Serialize};

/// API key for org members (supports multiple keys per member)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMemberApiKey {
    pub id: String,
    pub org_member_id: String,
    pub name: String,
    pub prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

/// API key for operators (supports multiple keys per operator)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorApiKey {
    pub id: String,
    pub operator_id: String,
    pub name: String,
    pub prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    /// Optional expiration in days from now
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

/// Response when creating an API key (includes full key, shown only once)
#[derive(Debug, Serialize)]
pub struct ApiKeyCreated {
    pub id: String,
    pub name: String,
    /// Full API key - shown only on creation
    pub key: String,
    pub prefix: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Response when listing API keys (no full key)
#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl From<OrgMemberApiKey> for ApiKeyInfo {
    fn from(key: OrgMemberApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            prefix: key.prefix,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            expires_at: key.expires_at,
        }
    }
}

impl From<OperatorApiKey> for ApiKeyInfo {
    fn from(key: OperatorApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            prefix: key.prefix,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            expires_at: key.expires_at,
        }
    }
}
