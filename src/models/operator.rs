use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatorRole {
    Owner,
    Admin,
    View,
}

impl OperatorRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatorRole::Owner => "owner",
            OperatorRole::Admin => "admin",
            OperatorRole::View => "view",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(OperatorRole::Owner),
            "admin" => Some(OperatorRole::Admin),
            "view" => Some(OperatorRole::View),
            _ => None,
        }
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    pub created_at: i64,
    pub created_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOperator {
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOperator {
    pub name: Option<String>,
    pub role: Option<OperatorRole>,
}
