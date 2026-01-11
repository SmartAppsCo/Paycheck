use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum OperatorRole {
    Owner,
    Admin,
    View,
}

impl OperatorRole {
    /// Returns true if this role can manage other operators (create, update, delete)
    pub fn can_manage_operators(&self) -> bool {
        matches!(self, OperatorRole::Owner)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operator {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: OperatorRole,
    pub created_at: i64,
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
