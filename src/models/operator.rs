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

/// Request to grant operator role to a user
#[derive(Debug, Deserialize)]
pub struct CreateOperator {
    pub user_id: String,
    pub role: OperatorRole,
}

/// Request to update a user's operator role
#[derive(Debug, Deserialize)]
pub struct UpdateOperator {
    pub role: Option<OperatorRole>,
}
