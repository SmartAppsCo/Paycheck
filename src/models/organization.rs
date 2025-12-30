use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub name: String,
    #[serde(default)]
    pub owner_email: Option<String>,
    #[serde(default)]
    pub owner_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
}
