use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum ProjectMemberRole {
    Admin,
    View,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMember {
    pub id: String,
    pub org_member_id: String,
    pub project_id: String,
    pub role: ProjectMemberRole,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectMemberWithDetails {
    /// Internal ID - not exposed in API responses (use user_id instead)
    #[serde(skip_serializing)]
    pub id: String,
    /// Internal ID - not exposed in API responses (use user_id instead)
    #[serde(skip_serializing)]
    pub org_member_id: String,
    pub user_id: String,
    pub project_id: String,
    pub role: ProjectMemberRole,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
    pub email: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectMember {
    pub user_id: String,
    pub role: ProjectMemberRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectMember {
    pub role: ProjectMemberRole,
}
