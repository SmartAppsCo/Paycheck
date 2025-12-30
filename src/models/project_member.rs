use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectMemberRole {
    Admin,
    View,
}

impl ProjectMemberRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProjectMemberRole::Admin => "admin",
            ProjectMemberRole::View => "view",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(ProjectMemberRole::Admin),
            "view" => Some(ProjectMemberRole::View),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMember {
    pub id: String,
    pub org_member_id: String,
    pub project_id: String,
    pub role: ProjectMemberRole,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectMemberWithDetails {
    pub id: String,
    pub org_member_id: String,
    pub project_id: String,
    pub role: ProjectMemberRole,
    pub created_at: i64,
    pub email: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectMember {
    pub org_member_id: String,
    pub role: ProjectMemberRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectMember {
    pub role: ProjectMemberRole,
}
