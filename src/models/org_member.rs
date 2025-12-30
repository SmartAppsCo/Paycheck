use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrgMemberRole {
    Owner,
    Admin,
    Member,
}

impl OrgMemberRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgMemberRole::Owner => "owner",
            OrgMemberRole::Admin => "admin",
            OrgMemberRole::Member => "member",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(OrgMemberRole::Owner),
            "admin" => Some(OrgMemberRole::Admin),
            "member" => Some(OrgMemberRole::Member),
            _ => None,
        }
    }

    pub fn can_manage_members(&self) -> bool {
        matches!(self, OrgMemberRole::Owner)
    }

    pub fn has_implicit_project_access(&self) -> bool {
        matches!(self, OrgMemberRole::Owner | OrgMemberRole::Admin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMember {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub name: String,
    pub role: OrgMemberRole,
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrgMember {
    pub email: String,
    pub name: String,
    pub role: OrgMemberRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrgMember {
    pub name: Option<String>,
    pub role: Option<OrgMemberRole>,
}
