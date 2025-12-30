use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeConfig {
    pub secret_key: String,
    pub publishable_key: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LemonSqueezyConfig {
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub domain: String,
    #[serde(skip_serializing)]
    pub private_key: Vec<u8>,
    pub public_key: String,
    pub stripe_config: Option<StripeConfig>,
    pub ls_config: Option<LemonSqueezyConfig>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectPublic {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub domain: String,
    pub public_key: String,
    pub has_stripe: bool,
    pub has_lemonsqueezy: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Project> for ProjectPublic {
    fn from(p: Project) -> Self {
        Self {
            id: p.id,
            org_id: p.org_id,
            name: p.name,
            domain: p.domain,
            public_key: p.public_key,
            has_stripe: p.stripe_config.is_some(),
            has_lemonsqueezy: p.ls_config.is_some(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateProject {
    pub name: String,
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub stripe_config: Option<StripeConfig>,
    pub ls_config: Option<LemonSqueezyConfig>,
}
