//! Prefixed ID generation for Paycheck entities.
//!
//! All IDs use a `pc_` brand prefix to guarantee collision avoidance with
//! payment provider IDs (Stripe's `prod_`, `cus_`, `sub_`, etc.).
//!
//! Format: `pc_{entity}_{uuid_simple}` (32 hex chars, no hyphens)

use uuid::Uuid;

/// All known entity prefixes for validation.
const ALL_PREFIXES: &[&str] = &[
    "pc_usr_",
    "pc_org_",
    "pc_proj_",
    "pc_prod_",
    "pc_lic_",
    "pc_dev_",
    "pc_txn_",
    "pc_aud_",
    "pc_mem_",
    "pc_pmem_",
    "pc_cfg_",
    "pc_ps_",
    "pc_ppl_",
    "pc_aks_",
    "pc_key_",
];

/// Validate that a string is a valid Paycheck prefixed ID.
///
/// This is a cheap check to reject garbage before hitting the database.
/// Validates format: `pc_{entity}_{32_hex_chars}`
pub fn is_valid_prefixed_id(s: &str) -> bool {
    // Must start with a known prefix
    let Some(prefix) = ALL_PREFIXES.iter().find(|p| s.starts_with(*p)) else {
        return false;
    };

    // Get the hex part after the prefix
    let hex_part = &s[prefix.len()..];

    // Must be exactly 32 hex characters
    hex_part.len() == 32 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Entity types that have prefixed IDs in Paycheck.
#[derive(Debug, Clone, Copy)]
pub enum EntityType {
    User,
    Organization,
    Project,
    Product,
    License,
    Device,
    Transaction,
    AuditLog,
    OrgMember,
    ProjectMember,
    ServiceConfig,
    PaymentSession,
    ProductProviderLink,
    ApiKeyScope,
    ApiKey,
}

impl EntityType {
    /// Returns the prefix for this entity type.
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::User => "pc_usr",
            Self::Organization => "pc_org",
            Self::Project => "pc_proj",
            Self::Product => "pc_prod",
            Self::License => "pc_lic",
            Self::Device => "pc_dev",
            Self::Transaction => "pc_txn",
            Self::AuditLog => "pc_aud",
            Self::OrgMember => "pc_mem",
            Self::ProjectMember => "pc_pmem",
            Self::ServiceConfig => "pc_cfg",
            Self::PaymentSession => "pc_ps",
            Self::ProductProviderLink => "pc_ppl",
            Self::ApiKeyScope => "pc_aks",
            Self::ApiKey => "pc_key",
        }
    }

    /// Generates a new prefixed ID for this entity type.
    pub fn gen_id(&self) -> String {
        format!("{}_{}", self.prefix(), Uuid::new_v4().as_simple())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_format() {
        let id = EntityType::User.gen_id();
        assert!(id.starts_with("pc_usr_"));
        // pc_usr_ (7 chars) + 32 hex chars = 39 chars total
        assert_eq!(id.len(), 39);
    }

    #[test]
    fn test_all_prefixes_unique() {
        let prefixes: Vec<&str> = vec![
            EntityType::User.prefix(),
            EntityType::Organization.prefix(),
            EntityType::Project.prefix(),
            EntityType::Product.prefix(),
            EntityType::License.prefix(),
            EntityType::Device.prefix(),
            EntityType::Transaction.prefix(),
            EntityType::AuditLog.prefix(),
            EntityType::OrgMember.prefix(),
            EntityType::ProjectMember.prefix(),
            EntityType::ServiceConfig.prefix(),
            EntityType::PaymentSession.prefix(),
            EntityType::ProductProviderLink.prefix(),
            EntityType::ApiKeyScope.prefix(),
            EntityType::ApiKey.prefix(),
        ];

        let mut seen = std::collections::HashSet::new();
        for prefix in prefixes {
            assert!(
                seen.insert(prefix),
                "Duplicate prefix found: {}",
                prefix
            );
        }
    }

    #[test]
    fn test_ids_are_unique() {
        let id1 = EntityType::User.gen_id();
        let id2 = EntityType::User.gen_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_is_valid_prefixed_id() {
        // Valid IDs
        assert!(is_valid_prefixed_id("pc_usr_a1b2c3d4e5f6789012345678901234ab"));
        assert!(is_valid_prefixed_id("pc_prod_a1b2c3d4e5f6789012345678901234ab"));
        assert!(is_valid_prefixed_id("pc_lic_00000000000000000000000000000000"));
        assert!(is_valid_prefixed_id("pc_dev_ffffffffffffffffffffffffffffffff"));

        // Generated IDs should be valid
        assert!(is_valid_prefixed_id(&EntityType::User.gen_id()));
        assert!(is_valid_prefixed_id(&EntityType::Product.gen_id()));
        assert!(is_valid_prefixed_id(&EntityType::License.gen_id()));

        // Invalid IDs
        assert!(!is_valid_prefixed_id("")); // empty
        assert!(!is_valid_prefixed_id("a1b2c3d4-e5f6-7890-1234-567890123456")); // plain UUID
        assert!(!is_valid_prefixed_id("pc_unknown_a1b2c3d4e5f6789012345678901234ab")); // unknown prefix
        assert!(!is_valid_prefixed_id("pc_usr_a1b2c3d4")); // too short
        assert!(!is_valid_prefixed_id("pc_usr_a1b2c3d4e5f6789012345678901234abcd")); // too long
        assert!(!is_valid_prefixed_id("pc_usr_a1b2c3d4e5f6789012345678901234gg")); // non-hex
        assert!(!is_valid_prefixed_id("prod_a1b2c3d4e5f6789012345678901234ab")); // missing pc_
    }
}
