//! Row mapping trait and helpers for reducing boilerplate in queries.
//!
//! This module provides a `FromRow` trait that models can implement to
//! define how they are constructed from database rows, plus helper functions
//! for common query patterns.

use rusqlite::{Connection, OptionalExtension, Row, ToSql};

use crate::models::*;

/// Parse a string column into an enum type, converting parse errors to rusqlite errors.
///
/// This provides graceful error handling instead of panicking when database
/// contains invalid enum values (from corruption, migration errors, etc.).
fn parse_enum<T: std::str::FromStr>(row: &Row, col: usize, col_name: &str) -> rusqlite::Result<T> {
    row.get::<_, String>(col)?.parse::<T>().map_err(|_| {
        rusqlite::Error::InvalidColumnType(col, col_name.to_string(), rusqlite::types::Type::Text)
    })
}

/// Trait for constructing a type from a database row.
///
/// Implementing this trait allows using the `query_one` and `query_all`
/// helper functions, reducing repetitive row mapping closures.
pub trait FromRow: Sized {
    /// Construct an instance from a database row.
    fn from_row(row: &Row) -> rusqlite::Result<Self>;
}

/// Query for a single optional result.
pub fn query_one<T: FromRow>(
    conn: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
) -> crate::error::Result<Option<T>> {
    conn.query_row(sql, params, T::from_row)
        .optional()
        .map_err(Into::into)
}

/// Query for multiple results.
pub fn query_all<T: FromRow>(
    conn: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
) -> crate::error::Result<Vec<T>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(params, T::from_row)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ============ SQL SELECT Constants ============

pub const USER_COLS: &str =
    "id, email, name, operator_role, created_at, updated_at, deleted_at, deleted_cascade_depth";

pub const ORGANIZATION_COLS: &str =
    "id, name, payment_config_id, email_config_id, created_at, updated_at, deleted_at, deleted_cascade_depth";

pub const SERVICE_CONFIG_COLS: &str =
    "id, org_id, name, category, provider, config_encrypted, created_at, updated_at";

pub const ORG_MEMBER_COLS: &str =
    "id, user_id, org_id, role, created_at, updated_at, deleted_at, deleted_cascade_depth";

pub const ORG_MEMBER_WITH_USER_COLS: &str = "m.id, m.user_id, u.email, u.name, m.org_id, m.role, m.created_at, m.updated_at, m.deleted_at, m.deleted_cascade_depth";

pub const API_KEY_COLS: &str = "id, user_id, name, key_prefix, key_hash, user_manageable, created_at, last_used_at, expires_at, revoked_at";

pub const API_KEY_SCOPE_COLS: &str = "api_key_id, org_id, project_id, access";

pub const PROJECT_COLS: &str = "id, org_id, name, license_key_prefix, private_key, public_key, redirect_url, email_from, email_enabled, email_webhook_url, payment_config_id, email_config_id, feedback_webhook_url, feedback_email, crash_webhook_url, crash_email, created_at, updated_at, deleted_at, deleted_cascade_depth";

pub const PROJECT_MEMBER_COLS: &str = "id, org_member_id, project_id, role, created_at, updated_at, deleted_at, deleted_cascade_depth";

pub const PRODUCT_COLS: &str = "id, project_id, name, tier, license_exp_days, updates_exp_days, activation_limit, device_limit, device_inactive_days, features, price_cents, currency, payment_config_id, email_config_id, created_at, deleted_at, deleted_cascade_depth";

pub const PROVIDER_LINK_COLS: &str = "id, product_id, provider, linked_id, created_at, updated_at";

/// Columns for licenses table (no encryption - email_hash instead of key)
/// Payment provider info moved to transactions table
pub const LICENSE_COLS: &str = "id, email_hash, project_id, product_id, customer_id, activation_count, revoked, created_at, expires_at, updates_expires_at, deleted_at, deleted_cascade_depth";

/// Columns for transactions table (payment events)
pub const TRANSACTION_COLS: &str = "id, license_id, project_id, product_id, org_id, payment_provider, provider_customer_id, provider_subscription_id, provider_order_id, currency, subtotal_cents, discount_cents, net_cents, tax_cents, total_cents, discount_code, tax_inclusive, customer_country, transaction_type, parent_transaction_id, is_subscription, test_mode, created_at";

pub const DEVICE_COLS: &str =
    "id, license_id, device_id, device_type, name, jti, activated_at, last_seen_at";

pub const PAYMENT_SESSION_COLS: &str =
    "id, product_id, customer_id, created_at, completed, license_id";

pub const ACTIVATION_CODE_COLS: &str = "code_hash, license_id, expires_at, used, created_at";

// ============ FromRow Implementations ============

impl FromRow for User {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        // operator_role is optional - parse it if present
        let operator_role: Option<OperatorRole> = row
            .get::<_, Option<String>>(3)?
            .and_then(|s| s.parse().ok());
        Ok(User {
            id: row.get(0)?,
            email: row.get(1)?,
            name: row.get(2)?,
            operator_role,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            deleted_at: row.get(6)?,
            deleted_cascade_depth: row.get(7)?,
        })
    }
}

impl FromRow for Organization {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Organization {
            id: row.get(0)?,
            name: row.get(1)?,
            payment_config_id: row.get(2)?,
            email_config_id: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            deleted_at: row.get(6)?,
            deleted_cascade_depth: row.get(7)?,
        })
    }
}

impl FromRow for ServiceConfig {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ServiceConfig {
            id: row.get(0)?,
            org_id: row.get(1)?,
            name: row.get(2)?,
            category: parse_enum(row, 3, "category")?,
            provider: parse_enum(row, 4, "provider")?,
            config_encrypted: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }
}

impl FromRow for OrgMember {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(OrgMember {
            id: row.get(0)?,
            user_id: row.get(1)?,
            org_id: row.get(2)?,
            role: parse_enum(row, 3, "role")?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            deleted_at: row.get(6)?,
            deleted_cascade_depth: row.get(7)?,
        })
    }
}

impl FromRow for OrgMemberWithUser {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(OrgMemberWithUser {
            id: row.get(0)?,
            user_id: row.get(1)?,
            email: row.get(2)?,
            name: row.get(3)?,
            org_id: row.get(4)?,
            role: parse_enum(row, 5, "role")?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
            deleted_at: row.get(8)?,
            deleted_cascade_depth: row.get(9)?,
        })
    }
}

impl FromRow for ApiKey {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ApiKey {
            id: row.get(0)?,
            user_id: row.get(1)?,
            name: row.get(2)?,
            prefix: row.get(3)?,
            key_hash: row.get(4)?,
            user_manageable: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_used_at: row.get(7)?,
            expires_at: row.get(8)?,
            revoked_at: row.get(9)?,
        })
    }
}

impl FromRow for ApiKeyScope {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ApiKeyScope {
            api_key_id: row.get(0)?,
            org_id: row.get(1)?,
            project_id: row.get(2)?,
            access: parse_enum(row, 3, "access")?,
        })
    }
}

impl FromRow for Project {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Project {
            id: row.get(0)?,
            org_id: row.get(1)?,
            name: row.get(2)?,
            license_key_prefix: row.get(3)?,
            private_key: row.get(4)?,
            public_key: row.get(5)?,
            redirect_url: row.get(6)?,
            email_from: row.get(7)?,
            email_enabled: row.get::<_, i32>(8)? != 0,
            email_webhook_url: row.get(9)?,
            payment_config_id: row.get(10)?,
            email_config_id: row.get(11)?,
            feedback_webhook_url: row.get(12)?,
            feedback_email: row.get(13)?,
            crash_webhook_url: row.get(14)?,
            crash_email: row.get(15)?,
            created_at: row.get(16)?,
            updated_at: row.get(17)?,
            deleted_at: row.get(18)?,
            deleted_cascade_depth: row.get(19)?,
        })
    }
}

impl FromRow for ProjectMember {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProjectMember {
            id: row.get(0)?,
            org_member_id: row.get(1)?,
            project_id: row.get(2)?,
            role: parse_enum(row, 3, "role")?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            deleted_at: row.get(6)?,
            deleted_cascade_depth: row.get(7)?,
        })
    }
}

impl FromRow for ProjectMemberWithDetails {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProjectMemberWithDetails {
            id: row.get(0)?,
            org_member_id: row.get(1)?,
            user_id: row.get(2)?,
            project_id: row.get(3)?,
            role: parse_enum(row, 4, "role")?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
            deleted_at: row.get(7)?,
            deleted_cascade_depth: row.get(8)?,
            email: row.get(9)?,
            name: row.get(10)?,
        })
    }
}

impl FromRow for Product {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let features_str: String = row.get(9)?;
        Ok(Product {
            id: row.get(0)?,
            project_id: row.get(1)?,
            name: row.get(2)?,
            tier: row.get(3)?,
            license_exp_days: row.get(4)?,
            updates_exp_days: row.get(5)?,
            activation_limit: row.get(6)?,
            device_limit: row.get(7)?,
            device_inactive_days: row.get(8)?,
            features: serde_json::from_str(&features_str).unwrap_or_default(),
            price_cents: row.get(10)?,
            currency: row.get(11)?,
            payment_config_id: row.get(12)?,
            email_config_id: row.get(13)?,
            created_at: row.get(14)?,
            deleted_at: row.get(15)?,
            deleted_cascade_depth: row.get(16)?,
        })
    }
}

impl FromRow for ProductProviderLink {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ProductProviderLink {
            id: row.get(0)?,
            product_id: row.get(1)?,
            provider: row.get(2)?,
            linked_id: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    }
}

impl FromRow for License {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(License {
            id: row.get(0)?,
            email_hash: row.get(1)?,
            project_id: row.get(2)?,
            product_id: row.get(3)?,
            customer_id: row.get(4)?,
            activation_count: row.get(5)?,
            revoked: row.get::<_, i32>(6)? != 0,
            created_at: row.get(7)?,
            expires_at: row.get(8)?,
            updates_expires_at: row.get(9)?,
            deleted_at: row.get(10)?,
            deleted_cascade_depth: row.get(11)?,
        })
    }
}

impl FromRow for Transaction {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let transaction_type_str: String = row.get(18)?;
        let transaction_type = TransactionType::from_str(&transaction_type_str).ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(
                18,
                "transaction_type".to_string(),
                rusqlite::types::Type::Text,
            )
        })?;

        Ok(Transaction {
            id: row.get(0)?,
            license_id: row.get(1)?,
            project_id: row.get(2)?,
            product_id: row.get(3)?,
            org_id: row.get(4)?,
            payment_provider: row.get(5)?,
            provider_customer_id: row.get(6)?,
            provider_subscription_id: row.get(7)?,
            provider_order_id: row.get(8)?,
            currency: row.get(9)?,
            subtotal_cents: row.get(10)?,
            discount_cents: row.get(11)?,
            net_cents: row.get(12)?,
            tax_cents: row.get(13)?,
            total_cents: row.get(14)?,
            discount_code: row.get(15)?,
            tax_inclusive: row.get::<_, Option<i32>>(16)?.map(|v| v != 0),
            customer_country: row.get(17)?,
            transaction_type,
            parent_transaction_id: row.get(19)?,
            is_subscription: row.get::<_, i32>(20)? != 0,
            test_mode: row.get::<_, i32>(21)? != 0,
            created_at: row.get(22)?,
        })
    }
}

impl FromRow for Device {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Device {
            id: row.get(0)?,
            license_id: row.get(1)?,
            device_id: row.get(2)?,
            device_type: parse_enum(row, 3, "device_type")?,
            name: row.get(4)?,
            jti: row.get(5)?,
            activated_at: row.get(6)?,
            last_seen_at: row.get(7)?,
        })
    }
}

impl FromRow for PaymentSession {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(PaymentSession {
            id: row.get(0)?,
            product_id: row.get(1)?,
            customer_id: row.get(2)?,
            created_at: row.get(3)?,
            completed: row.get::<_, i32>(4)? != 0,
            license_id: row.get(5)?,
        })
    }
}

impl FromRow for ActivationCode {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(ActivationCode {
            code: row.get(0)?,
            license_id: row.get(1)?,
            expires_at: row.get(2)?,
            used: row.get::<_, i32>(3)? != 0,
            created_at: row.get(4)?,
        })
    }
}
