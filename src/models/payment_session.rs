use serde::{Deserialize, Serialize};

/// Payment session tracks a purchase flow from /buy to webhook completion.
/// Device info is NOT stored here - purchase ≠ activation.
/// Device is created when user activates via /redeem.
/// Redirect URL is configured per-project, not per-session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSession {
    pub id: String,
    pub product_id: String,
    /// Developer-managed customer identifier (flows through to license)
    pub customer_id: Option<String>,
    pub created_at: i64,
    pub completed: bool,
    /// License ID created by webhook (set when checkout completes)
    pub license_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePaymentSession {
    pub product_id: String,
    /// Developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
}
