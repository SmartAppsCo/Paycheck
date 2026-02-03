use serde::{Deserialize, Serialize};

/// Represents a payment event (purchase, renewal, or refund)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub license_id: Option<String>,
    pub project_id: String,
    pub product_id: Option<String>,
    pub org_id: String,

    // Provider info
    pub payment_provider: String,
    pub provider_customer_id: Option<String>,
    pub provider_subscription_id: Option<String>,
    pub provider_order_id: String,

    // Amounts (cents)
    pub currency: String,
    pub subtotal_cents: i64,
    pub discount_cents: i64,
    pub net_cents: i64,
    pub tax_cents: i64,
    pub total_cents: i64,

    // Discount code (if any)
    pub discount_code: Option<String>,

    // Tax info
    pub tax_inclusive: Option<bool>,

    // Geography (country only, no PII)
    pub customer_country: Option<String>,

    // Classification
    pub transaction_type: TransactionType,
    pub parent_transaction_id: Option<String>,
    pub is_subscription: bool,

    /// Source distinguishes voluntary refunds from disputes.
    /// Values: "payment", "refund", "dispute", "dispute_reversal"
    pub source: String,
    /// Flexible metadata for provider-specific data (JSON).
    /// For disputes: {"dispute_id": "dp_xxx", "reason": "fraudulent"}
    pub metadata: Option<String>,

    pub test_mode: bool,
    pub created_at: i64,
}

/// Data required to create a new transaction
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTransaction {
    pub license_id: Option<String>,
    pub project_id: String,
    pub product_id: Option<String>,
    pub org_id: String,

    pub payment_provider: String,
    pub provider_customer_id: Option<String>,
    pub provider_subscription_id: Option<String>,
    pub provider_order_id: String,

    pub currency: String,
    pub subtotal_cents: i64,
    pub discount_cents: i64,
    pub net_cents: i64,
    pub tax_cents: i64,
    pub total_cents: i64,

    pub discount_code: Option<String>,
    pub tax_inclusive: Option<bool>,
    pub customer_country: Option<String>,

    pub transaction_type: TransactionType,
    pub parent_transaction_id: Option<String>,
    pub is_subscription: bool,

    /// Source distinguishes voluntary refunds from disputes.
    /// Values: "payment", "refund", "dispute", "dispute_reversal"
    pub source: String,
    /// Flexible metadata for provider-specific data (JSON).
    pub metadata: Option<String>,

    pub test_mode: bool,
}

/// Type of payment transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Purchase,
    Renewal,
    Refund,
}

impl TransactionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Purchase => "purchase",
            Self::Renewal => "renewal",
            Self::Refund => "refund",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "purchase" => Some(Self::Purchase),
            "renewal" => Some(Self::Renewal),
            "refund" => Some(Self::Refund),
            _ => None,
        }
    }
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Filters for querying transactions
#[derive(Debug, Default, Clone, Deserialize)]
pub struct TransactionFilters {
    pub project_id: Option<String>,
    pub product_id: Option<String>,
    pub license_id: Option<String>,
    pub transaction_type: Option<TransactionType>,
    pub payment_provider: Option<String>,
    pub start_date: Option<i64>,
    pub end_date: Option<i64>,
    pub test_mode: Option<bool>,
}

/// Revenue statistics for a single currency
#[derive(Debug, Clone, Serialize)]
pub struct CurrencyStats {
    /// ISO 4217 currency code (lowercase, e.g., "usd", "eur")
    pub currency: String,
    /// Total gross revenue (sum of net_cents for purchases + renewals)
    pub gross_revenue_cents: i64,
    /// Total refunded (absolute value of refund net_cents)
    pub refunded_cents: i64,
    /// Net revenue (gross - refunds)
    pub net_revenue_cents: i64,
    /// Total discount amount given
    pub total_discount_cents: i64,
    /// Total tax collected
    pub total_tax_cents: i64,
}

/// Aggregate statistics for transactions, grouped by currency
#[derive(Debug, Clone, Serialize)]
pub struct TransactionStats {
    /// Revenue breakdown by currency (amounts cannot be summed across currencies)
    pub by_currency: Vec<CurrencyStats>,
    /// Total number of purchase transactions (across all currencies)
    pub purchase_count: i64,
    /// Total number of renewal transactions (across all currencies)
    pub renewal_count: i64,
    /// Total number of refund transactions (across all currencies)
    pub refund_count: i64,
}
