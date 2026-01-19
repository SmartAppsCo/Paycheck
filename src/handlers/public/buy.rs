use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::Json;
use crate::models::{CreatePaymentSession, ServiceProvider};
use crate::payments::{LemonSqueezyClient, PaymentProvider, StripeClient};

/// Simplified BuyRequest - Paycheck knows the product pricing details.
/// Device info is NOT required here - purchase ≠ activation.
/// Redirect URL is configured per-project, not per-request.
#[derive(Debug, Deserialize)]
pub struct BuyRequest {
    /// Public key - identifies the project (preferred over product_id lookup)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Product ID - Paycheck looks up project and pricing from this
    pub product_id: String,
    /// Optional: explicit payment provider (auto-detected if not specified)
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional: developer-managed customer identifier (flows through to license)
    #[serde(default)]
    pub customer_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BuyResponse {
    pub checkout_url: String,
    pub session_id: String,
}

pub async fn initiate_buy(
    State(state): State<AppState>,
    Json(request): Json<BuyRequest>,
) -> Result<Json<BuyResponse>> {
    let conn = state.db.get()?;

    // Get product - this gives us project_id and payment config
    let product = queries::get_product_by_id(&conn, &request.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    // Get project - prefer public_key lookup if provided, otherwise use product's project_id
    let project = if let Some(ref public_key) = request.public_key {
        let project = queries::get_project_by_public_key(&conn, public_key)?
            .or_not_found(msg::PROJECT_NOT_FOUND)?;
        // Verify the product belongs to this project
        if product.project_id != project.id {
            return Err(AppError::BadRequest(
                "Product does not belong to this project".into(),
            ));
        }
        project
    } else {
        queries::get_project_by_id(&conn, &product.project_id)?
            .or_not_found(msg::PROJECT_NOT_FOUND)?
    };

    // Get organization (payment config is at org level)
    let org = queries::get_organization_by_id(&conn, &project.org_id)?
        .or_not_found(msg::ORG_NOT_FOUND)?;

    // Determine payment provider
    let provider = if let Some(ref p) = request.provider {
        // Explicit provider specified
        p.parse::<PaymentProvider>()
            .ok()
            .ok_or_else(|| AppError::BadRequest(msg::INVALID_PROVIDER.into()))?
    } else if let Some(ref provider) = org.payment_provider {
        // Use organization's payment provider
        provider
            .parse::<PaymentProvider>()
            .ok()
            .ok_or_else(|| AppError::BadRequest(msg::INVALID_ORG_PROVIDER.into()))?
    } else {
        // Auto-detect: use the only configured provider, or error if both/neither
        let has_stripe = queries::org_has_service_config(&conn, &org.id, ServiceProvider::Stripe)?;
        let has_ls = queries::org_has_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy)?;
        match (has_stripe, has_ls) {
            (true, false) => PaymentProvider::Stripe,
            (false, true) => PaymentProvider::LemonSqueezy,
            (true, true) => {
                return Err(AppError::BadRequest(
                    "Multiple payment providers configured. Specify 'provider' parameter (stripe or lemonsqueezy).".into()
                ));
            }
            (false, false) => {
                return Err(AppError::BadRequest(
                    "No payment provider configured".into(),
                ));
            }
        }
    };

    // Get provider link for this product and provider
    let provider_str = match provider {
        PaymentProvider::Stripe => "stripe",
        PaymentProvider::LemonSqueezy => "lemonsqueezy",
    };
    let provider_link = queries::get_provider_link(&conn, &product.id, provider_str)?
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "No {} link configured for this product",
                provider_str
            ))
        })?;

    // Create payment session (NO device info - that comes at activation time)
    let session = queries::create_payment_session(
        &conn,
        &CreatePaymentSession {
            product_id: request.product_id.clone(),
            customer_id: request.customer_id.clone(),
        },
    )?;

    // Build callback URL (the payment provider will redirect here after success)
    let callback_url = format!("{}/callback?session={}", state.base_url, session.id);
    let cancel_url = format!("{}/cancel", state.base_url);

    // Create checkout with the appropriate provider using the linked_id
    let checkout_url = match provider {
        PaymentProvider::Stripe => {
            let config = queries::get_org_stripe_config(&conn, &org.id, &state.master_key)?
                .ok_or_else(|| AppError::BadRequest(msg::STRIPE_NOT_CONFIGURED.into()))?;

            let client = StripeClient::new(&config);
            let (_, url) = client
                .create_checkout_session(
                    &session.id,
                    &product.project_id,
                    &product.id,
                    &provider_link.linked_id, // Stripe Price ID (e.g., "price_1ABC...")
                    &callback_url,
                    &cancel_url,
                )
                .await?;
            url
        }
        PaymentProvider::LemonSqueezy => {
            let config = queries::get_org_ls_config(&conn, &org.id, &state.master_key)?
                .ok_or_else(|| AppError::BadRequest(msg::LS_NOT_CONFIGURED.into()))?;

            let client = LemonSqueezyClient::new(&config);
            let (_, url) = client
                .create_checkout(
                    &session.id,
                    &product.project_id,
                    &product.id,
                    &provider_link.linked_id, // LemonSqueezy Variant ID
                    &callback_url,
                )
                .await?;
            url
        }
    };

    Ok(Json(BuyResponse {
        checkout_url,
        session_id: session.id,
    }))
}
