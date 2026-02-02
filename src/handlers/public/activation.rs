//! Activation code request handler.
//!
//! Allows users to request activation codes sent to their purchase email.
//! This enables activation on new devices without needing a permanent license key.
//! If the user has multiple licenses, all codes are sent in a single email.

use std::collections::HashMap;

use axum::{extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::email::{
    EmailSendConfig, EmailSendResult, EmailTrigger, LicenseCodeInfo, MultiLicenseEmailConfig,
};
use crate::error::Result;
use crate::extractors::Json;
use crate::metering::{spawn_email_metering, EmailMeteringEvent};
use crate::models::{ActorType, AuditAction, AuditLogNames};
use crate::util::AuditLogBuilder;

#[derive(Debug, Deserialize)]
pub struct RequestCodeBody {
    /// The email address used for the original purchase
    pub email: String,
    /// Public key identifying the project
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RequestCodeResponse {
    /// Generic success message (same whether email exists or not)
    pub message: &'static str,
}

/// POST /activation/request-code
///
/// Request activation codes sent to the purchase email.
/// If the user has multiple licenses, all codes are sent in a single email.
/// Always returns 200 with a generic message to prevent email enumeration.
///
/// Rate limited to 3 requests per email per hour.
pub async fn request_activation_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RequestCodeBody>,
) -> Result<Json<RequestCodeResponse>> {
    let conn = state.db.get()?;

    // Compute email hash for rate limiting and lookup
    let email_hash = state.email_hasher.hash(&body.email);

    // Rate limit check (by email hash)
    if let Err(_msg) = state.activation_rate_limiter.check(&email_hash) {
        // Return same generic message to prevent timing attacks
        tracing::warn!("Rate limit exceeded for email hash {}...", &email_hash[..8]);
        // Still return success to prevent email enumeration via rate limit error timing
        return Ok(Json(RequestCodeResponse {
            message: "If a license exists for this email, an activation code has been sent.",
        }));
    }

    // Look up project by public key
    let project = match queries::get_project_by_public_key(&conn, &body.public_key)? {
        Some(p) => p,
        None => {
            // Don't reveal project doesn't exist - return same response
            tracing::debug!("Project not found for public key");
            return Ok(Json(RequestCodeResponse {
                message: "If a license exists for this email, an activation code has been sent.",
            }));
        }
    };

    // Look up ALL licenses by email hash and project (user may have multiple)
    let licenses = queries::get_licenses_by_email_hash(&conn, &project.id, &email_hash)?;

    // Filter to non-revoked licenses only (query already does this, but be explicit)
    let active_licenses: Vec<_> = licenses.into_iter().filter(|l| !l.revoked).collect();

    if active_licenses.is_empty() {
        tracing::debug!(
            "No active licenses found for email hash {}... in project {}",
            &email_hash[..8],
            project.id
        );
        return Ok(Json(RequestCodeResponse {
            message: "If a license exists for this email, an activation code has been sent.",
        }));
    }

    // Batch fetch all products for the licenses (avoids N+1 queries)
    let product_ids: Vec<&str> = active_licenses
        .iter()
        .map(|l| l.product_id.as_str())
        .collect();
    let products = queries::get_products_by_ids(&conn, &product_ids)?;
    let product_names: HashMap<&str, &str> = products
        .iter()
        .map(|p| (p.id.as_str(), p.name.as_str()))
        .collect();

    // Get organization and effective email config (product → project → org level)
    // Use first product for email config lookup (all products in same project typically share config)
    let org = queries::get_organization_by_id(&conn, &project.org_id)?;
    let first_product = products.first();
    let org_resend_key = match (&org, first_product) {
        (Some(org), Some(product)) => {
            queries::get_effective_email_config(&conn, product, &project, org, &state.master_key)
                .ok()
                .flatten()
                .map(|(key, _source)| key)
        }
        _ => None,
    };

    // Create activation codes for all licenses
    let mut license_codes: Vec<LicenseCodeInfo> = Vec::with_capacity(active_licenses.len());

    for license in &active_licenses {
        let code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

        let product_name = product_names
            .get(license.product_id.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Your Product".to_string());

        license_codes.push(LicenseCodeInfo {
            product_name,
            code: code.code,
            license_id: license.id.clone(),
            purchased_at: license.created_at,
        });
    }

    // Audit log the activation code request (only when we actually found licenses)
    let audit_conn = state.audit.get()?;
    let org_name = org.as_ref().map(|o| o.name.clone());
    if let Err(e) = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::Public, None)
        .action(AuditAction::RequestActivationCode)
        .resource("license", &active_licenses[0].id) // Use first license as resource
        .details(&serde_json::json!({
            "email": body.email,
            "licenses_found": active_licenses.len(),
            "license_ids": active_licenses.iter().map(|l| &l.id).collect::<Vec<_>>(),
        }))
        .org(&project.org_id)
        .project(&project.id)
        .names(&AuditLogNames {
            org_name,
            project_name: Some(project.name.clone()),
            ..Default::default()
        })
        .save()
    {
        tracing::warn!("Failed to write activation code request audit log: {}", e);
    }

    // Send email - use single-license format for 1, multi-license for 2+
    let email_result = if license_codes.len() == 1 {
        let info = &license_codes[0];
        let email_config = EmailSendConfig {
            to_email: &body.email,
            code: &info.code,
            expires_in_minutes: 30,
            product_name: &info.product_name,
            project_name: &project.name,
            project: &project,
            license_id: &info.license_id,
            purchased_at: info.purchased_at,
            org_resend_key: org_resend_key.as_deref(),
            trigger: EmailTrigger::RecoveryRequest,
        };
        state.email_service.send_activation_code(email_config).await
    } else {
        let email_config = MultiLicenseEmailConfig {
            to_email: &body.email,
            expires_in_minutes: 30,
            project_name: &project.name,
            project: &project,
            licenses: license_codes,
            org_resend_key: org_resend_key.as_deref(),
            trigger: EmailTrigger::RecoveryRequest,
        };
        state
            .email_service
            .send_multi_license_activation_codes(email_config)
            .await
    };

    match email_result {
        Ok(result) => {
            tracing::info!(
                result = ?result,
                email_hash_prefix = &email_hash[..8],
                project_id = %project.id,
                license_count = active_licenses.len(),
                "Activation code email processed"
            );

            // Fire-and-forget metering event
            let delivery_method = match result {
                EmailSendResult::Sent if org_resend_key.is_some() => Some("org_key"),
                EmailSendResult::Sent => Some("system_key"),
                EmailSendResult::WebhookCalled => Some("webhook"),
                EmailSendResult::Disabled | EmailSendResult::NoApiKey => None,
            };

            if let Some(delivery_method) = delivery_method {
                // Use first license ID as idempotency key (or generate UUID for multi-license)
                let idempotency_key = if active_licenses.len() == 1 {
                    active_licenses[0].id.clone()
                } else {
                    uuid::Uuid::new_v4().to_string()
                };

                spawn_email_metering(
                    state.http_client.clone(),
                    state.metering_webhook_url.clone(),
                    EmailMeteringEvent {
                        event: "activation_sent".to_string(),
                        org_id: project.org_id.clone(),
                        project_id: project.id.clone(),
                        license_id: active_licenses.first().map(|l| l.id.clone()),
                        product_id: active_licenses.first().map(|l| l.product_id.clone()),
                        delivery_method: delivery_method.to_string(),
                        timestamp: chrono::Utc::now().timestamp(),
                        idempotency_key,
                    },
                );
            }
        }
        Err(e) => {
            // Log error but don't expose it to user
            tracing::error!(
                error = %e,
                email_hash_prefix = &email_hash[..8],
                project_id = %project.id,
                license_count = active_licenses.len(),
                "Failed to send activation code email"
            );
        }
    }

    // Always return same response (email enumeration protection)
    Ok(Json(RequestCodeResponse {
        message: "If a license exists for this email, an activation code has been sent.",
    }))
}
