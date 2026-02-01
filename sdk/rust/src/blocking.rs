//! Blocking Paycheck client using ureq

use crate::device::{generate_uuid, get_machine_id};
use crate::error::{PaycheckError, Result, map_status_to_error_code};
use crate::jwt::{decode_token, is_jwt_expired, is_license_expired, verify_token};
use crate::storage::{FileStorage, StorageAdapter, keys};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use url::Url;

/// Default Paycheck API URL
pub const DEFAULT_BASE_URL: &str = "https://api.paycheck.dev";

/// Valid characters for activation code parts (base32-like, excludes confusing 0/O/1/I)
const ACTIVATION_CODE_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Normalize activation code by stripping non-alphanumeric characters.
///
/// Converts to uppercase and replaces any sequence of non-alphanumeric
/// characters with a single dash. This handles user input with accidental
/// dots, underscores, extra spaces, backticks (from email copy-paste), or
/// other characters.
///
/// Examples:
/// - "`C9MA-JUFF`" → "C9MA-JUFF" (backticks stripped)
/// - "MYAPP.AB3D.EF5G" → "MYAPP-AB3D-EF5G"
/// - "  myapp  ab3d  ef5g  " → "MYAPP-AB3D-EF5G"
fn normalize_activation_code(code: &str) -> String {
    let upper = code.to_uppercase();
    let mut result = String::with_capacity(upper.len());
    let mut last_was_separator = true; // Start true to avoid leading dash

    for c in upper.chars() {
        if c.is_ascii_alphanumeric() {
            result.push(c);
            last_was_separator = false;
        } else if !last_was_separator {
            result.push('-');
            last_was_separator = true;
        }
    }

    // Remove trailing dash if present
    if result.ends_with('-') {
        result.pop();
    }

    result
}

/// Validate activation code format and return normalized code.
///
/// Accepts two formats:
/// - `PREFIX-XXXX-XXXX` (full code with prefix)
/// - `XXXX-XXXX` (bare code, server will prepend project prefix)
///
/// Non-alphanumeric characters are stripped before validation, so codes like
/// "PREFIX...XXXX__XXXX" or "PREFIX XXXX XXXX" are normalized to "PREFIX-XXXX-XXXX".
///
/// Returns the normalized code if valid, Err with message if invalid.
fn validate_activation_code(code: &str) -> Result<String> {
    let normalized = normalize_activation_code(code);
    if normalized.is_empty() {
        return Err(PaycheckError::validation("Activation code is empty"));
    }

    // Split on dashes (all non-alphanumeric chars are now dashes)
    let parts: Vec<&str> = normalized.split('-').filter(|s| !s.is_empty()).collect();

    // Determine which parts contain the XXXX-XXXX code
    let code_parts: &[&str] = match parts.len() {
        3 => &parts[1..], // PREFIX-XXXX-XXXX: validate parts 2 and 3
        2 => &parts[..],  // XXXX-XXXX: validate both parts
        _ => {
            return Err(PaycheckError::validation(
                "Invalid activation code format (expected PREFIX-XXXX-XXXX or XXXX-XXXX)",
            ));
        }
    };

    // Validate the XXXX parts (must be exactly 4 characters from valid set)
    for (i, part) in code_parts.iter().enumerate() {
        if part.len() != 4 {
            return Err(PaycheckError::validation(format!(
                "Activation code part {} must be 4 characters (got {})",
                i + 1,
                part.len()
            )));
        }

        for c in part.bytes() {
            if !ACTIVATION_CODE_CHARS.contains(&c) {
                return Err(PaycheckError::validation(format!(
                    "Invalid character '{}' in activation code",
                    c as char
                )));
            }
        }
    }

    Ok(normalized)
}

/// Configuration options for the Paycheck client
#[derive(Clone, Default)]
pub struct PaycheckOptions {
    /// Paycheck server URL (default: "https://api.paycheck.dev")
    pub base_url: Option<String>,
    /// Custom storage adapter (default: FileStorage based on app_name)
    pub storage: Option<Arc<dyn StorageAdapter>>,
    /// Device type (default: Machine for desktop)
    pub device_type: Option<DeviceType>,
    /// Override device ID (default: auto-generated)
    pub device_id: Option<String>,
    /// Auto-refresh expired tokens (default: true)
    pub auto_refresh: Option<bool>,
}

impl std::fmt::Debug for PaycheckOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaycheckOptions")
            .field("base_url", &self.base_url)
            .field("storage", &"<storage>")
            .field("device_type", &self.device_type)
            .field("device_id", &self.device_id)
            .field("auto_refresh", &self.auto_refresh)
            .finish()
    }
}

/// Result from offline validation
#[derive(Debug, Clone)]
pub struct OfflineValidateResult {
    /// Whether the license is valid
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<LicenseClaims>,
    /// Reason for invalidity
    pub reason: Option<String>,
}

/// Result from sync operation
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Whether the license is valid
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<LicenseClaims>,
    /// Whether the server was reached
    pub synced: bool,
    /// Whether operating in offline mode (using cached JWT)
    pub offline: bool,
    /// Reason for invalidity
    pub reason: Option<String>,
}

/// Result from importing a token
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Whether the token was valid and imported
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<LicenseClaims>,
    /// Reason for invalidity
    pub reason: Option<String>,
}

/// Paycheck SDK client (blocking).
///
/// Initialize with your project's public key and storage directory. The public key
/// enables offline JWT signature verification using Ed25519. The storage directory
/// is where license data will be persisted (created automatically if needed).
///
/// # Example
/// ```rust,ignore
/// use paycheck_sdk::Paycheck;
/// use std::path::PathBuf;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let data_dir = PathBuf::from("/path/to/app/data");
///     let paycheck = Paycheck::new("your-base64-public-key", &data_dir)?;
///
///     // Check if already licensed (offline, verifies Ed25519 signature)
///     if paycheck.is_licensed() {
///         println!("Licensed! Tier: {:?}", paycheck.get_tier());
///         return Ok(());
///     }
///
///     // Activate with code (blocking ~500ms)
///     let result = paycheck.activate_with_code("MYAPP-AB3D-EF5G", None)?;
///     println!("Activated! Tier: {}", result.tier);
///
///     Ok(())
/// }
/// ```
pub struct Paycheck {
    public_key: String,
    base_url: String,
    storage: Arc<dyn StorageAdapter>,
    auto_refresh: bool,
    device_id: String,
    device_type: DeviceType,
}

impl Paycheck {
    /// Create a new Paycheck client with default options.
    ///
    /// # Arguments
    /// * `public_key` - Base64-encoded Ed25519 public key from your Paycheck dashboard
    /// * `storage_dir` - Directory for persistent storage (created if it doesn't exist)
    ///
    /// License data will be stored in `{storage_dir}/paycheck.json`.
    pub fn new(public_key: &str, storage_dir: &Path) -> Result<Self> {
        Self::with_options(public_key, storage_dir, PaycheckOptions::default())
    }

    /// Create a new Paycheck client with custom options.
    ///
    /// # Arguments
    /// * `public_key` - Base64-encoded Ed25519 public key from your Paycheck dashboard
    /// * `storage_dir` - Directory for persistent storage (created if it doesn't exist)
    /// * `options` - Custom configuration
    ///
    /// License data will be stored in `{storage_dir}/paycheck.json`.
    pub fn with_options(
        public_key: &str,
        storage_dir: &Path,
        options: PaycheckOptions,
    ) -> Result<Self> {
        if public_key.is_empty() {
            return Err(PaycheckError::validation("public_key is required"));
        }

        // Create storage directory if it doesn't exist
        if !storage_dir.exists() {
            std::fs::create_dir_all(storage_dir).map_err(|e| {
                PaycheckError::validation(format!("Failed to create storage directory: {}", e))
            })?;
        }

        let base_url = options
            .base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        let storage: Arc<dyn StorageAdapter> = match options.storage {
            Some(s) => s,
            None => Arc::new(
                FileStorage::new(storage_dir)
                    .ok_or_else(|| PaycheckError::validation("Failed to initialize storage"))?,
            ),
        };

        let device_type = options.device_type.unwrap_or(DeviceType::Machine);
        let auto_refresh = options.auto_refresh.unwrap_or(true);

        let device_id = options.device_id.unwrap_or_else(|| {
            if let Some(id) = storage.get(keys::DEVICE_ID) {
                return id;
            }

            let id = match device_type {
                DeviceType::Machine => get_machine_id().unwrap_or_else(|_| generate_uuid()),
                DeviceType::Uuid => generate_uuid(),
            };

            storage.set(keys::DEVICE_ID, &id);
            id
        });

        Ok(Self {
            public_key: public_key.to_string(),
            base_url,
            storage,
            auto_refresh,
            device_id,
            device_type,
        })
    }

    // ==================== Core Methods ====================

    /// Start a checkout session to purchase a product.
    ///
    /// Note: Redirect URL is configured per-project in the Paycheck dashboard,
    /// not per-request. This prevents open redirect vulnerabilities.
    pub fn checkout(
        &self,
        product_id: &str,
        options: Option<CheckoutOptions>,
    ) -> Result<CheckoutResult> {
        #[derive(Serialize)]
        struct BuyRequest {
            public_key: String,
            product_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            provider: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            customer_id: Option<String>,
        }

        let opts = options.unwrap_or_default();
        let body = BuyRequest {
            public_key: self.public_key.clone(),
            product_id: product_id.to_string(),
            provider: opts.provider,
            customer_id: opts.customer_id,
        };

        self.post("/buy", &body)
    }

    /// Validate the stored license.
    ///
    /// By default, performs offline validation by verifying the Ed25519 signature
    /// and checking expiration.
    pub fn validate(&self, token: Option<&str>) -> OfflineValidateResult {
        let token = match token {
            Some(t) => t.to_string(),
            None => match self.get_token() {
                Some(t) => t,
                None => {
                    return OfflineValidateResult {
                        valid: false,
                        claims: None,
                        reason: None,
                    };
                }
            },
        };

        // Verify signature
        if !verify_token(&token, &self.public_key) {
            return OfflineValidateResult {
                valid: false,
                claims: None,
                reason: Some("Invalid signature".to_string()),
            };
        }

        // Decode claims
        let claims = match decode_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return OfflineValidateResult {
                    valid: false,
                    claims: None,
                    reason: Some("Invalid token format".to_string()),
                };
            }
        };

        // Check device ID matches
        if claims.device_id != self.device_id {
            return OfflineValidateResult {
                valid: false,
                claims: Some(claims),
                reason: Some("Device mismatch".to_string()),
            };
        }

        // Check license expiration
        if is_license_expired(&claims) {
            return OfflineValidateResult {
                valid: false,
                claims: Some(claims),
                reason: Some("License expired".to_string()),
            };
        }

        OfflineValidateResult {
            valid: true,
            claims: Some(claims),
            reason: None,
        }
    }

    /// Online validation check (also checks revocation).
    pub fn validate_online(&self) -> Result<ValidateResult> {
        let Some(token) = self.get_token() else {
            return Ok(ValidateResult {
                valid: false,
                license_exp: None,
                updates_exp: None,
            });
        };

        let claims = match decode_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return Ok(ValidateResult {
                    valid: false,
                    license_exp: None,
                    updates_exp: None,
                });
            }
        };

        #[derive(Serialize)]
        struct ValidateRequest {
            public_key: String,
            jti: String,
        }

        let body = ValidateRequest {
            public_key: self.public_key.clone(),
            jti: claims.jti,
        };

        match self.post::<ValidateResponse, _>("/validate", &body) {
            Ok(r) => Ok(r.into()),
            Err(_) => Ok(ValidateResult {
                valid: false,
                license_exp: None,
                updates_exp: None,
            }),
        }
    }

    /// Sync with the server and validate the license.
    ///
    /// This is the recommended method for online/subscription apps. It:
    /// 1. Tries to reach the server to check for updates (renewals, revocation)
    /// 2. Refreshes the token if the server has newer expiration dates
    /// 3. Falls back to offline validation if the server is unreachable
    ///
    /// Always returns a result - never returns an error for network failures.
    ///
    /// # Example
    /// ```rust,ignore
    /// // On app startup for subscription apps
    /// let result = paycheck.sync();
    ///
    /// if result.valid {
    ///     if result.offline {
    ///         println!("Offline mode - using cached license");
    ///     }
    ///     load_app(&result.claims.unwrap().tier);
    /// } else {
    ///     if !result.synced {
    ///         println!("Please connect to verify your license");
    ///     } else {
    ///         show_activation_prompt();
    ///     }
    /// }
    /// ```
    pub fn sync(&self) -> SyncResult {
        let Some(token) = self.get_token() else {
            return SyncResult {
                valid: false,
                claims: None,
                synced: false,
                offline: true,
                reason: None,
            };
        };

        // First, verify signature locally
        if !verify_token(&token, &self.public_key) {
            return SyncResult {
                valid: false,
                claims: None,
                synced: false,
                offline: true,
                reason: Some("Invalid signature".to_string()),
            };
        }

        // Decode claims
        let mut claims = match decode_token(&token) {
            Ok(c) => c,
            Err(_) => {
                return SyncResult {
                    valid: false,
                    claims: None,
                    synced: false,
                    offline: true,
                    reason: Some("Invalid token format".to_string()),
                };
            }
        };

        // Check device ID matches
        if claims.device_id != self.device_id {
            return SyncResult {
                valid: false,
                claims: Some(claims),
                synced: false,
                offline: true,
                reason: Some("Device mismatch".to_string()),
            };
        }

        // Try to sync with server
        #[derive(Serialize)]
        struct ValidateRequest {
            public_key: String,
            jti: String,
        }

        let body = ValidateRequest {
            public_key: self.public_key.clone(),
            jti: claims.jti.clone(),
        };

        match self.post::<ValidateResponse, _>("/validate", &body) {
            Ok(response) => {
                if !response.valid {
                    return SyncResult {
                        valid: false,
                        claims: Some(claims),
                        synced: true,
                        offline: false,
                        reason: Some("Revoked or invalid".to_string()),
                    };
                }

                // Check if server has updated expiration - refresh token if so
                if response.license_exp != claims.license_exp
                    && let Ok(new_token) = self.refresh_token()
                    && let Ok(new_claims) = decode_token(&new_token)
                {
                    claims = new_claims;
                }
                // Refresh failed, but validation passed - continue with current token

                // Check license expiration with potentially updated claims
                if is_license_expired(&claims) {
                    return SyncResult {
                        valid: false,
                        claims: Some(claims),
                        synced: true,
                        offline: false,
                        reason: Some("License expired".to_string()),
                    };
                }

                SyncResult {
                    valid: true,
                    claims: Some(claims),
                    synced: true,
                    offline: false,
                    reason: None,
                }
            }
            Err(_) => {
                // Server unreachable - fall back to offline validation
                if is_license_expired(&claims) {
                    return SyncResult {
                        valid: false,
                        claims: Some(claims),
                        synced: false,
                        offline: true,
                        reason: Some("License expired".to_string()),
                    };
                }

                SyncResult {
                    valid: true,
                    claims: Some(claims),
                    synced: false,
                    offline: true,
                    reason: None,
                }
            }
        }
    }

    /// Import a JWT token directly (offline activation).
    ///
    /// Use this when you have a JWT from another source (clipboard, QR code,
    /// file, enterprise IT distribution). The token is verified locally using
    /// Ed25519 signature verification - no network required.
    ///
    /// # Example
    /// ```rust,ignore
    /// // Offline activation from clipboard
    /// let jwt = get_clipboard_text();
    /// let result = paycheck.import_token(&jwt);
    /// if result.valid {
    ///     println!("Activated offline! Tier: {}", result.claims.unwrap().tier);
    /// }
    /// ```
    pub fn import_token(&self, token: &str) -> ImportResult {
        // Verify Ed25519 signature
        if !verify_token(token, &self.public_key) {
            return ImportResult {
                valid: false,
                claims: None,
                reason: Some("Invalid signature".to_string()),
            };
        }

        // Decode and validate claims
        let claims = match decode_token(token) {
            Ok(c) => c,
            Err(_) => {
                return ImportResult {
                    valid: false,
                    claims: None,
                    reason: Some("Invalid token format".to_string()),
                };
            }
        };

        // Check device ID matches
        if claims.device_id != self.device_id {
            return ImportResult {
                valid: false,
                claims: Some(claims),
                reason: Some("Device mismatch".to_string()),
            };
        }

        // Check license expiration
        if is_license_expired(&claims) {
            return ImportResult {
                valid: false,
                claims: Some(claims),
                reason: Some("License expired".to_string()),
            };
        }

        // Valid - store the token
        self.storage.set(keys::TOKEN, token);

        ImportResult {
            valid: true,
            claims: Some(claims),
            reason: None,
        }
    }

    /// Activate with a short-lived activation code.
    ///
    /// The code must be in PREFIX-XXXX-XXXX format. The SDK validates and normalizes
    /// the format before making a network request to avoid unnecessary API calls.
    /// Non-alphanumeric characters are stripped, so codes with accidental dots,
    /// underscores, or extra spaces are handled gracefully.
    pub fn activate_with_code(
        &self,
        code: &str,
        options: Option<DeviceInfo>,
    ) -> Result<ActivationResult> {
        // Validate and normalize code format before making network request
        let normalized_code = validate_activation_code(code)?;

        #[derive(Serialize)]
        struct RedeemRequest {
            public_key: String,
            code: String,
            device_id: String,
            device_type: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            device_name: Option<String>,
        }

        let body = RedeemRequest {
            public_key: self.public_key.clone(),
            code: normalized_code,
            device_id: self.device_id.clone(),
            device_type: self.device_type.to_string(),
            device_name: options.and_then(|d| d.device_name),
        };

        let response: RedeemResponse = self.post("/redeem", &body)?;

        self.storage.set(keys::TOKEN, &response.token);

        Ok(response.into())
    }

    /// Request an activation code to be sent to the purchase email.
    ///
    /// Use this for license recovery when a user needs to activate on a new device.
    /// The server will send a short-lived activation code (30 min TTL) to the email
    /// associated with the license purchase.
    ///
    /// Note: The response is always a generic success message to prevent email enumeration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let result = paycheck.request_activation_code("user@example.com")?;
    /// println!("{}", result.message);
    /// ```
    pub fn request_activation_code(&self, email: &str) -> Result<RequestCodeResult> {
        #[derive(Serialize)]
        struct RequestCodeRequest {
            email: String,
            public_key: String,
        }

        let body = RequestCodeRequest {
            email: email.to_string(),
            public_key: self.public_key.clone(),
        };

        let response: RequestCodeResponse = self.post("/activation/request-code", &body)?;

        Ok(response.into())
    }

    // ==================== Helper Methods ====================

    /// Quick check if a valid license is stored.
    /// Performs offline signature verification.
    pub fn is_licensed(&self) -> bool {
        self.validate(None).valid
    }

    /// Get decoded license claims (without signature verification).
    pub fn get_license(&self) -> Option<LicenseClaims> {
        let token = self.get_token()?;
        decode_token(&token).ok()
    }

    /// Check if license has a specific feature.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.get_license()
            .map(|c| c.features.iter().any(|f| f == feature))
            .unwrap_or(false)
    }

    /// Get the product tier.
    pub fn get_tier(&self) -> Option<String> {
        self.get_license().map(|c| c.tier)
    }

    /// Check if the license is expired.
    pub fn is_expired(&self) -> bool {
        self.get_license()
            .map(|c| is_license_expired(&c))
            .unwrap_or(true)
    }

    /// Check if the license covers a specific version by its release timestamp.
    pub fn covers_version(&self, timestamp: i64) -> bool {
        self.get_license()
            .map(|c| crate::jwt::covers_version(&c, timestamp))
            .unwrap_or(false)
    }

    // ==================== Token Management ====================

    /// Get the stored JWT token.
    pub fn get_token(&self) -> Option<String> {
        self.storage.get(keys::TOKEN)
    }

    /// Clear stored token.
    pub fn clear_token(&self) {
        self.storage.remove(keys::TOKEN);
    }

    /// Refresh the JWT token.
    pub fn refresh_token(&self) -> Result<String> {
        let token = self.get_token().ok_or_else(PaycheckError::no_token)?;

        #[derive(Deserialize)]
        struct RefreshResponse {
            token: String,
        }

        let response: RefreshResponse = self.post_with_auth("/refresh", &(), &token)?;

        self.storage.set(keys::TOKEN, &response.token);
        Ok(response.token)
    }

    // ==================== Device Management ====================

    /// Deactivate this device.
    pub fn deactivate(&self) -> Result<DeactivateResult> {
        let token = self.ensure_fresh_token()?;

        let response: DeactivateResponse =
            self.post_with_auth("/devices/deactivate", &(), &token)?;

        self.clear_token();

        Ok(response.into())
    }

    /// Get full license information including devices.
    /// Uses the stored JWT token for authentication.
    pub fn get_license_info(&self) -> Result<LicenseInfo> {
        let token = self.ensure_fresh_token()?;

        let url = format!(
            "{}/license?public_key={}",
            self.base_url,
            urlencoding::encode(&self.public_key)
        );

        let response: LicenseInfoResponse = self.get_with_auth(&url, &token)?;
        Ok(response.into())
    }

    // ==================== Callback Handling ====================

    /// Handle the callback URL after payment redirect.
    ///
    /// Extracts the activation code and project ID from the callback URL.
    /// Use the code with `activate_with_code()` to complete activation.
    pub fn handle_callback(&self, url: &str) -> Result<CallbackResult> {
        let parsed =
            Url::parse(url).map_err(|_| PaycheckError::validation("Invalid callback URL"))?;

        let mut result = CallbackResult {
            status: CallbackStatus::Pending,
            code: None,
            project_id: None,
        };

        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "status" => {
                    result.status = if value == "success" {
                        CallbackStatus::Success
                    } else {
                        CallbackStatus::Pending
                    };
                }
                "code" => {
                    result.code = Some(value.to_string());
                }
                "project_id" => {
                    result.project_id = Some(value.to_string());
                }
                _ => {}
            }
        }

        Ok(result)
    }

    // ==================== Internal HTTP Helpers ====================

    fn ensure_fresh_token(&self) -> Result<String> {
        let token = self.get_token().ok_or_else(PaycheckError::no_token)?;

        if self.auto_refresh
            && let Ok(claims) = decode_token(&token)
            && is_jwt_expired(&claims)
        {
            return self.refresh_token();
        }

        Ok(token)
    }

    fn get_with_auth<T: for<'de> Deserialize<'de>>(&self, url: &str, token: &str) -> Result<T> {
        let response = ureq::get(url)
            .header("Authorization", &format!("Bearer {}", token))
            .header("User-Agent", "paycheck-sdk-rust/0.5.0")
            .call()
            .map_err(|e| self.map_ureq_error(e))?;

        response
            .into_body()
            .read_json()
            .map_err(|e| PaycheckError::network(e.to_string()))
    }

    fn post<T: for<'de> Deserialize<'de>, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = ureq::post(&url)
            .header("User-Agent", "paycheck-sdk-rust/0.5.0")
            .send_json(body)
            .map_err(|e| self.map_ureq_error(e))?;

        response
            .into_body()
            .read_json()
            .map_err(|e| PaycheckError::network(e.to_string()))
    }

    fn post_with_auth<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        token: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = ureq::post(&url)
            .header("Authorization", &format!("Bearer {}", token))
            .header("User-Agent", "paycheck-sdk-rust/0.5.0")
            .send_json(body)
            .map_err(|e| self.map_ureq_error(e))?;

        response
            .into_body()
            .read_json()
            .map_err(|e| PaycheckError::network(e.to_string()))
    }

    fn map_ureq_error(&self, error: ureq::Error) -> PaycheckError {
        match error {
            ureq::Error::StatusCode(status) => {
                // Try to read error body
                let message = format!("Request failed with status {}", status);
                let code = map_status_to_error_code(status, &message);
                PaycheckError::with_status(code, message, status)
            }
            _ => PaycheckError::network(error.to_string()),
        }
    }
}

impl std::fmt::Debug for Paycheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paycheck")
            .field("base_url", &self.base_url)
            .field("device_id", &self.device_id)
            .field("device_type", &self.device_type)
            .field("auto_refresh", &self.auto_refresh)
            .finish()
    }
}

/// Checkout options for the new API.
///
/// Note: Redirect URL is configured per-project in the Paycheck dashboard,
/// not per-request. This prevents open redirect vulnerabilities.
#[derive(Debug, Clone, Default)]
pub struct CheckoutOptions {
    /// Payment provider (auto-detected if not specified)
    pub provider: Option<String>,
    /// Your customer identifier (flows through to license)
    pub customer_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_activation_code() {
        // Basic normalization
        assert_eq!(normalize_activation_code("myapp-ab3d-ef5g"), "MYAPP-AB3D-EF5G");

        // Multiple separators collapsed to single dash
        assert_eq!(normalize_activation_code("MYAPP--AB3D--EF5G"), "MYAPP-AB3D-EF5G");
        assert_eq!(normalize_activation_code("MYAPP  AB3D  EF5G"), "MYAPP-AB3D-EF5G");

        // Non-alphanumeric characters replaced with dashes
        assert_eq!(normalize_activation_code("MYAPP.AB3D.EF5G"), "MYAPP-AB3D-EF5G");
        assert_eq!(normalize_activation_code("MYAPP_AB3D_EF5G"), "MYAPP-AB3D-EF5G");
        assert_eq!(normalize_activation_code("MYAPP...AB3D___EF5G"), "MYAPP-AB3D-EF5G");

        // Leading/trailing separators removed
        assert_eq!(normalize_activation_code("  MYAPP-AB3D-EF5G  "), "MYAPP-AB3D-EF5G");
        assert_eq!(normalize_activation_code("---MYAPP-AB3D-EF5G---"), "MYAPP-AB3D-EF5G");

        // Mixed separators
        assert_eq!(normalize_activation_code("MYAPP - AB3D - EF5G"), "MYAPP-AB3D-EF5G");

        // Backticks from email copy-paste (common issue)
        assert_eq!(normalize_activation_code("`C9MA-JUFF`"), "C9MA-JUFF");
        assert_eq!(normalize_activation_code("`MYAPP-C9MA-JUFF`"), "MYAPP-C9MA-JUFF");
    }

    #[test]
    fn test_validate_activation_code_full() {
        // Full code format: PREFIX-XXXX-XXXX
        assert!(validate_activation_code("MYAPP-AB3D-EF5G").is_ok());

        // Spaces instead of dashes
        assert!(validate_activation_code("MYAPP AB3D EF5G").is_ok());

        // Mixed separators
        assert!(validate_activation_code("MYAPP-AB3D EF5G").is_ok());

        // Extra whitespace
        assert!(validate_activation_code("  MYAPP-AB3D-EF5G  ").is_ok());

        // Lowercase (should be accepted, converted internally)
        assert!(validate_activation_code("myapp-ab3d-ef5g").is_ok());

        // All valid characters in code parts
        assert!(validate_activation_code("TEST-ABCD-2345").is_ok());
        assert!(validate_activation_code("TEST-HJKM-6789").is_ok());

        // Non-alphanumeric separators (dots, underscores, etc.)
        assert!(validate_activation_code("MYAPP.AB3D.EF5G").is_ok());
        assert!(validate_activation_code("MYAPP_AB3D_EF5G").is_ok());
        assert!(validate_activation_code("MYAPP...AB3D___EF5G").is_ok());
    }

    #[test]
    fn test_validate_activation_code_bare() {
        // Bare code format: XXXX-XXXX (server prepends prefix)
        assert!(validate_activation_code("AB3D-EF5G").is_ok());

        // Bare code with space
        assert!(validate_activation_code("AB3D EF5G").is_ok());

        // Extra whitespace
        assert!(validate_activation_code("  AB3D-EF5G  ").is_ok());

        // Lowercase
        assert!(validate_activation_code("ab3d-ef5g").is_ok());

        // Non-alphanumeric separators
        assert!(validate_activation_code("AB3D.EF5G").is_ok());
        assert!(validate_activation_code("AB3D_EF5G").is_ok());
    }

    #[test]
    fn test_validate_activation_code_returns_normalized() {
        // Verify the normalized code is returned
        assert_eq!(
            validate_activation_code("myapp-ab3d-ef5g").unwrap(),
            "MYAPP-AB3D-EF5G"
        );
        assert_eq!(
            validate_activation_code("MYAPP.AB3D.EF5G").unwrap(),
            "MYAPP-AB3D-EF5G"
        );
        assert_eq!(
            validate_activation_code("  ab3d  ef5g  ").unwrap(),
            "AB3D-EF5G"
        );
    }

    #[test]
    fn test_validate_activation_code_invalid() {
        // Empty
        assert!(validate_activation_code("").is_err());
        assert!(validate_activation_code("   ").is_err());

        // Wrong number of parts (1 or 4+)
        assert!(validate_activation_code("AB3DEF5G").is_err()); // 1 part (no separator)
        assert!(validate_activation_code("MYAPP-AB3D-EF5G-XXXX").is_err()); // 4 parts

        // Wrong length in code parts (full code)
        assert!(validate_activation_code("MYAPP-ABC-EF5G").is_err()); // 3 chars
        assert!(validate_activation_code("MYAPP-ABCDE-EF5G").is_err()); // 5 chars

        // Wrong length in code parts (bare code)
        assert!(validate_activation_code("ABC-EF5G").is_err()); // 3 chars
        assert!(validate_activation_code("AB3D-EF5").is_err()); // 3 chars

        // Invalid characters (0, O, 1, I are excluded to avoid confusion)
        assert!(validate_activation_code("MYAPP-AB0D-EF5G").is_err()); // 0 (looks like O)
        assert!(validate_activation_code("MYAPP-ABOD-EF5G").is_err()); // O (looks like 0)
        assert!(validate_activation_code("AB0D-EF5G").is_err()); // 0 in bare code
        assert!(validate_activation_code("ABID-EF5G").is_err()); // I in bare code
    }
}
