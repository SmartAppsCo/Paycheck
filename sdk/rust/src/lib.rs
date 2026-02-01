//! # Paycheck SDK
//!
//! Official Rust SDK for [Paycheck](https://paycheck.dev) -
//! the offline-first licensing system for indie developers.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use paycheck_sdk::Paycheck;
//! use std::path::PathBuf;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let data_dir = PathBuf::from("/path/to/app/data");
//!     let paycheck = Paycheck::new("your-base64-public-key", &data_dir)?;
//!
//!     // Check if already licensed (works offline, verifies Ed25519 signature!)
//!     if paycheck.is_licensed() {
//!         println!("Licensed! Tier: {:?}", paycheck.get_tier());
//!         return Ok(());
//!     }
//!
//!     // Activate with code (blocking ~500ms)
//!     let result = paycheck.activate_with_code("MYAPP-AB3D-EF5G", None)?;
//!     println!("Activated! Tier: {}", result.tier);
//!
//!     // Feature gating
//!     if paycheck.has_feature("export") {
//!         println!("Export feature enabled!");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## With Custom Options
//!
//! ```rust,ignore
//! use paycheck_sdk::{Paycheck, PaycheckOptions, DeviceType};
//!
//! let paycheck = Paycheck::with_options(
//!     "your-base64-public-key",
//!     &data_dir,
//!     PaycheckOptions {
//!         base_url: Some("https://pay.myapp.com".into()),
//!         device_type: Some(DeviceType::Uuid),
//!         ..Default::default()
//!     },
//! )?;
//! ```
//!
//! ## Storage
//!
//! License data is persisted to `{storage_dir}/paycheck.json`. The directory is
//! created automatically if it doesn't exist.
//!
//! ## Features
//!
//! - `rustls-tls` (default): Use rustls for HTTPS
//! - `native-tls`: Use native TLS for HTTPS (alternative to rustls-tls)
//!
//! ## Offline-First Design
//!
//! The SDK is designed for offline-first operation:
//!
//! - `is_licensed()`, `has_feature()`, `get_tier()` work without network
//! - Ed25519 signature verification ensures JWT authenticity offline
//! - License validity is checked via `license_exp` claim, not JWT `exp`
//! - Tokens auto-refresh when network is available
//!
//! ## Understanding Expiration Times
//!
//! Paycheck JWTs have **three expiration-related claims**:
//!
//! | Claim | Typical Value | Purpose |
//! |-------|---------------|---------|
//! | `exp` | ~1 hour | Token freshness, revocation propagation window |
//! | `license_exp` | null or future date | Actual license validity ("is user licensed?") |
//! | `updates_exp` | null or future date | Version access ("can user use this version?") |
//!
//! **Key point:** The JWT's `exp` (~1 hour) is NOT the license expiration. Expired JWTs
//! can still be refreshed via `/refresh` as long as `license_exp` hasn't passed.
//! The short `exp` ensures revocations propagate within an hour and claims stay fresh.
//!
//! See `sdk/CORE.md` for detailed documentation.

pub mod blocking;
pub mod device;
pub mod error;
pub mod jwt;
pub mod storage;
pub mod types;

// Main exports
pub use blocking::{
    CheckoutOptions, ImportResult, OfflineValidateResult, Paycheck, PaycheckOptions, SyncResult,
    DEFAULT_BASE_URL,
};

// Error types
pub use error::{PaycheckError, PaycheckErrorCode, Result};

// Storage
pub use storage::{FileStorage, StorageAdapter};

// Types
pub use types::{
    ActivationResult, CallbackResult, CallbackStatus, CheckoutParams, CheckoutResult,
    DeactivateResult, DeviceInfo, DeviceType, LicenseClaims, LicenseDeviceInfo, LicenseInfo,
    LicenseStatus, RequestCodeResult, ValidateResult,
};

// Device utilities
pub use device::{generate_uuid, get_machine_id};

// JWT utilities
pub use jwt::{
    covers_version, decode_token, has_feature, is_jwt_expired, is_license_expired,
    verify_and_decode_token, verify_token,
};
