# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).


## [0.8.0] - 2026-02-05

### Added

- **Tagging system for users and organizations**: Flexible tagging with add/remove semantics where remove takes precedence over add
  - Tags stored as JSON arrays in the database
  - New `PATCH /operators/users/{id}/tags` endpoint for user tags (admin+ required)
  - New `PATCH /operators/organizations/{id}/tags` endpoint for org tags (admin+ required)
  - Request body: `{"add": ["tag1", "tag2"], "remove": ["tag3"]}` — remove takes precedence
- **Org tag enforcement for public API endpoints**: Configurable tag-based blocking for organizations
  - `PAYCHECK_DISABLE_CHECKOUT_TAG`: Blocks `POST /buy` when org has matching tag
  - `PAYCHECK_DISABLE_PUBLIC_API_TAG`: Blocks `/buy`, `/validate`, `/activation/request-code`, and `/refresh`
  - Returns 503 Service Unavailable when org has the matching tag
  - No blocking when env vars are not set (self-hosted friendly)

### Fixed

- **Unnecessary backup on fresh databases**: Migration system now skips backup for version 0 databases (nothing to backup)


## [0.7.2] - 2026-02-04

### Fixed

- **JTI prefix consistency**: New JWT IDs now use `pc_jti_` prefix via `EntityType::Jti.gen_id()` (existing tokens unaffected - stored JTI is reused on refresh)


## [0.7.1] - 2026-02-04

### Fixed

- **API key prefix consistency**: New API keys now use `pc_key_` prefix via `EntityType::ApiKey.gen_id()` (existing keys unaffected - lookup is by hash)
- Docs site logo now navigates in same window instead of opening new tab


## [0.7.0] - 2026-02-04

### Added

- **Prefixed entity IDs**: All IDs now use `pc_{entity}_{32_hex_chars}` format (e.g., `pc_usr_`, `pc_org_`, `pc_lic_`)
  - Instant entity type identification in logs and support tickets
  - Collision avoidance with payment provider IDs (Stripe's `prod_`, `cus_`, `sub_`)
  - New `src/id.rs` module with `EntityType` enum for 15 entity types
- **Transaction tracking**: Revenue analytics decoupled from licenses
  - `GET /orgs/{org_id}/transactions[/stats]` — org-level revenue
  - `GET /orgs/{org_id}/projects/{project_id}/transactions[/stats]` — project-level revenue
  - `GET /orgs/{org_id}/projects/{project_id}/licenses/{license_id}/transactions` — license history
  - Filters: `product_id`, `transaction_type`, `date_range`, `test_mode`
  - Stats: `total_revenue`, `net_revenue`, `transactions_by_type`
- **Feedback and crash reporting**: Passthrough to dev-configured endpoints (no PII storage)
  - `POST /feedback` and `POST /crash` endpoints (JWT auth required)
  - Webhook (primary) + email (fallback) delivery with exponential backoff
  - Project config: `feedback_webhook_url`, `feedback_email`, `crash_webhook_url`, `crash_email`
  - SDK methods: `submitFeedback()`, `reportCrash()`, `reportError()` with stack trace sanitization
- **Usage metering webhook**: Optional billing events for hosted deployments
  - Email events: `activation_sent`, `feedback_sent`, `crash_sent` with `delivery_method`
  - Sales events: `purchase`, `renewal`, `refund` with transaction details
  - Configure via `PAYCHECK_METERING_WEBHOOK_URL`
- **Refund handling**: Stripe and LemonSqueezy refund webhooks create `refund` transactions
- **Subscription renewal transactions**: Renewal webhooks now create transaction records
- **3-level email config lookup**: Product → Project → Org inheritance for `email_config_id`
- **Configurable request body size**: `PAYCHECK_MAX_BODY_SIZE` env var (default: 1MB)
- **Docusaurus documentation site**: Comprehensive docs at docs.paycheck.dev
- **SDK issuer validation**: Rust and TypeScript SDKs reject JWTs not issued by Paycheck

### Changed

- **Breaking**: `/validate` endpoint now accepts full JWT token instead of just `jti`
- README simplified to point to hosted documentation
- SDK package metadata updated with correct license (Elastic-2.0) and repository URL
- Use `OsRng` instead of `thread_rng()` for all cryptographic operations
- Memory limits added to activation rate limiter (DoS prevention)

### Fixed

- **Project restore endpoint unreachable**: Moved to `org_routes` layer (middleware was rejecting soft-deleted projects)
- **Service config deletion**: Now uses TOCTOU-safe transaction
- **Soft delete restore cascades**: `project_members` now properly restored with parent
- **Queries excluding soft-deleted entities**: Joined entity lookups now filter `deleted_at`
- **CORS headers**: Added `x-on-behalf-of` to allowed headers
- **Feedback billing fairness**: Metering correctly reports `org_key` vs `system_key` for all email types


## [0.6.2] - 2026-02-01

### Fixed

- **Payment callback webhook race condition**: Callback endpoint now polls for up to 500ms before returning `status=pending`, catching cases where the browser redirect beats the webhook delivery (typically 100-300ms)


## [0.6.1] - 2026-02-01

### Changed

- **SDKs normalize activation codes**: Non-alphanumeric characters (backticks, dots, underscores, etc.) are stripped before validation
  - Handles messy copy-paste from emails gracefully (e.g., `` `C9MA-JUFF` `` → `C9MA-JUFF`)
  - Multiple separators collapsed into single dashes
- **Project prefix validation**: `license_key_prefix` must contain only alphanumeric characters
  - Ensures SDK normalization works correctly (non-alphanumeric chars are treated as separators)

### Fixed

- Email template uses `<span>` instead of `<code>` to prevent some email clients from adding backticks when copying activation codes


## [0.6.0] - 2026-02-01

### Added

- **Expanded license update API**: `PUT /orgs/.../licenses/{id}` now supports updating `customer_id`, `expires_at`, and `updates_expires_at`
  - Nullable fields can be explicitly set to null via `Option<Option<T>>` pattern
- **Optional activation code prefix**: Server accepts both `PREFIX-XXXX-XXXX` and bare `XXXX-XXXX` formats
  - Bare codes get project prefix prepended before hashing (no collision risk)
  - SDKs validate both formats before making network requests
  - Allows apps to display prefix as a visual hint without requiring user input

### Changed

- **Breaking (Rust SDK)**: Refactored to sync-first for desktop app compatibility
  - Replaced async `reqwest` + `tokio` with sync `ureq` (no async runtime required)
  - Removed `MemoryStorage` — desktop apps should use persistent file storage
  - Constructor now takes explicit `storage_dir` path instead of app name
  - Auto-creates storage directory if it doesn't exist
  - Split API: `new()` for defaults, `with_options()` for custom configuration
  - Simplified TLS feature flags: `rustls-tls` (default) or `native-tls`
- **Breaking**: License update endpoint changed from `PATCH` to `PUT` for consistency
- Audit action renamed: `UpdateLicenseEmail` → `UpdateLicense`


## [0.5.0] - 2026-02-01

### Added

- **Named service configs**: Reusable config pool at the org level with user-friendly names
  - New CRUD endpoints: `GET/POST /orgs/{org_id}/service-configs`, `GET/PUT/DELETE /orgs/{org_id}/service-configs/{id}`
  - Configs have `name`, `category` (payment/email), and `provider` (stripe/lemonsqueezy/resend)
  - Configs can be shared across projects and products via FK references
- **Three-level config inheritance**: Product → Project → Org for both payment and email configs
  - `payment_config_id` and `email_config_id` fields on organizations, projects, and products
  - Lookup functions check product first, then project, then org
  - `ConfigSource` enum indicates where the effective config came from
- **Cancel URL support**: Payment checkout cancel redirects to project's `redirect_url` with `?status=canceled` query parameter
- Database migration 002 for existing databases (adds new columns, migrates existing configs)

### Changed

- **Breaking**: Service configs now use named configs instead of scope-based configs
  - Old `ServiceScope` enum removed; configs are now org-owned with FK references
  - `stripe_config`/`ls_config`/`resend_api_key` fields in API replaced with `payment_config_id`/`email_config_id`
- **Breaking**: `get_effective_email_config()` now requires a `product` parameter for 3-level lookup
- **Breaking**: Organization model no longer stores payment credentials directly
  - Use `payment_config_id` and `email_config_id` to reference service configs
- Provider link documentation clarified to distinguish from service configs (provider links map products to payment provider price IDs)


## [0.4.0] - 2026-01-20

### Added

- Database migration system with automatic backup before schema changes
  - Migrations run on startup, tracked via `PRAGMA user_version`
  - Creates timestamped backups (e.g., `paycheck.db.backup_v0_20260120_143022`)
  - Configure retention with `MIGRATION_BACKUP_COUNT` (default: 3, -1 = keep all, 0 = none)

### Changed

- Subscription renewals now use the payment provider's billing period end date instead of calculating from `license_exp_days`


## [0.3.0] - 2026-01-20

### Added

- `device_inactive_days` product field — excludes devices not seen within N days from device limit count, allowing natural device rotation
- `syncInterval` option in React `useLicense` hook for periodic server check-ins (minimum 5 minutes)
- License details now include `active_device_count` and `total_device_count` fields

### Changed

- **Breaking**: `device_limit` and `activation_limit` changed from `i32` (0 = unlimited) to `Option<i32>` (null = unlimited)
- Null values for optional fields are now always serialized explicitly in API responses

### Fixed

- SDK types for `activation_limit` and `device_limit` now correctly typed as nullable (`Option<i32>` in Rust, `number | null` in TypeScript)


## [0.2.0] - 2026-01-20

### Added

- Audit logging for public endpoints (`/buy`, `/callback`, `/redeem`, `/validate`)
- Cross-tab license detection in React `useLicense` hook — automatically syncs when license is activated in another tab
- License creation API (`POST /orgs/.../licenses`) now returns full license details including activation code
- Activation code emails now display prefix as non-selectable (CSS `user-select: none`) for easier copying
- `/redeem` endpoint normalizes activation codes to handle whitespace/formatting variations

### Changed

- **Breaking**: Replaced `has_stripe`/`has_lemonsqueezy` booleans with `configured_services` map in organization responses
- **Breaking**: Removed per-request `redirect_url` from SDKs — redirect URL is now configured per-project only
- **Breaking**: Replaced `ProductPaymentConfig` with `ProductProviderLink` for payment provider integration
- **Breaking**: Paginated response fields reordered — metadata (`page`, `per_page`, `total`, `total_pages`) now appears before `items`
- Organization defaults now grouped by category in API responses
- Email copy updated to clarify "8-character code (after the prefix)"

### Fixed

- React `useLicense()` hook not updating when license activated in another hook instance
- `UpdateProduct` deserialization for nullable fields (`device_limit`, `activation_limit`, `license_exp_days`, `updates_exp_days`)
- SDK response field casing now consistent (camelCase in TypeScript SDK)
- Stripe webhook email extraction from `customer_details`
- React SDK double-activation issue on mount
- Impersonation audit logging regression — `actor_user_id` now correctly records impersonated user


## [0.1.2] - 2026-01-19

### Changed

- **Breaking**: `POST /orgs/{org_id}/projects/{project_id}/members` now accepts `user_id` instead of `org_member_id` in request body

### Fixed

- Bruno API collection: project member endpoints now use `{{user_id}}` in URL paths to match API spec
- Bruno API collection: environment variables consolidated to use `user_id` instead of `member_id`/`project_member_id`


## [0.1.1] - 2026-01-19

### Fixed

- `X-On-Behalf-Of` header in `--seed` output now correctly shows `user_id` instead of the internal member record ID
- Bruno API collection impersonation examples now use `{{user_id}}` instead of `{{member_id}}`




## [0.1.0] - 2026-01-18

Initial release of Paycheck — an offline-first licensing system for indie developers.

### Added

- **Offline-first licensing**: Ed25519-signed JWTs verified locally without server contact
- **Email-based activation**: Short-lived codes (30-min TTL) instead of permanent license keys
- **Payment providers**: Stripe and LemonSqueezy integration with webhook support
- **Multi-tenant architecture**: Operators → Organizations → Projects → Products → Licenses
- **Public API**: Buy, redeem, validate, refresh, and device management endpoints
- **Admin APIs**: Operator and organization endpoints with role-based access control
- **Security**: Envelope encryption (AES-256-GCM), rate limiting, API key scopes, audit logging
- **Email delivery**: Resend integration, webhook mode, or DIY via admin API
- **SDKs**: Rust and TypeScript (with React hooks) for client integration
- **Dev tools**: `--seed` for test data, `--ephemeral` mode, master key rotation
