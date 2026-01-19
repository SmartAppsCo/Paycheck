# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).


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
