# Paycheck SDK Core Specification

This document defines the core functions that every Paycheck SDK must implement. All SDKs should maintain consistent naming, behavior, and error handling.

## Design Principles

1. **Offline-first**: License checks work without network access, with Ed25519 signature verification
2. **Minimal config**: Just `publicKey` to get started
3. **Sensible defaults**: Auto-generate device IDs, use localStorage/files
4. **Override capability**: Custom storage, device IDs when needed
5. **Type-safe**: Strong typing for all public APIs
6. **Secure**: Ed25519 signature verification ensures JWT authenticity offline

---

## Understanding JWT Expiration vs License Expiration

Paycheck JWTs contain **three expiration-related claims** that serve different purposes:

### `exp` — JWT Expiration (~1 hour)

The standard JWT `exp` claim controls how long the token itself is considered fresh.

**Purpose:**
- **Revocation propagation**: If a license is revoked server-side, the JWT remains locally valid until `exp`. A shorter `exp` means revocations take effect faster.
- **Claims freshness**: When the JWT is refreshed, the server returns current `tier`, `features`, and expiration dates. If a user upgraded their plan, the short `exp` ensures the app picks up changes within an hour.
- **Refresh trigger**: The SDK uses `exp` to know when to call `/refresh` for updated data.

**Key behaviors:**
- Expired JWTs can still be refreshed via `/refresh` (up to 10 years old)
- Expired JWTs can still be validated via `/validate` (endpoint uses JTI, not the JWT itself)
- Offline validation should check `license_exp`, NOT `exp`

### `license_exp` — License Expiration (business logic)

The custom `license_exp` claim controls when the actual license access ends.

**Purpose:**
- Determines if the user has a valid license to use your software
- Can be `null` for perpetual licenses (one-time purchases)
- Set based on product configuration (e.g., 30 days for monthly, 365 for annual, null for lifetime)

**Key behaviors:**
- This is what your app should check for "is the user licensed?"
- Once `license_exp` passes, the license is truly expired and cannot be refreshed
- Perpetual licenses (`license_exp: null`) never expire

### `updates_exp` — Version Access Expiration

The `updates_exp` claim controls which versions the user can access.

**Purpose:**
- Enables "perpetual license with 1 year of updates" business models
- Can be `null` for lifetime update access

**Key behaviors:**
- Compare against your app's build/release timestamp
- `coversVersion(timestamp)` returns true if `updates_exp` is null or >= timestamp

### Summary Table

| Claim | Typical Value | Purpose | Check When |
|-------|---------------|---------|------------|
| `exp` | ~1 hour | Token freshness, revocation window | Auto-refresh trigger |
| `license_exp` | null, or future date | License validity | "Is user licensed?" |
| `updates_exp` | null, or future date | Version access | "Can user use this version?" |

### Example Scenarios

**One-time purchase with lifetime updates:**
```
exp: 1hr from now (refreshable forever)
license_exp: null (perpetual)
updates_exp: null (all versions)
```

**One-time purchase with 1 year of updates:**
```
exp: 1hr from now (refreshable while license valid)
license_exp: null (perpetual)
updates_exp: purchase_date + 365 days
```

**Monthly subscription:**
```
exp: 1hr from now
license_exp: subscription_end_date (e.g., 30 days from renewal)
updates_exp: subscription_end_date
```

### SDK Validation Logic

The SDK's `validate()` and `sync()` methods check `license_exp`, not `exp`:

```
1. Verify Ed25519 signature (ensures JWT wasn't tampered)
2. Check device_id matches (prevents token theft)
3. Check license_exp hasn't passed (is user licensed?)
4. Return { valid: true, claims }
```

The `exp` claim is only used internally by `autoRefresh` to decide when to call `/refresh`.

## Client Configuration

### `new Paycheck(publicKey: string, options?: PaycheckOptions)`

Creates a configured Paycheck instance.

```
publicKey: string           # Required. Base64-encoded Ed25519 public key from Paycheck dashboard

PaycheckOptions:
  baseUrl?: string          # Optional. Paycheck server URL (default: "https://api.paycheck.dev")
  storage?: StorageAdapter  # Optional. Custom storage (default: localStorage for web, file for desktop)
  autoRefresh?: boolean     # Optional. Auto-refresh expired tokens (default: true)
  deviceId?: string         # Optional. Override device ID (default: auto-generated)
  deviceType?: DeviceType   # Optional. "uuid" or "machine" (default: "uuid" for web, "machine" for desktop)
```

**Behavior:**
- Validates that publicKey is provided
- Initializes storage adapter
- Generates or retrieves persistent device ID
- Returns Paycheck instance ready for use

---

## Payment Flow

### `checkout(productId: string, options?: CheckoutOptions) -> Promise<CheckoutResult>`

Initiates a payment checkout session.

```
CheckoutOptions:
  provider?: string         # Optional. Payment provider (auto-detected if not specified)
  customerId?: string       # Optional. Your customer identifier (flows through to license)
  redirect?: string         # Optional. Post-payment redirect URL (must be in project's allowlist)

CheckoutResult:
  checkoutUrl: string       # URL to redirect user to
  sessionId: string         # Payment session ID
```

**Behavior:**
- POST to `/buy` endpoint with `public_key` and `product_id`
- Device info is NOT sent - purchase ≠ activation (device created at /redeem time)
- Returns checkout URL for redirect
- Throws on validation errors (invalid product, no payment provider configured, etc.)

---

### `handleCallback(url: string) -> CallbackResult`

Parses the post-payment callback URL and extracts credentials.

```
CallbackResult:
  status: "success" | "pending"
  code?: string             # Short-lived redemption code (present on success)
  licenseKey?: string       # Permanent license key (only on internal success page)
  projectId?: string        # Project ID (for reference)
```

**Behavior:**
- Parses URL query parameters (`code`, `license_key`, `project_id`, `status`)
- Note: NO token is returned - user must call activate() with device info to get a JWT
- Returns parsed result (license_key is returned but NOT stored for security)

---

## License Activation

### `activate(licenseKey: string, deviceInfo?: DeviceInfo) -> Promise<ActivationResult>`

Exchanges a permanent license key for a JWT.

```
DeviceInfo:
  deviceName?: string       # Optional. Human-readable device name

ActivationResult:
  token: string             # JWT for this device
  licenseExp: number | null # When license expires (null = perpetual)
  updatesExp: number | null # When version access expires (null = all versions)
  tier: string              # Product tier
  features: string[]        # Enabled features
  redemptionCode: string    # Short-lived code for future activations
  redemptionCodeExpiresAt: number
```

**Behavior:**
- POST to `/redeem/key` with license key in Authorization header
- Includes `public_key` in request body
- Stores returned token automatically
- Throws on invalid key, revoked license, device limit reached

---

### `activateWithCode(code: string, deviceInfo?: DeviceInfo) -> Promise<ActivationResult>`

Exchanges a short-lived activation code for a JWT.

```
code: string  # Accepts two formats:
              # - Full: "PREFIX-XXXX-XXXX" (e.g., "MYAPP-AB3D-EF5G")
              # - Bare: "XXXX-XXXX" (e.g., "AB3D-EF5G") - server prepends project prefix
```

**Behavior:**
- Validates code format client-side before making API request (avoids unnecessary network calls)
- POST to `/redeem` with code in JSON body (not URL params for security)
- Includes `public_key`, `device_id`, `device_type` in request body
- Server normalizes bare codes by prepending the project's configured prefix
- Activation codes expire in 30 minutes and are single-use
- Throws `VALIDATION_ERROR` if code format is invalid (wrong length, invalid characters)

---

### `formatActivationCode(code: string) -> string`

Formats user input to match the server's expected activation code format.

**Behavior:**
- Converts to uppercase
- Replaces any non-alphanumeric characters with dashes
- Trims leading/trailing separators
- Does NOT validate - just formats (use for UI display as user types)

**Example:**
```
formatActivationCode("myapp ab3d ef5g")  -> "MYAPP-AB3D-EF5G"
formatActivationCode("`AB3D-EF5G`")      -> "AB3D-EF5G"
formatActivationCode("ab3d...ef5g")      -> "AB3D-EF5G"
```

Use this to show users exactly what the server will see, or to format codes in real-time as users type.

---

## Token Operations

### `getToken() -> string | null`

Returns the currently stored JWT, or null if none.

**Behavior:**
- Reads from storage
- Does NOT validate token
- Synchronous operation

---

### `refreshToken() -> Promise<string>`

Refreshes the current token (works even if expired).

**Behavior:**
- POST to `/refresh` with current token in Authorization header
- Updates stored token with new one
- Throws if no token stored or refresh fails
- Paycheck accepts tokens up to 10 years old for refresh

---

### `clearToken() -> void`

Removes the stored token.

**Behavior:**
- Removes token from storage
- Synchronous operation

---

## License Validation

### `validate(options?: ValidateOptions) -> Promise<OfflineValidateResult>`

Validates the stored license with Ed25519 signature verification.

```
ValidateOptions:
  online?: boolean          # Also check revocation with server (default: false)
  token?: string            # Validate specific token instead of stored one

OfflineValidateResult:
  valid: boolean            # Whether the license is valid
  claims?: LicenseClaims    # Decoded claims if valid
  reason?: string           # Reason for invalidity
```

**Behavior:**
- If no token stored, returns `{ valid: false }` (no reason - this is not an error)
- Verifies Ed25519 signature using the public key
- Verifies `device_id` in claims matches current device
- Checks `license_exp` for expiration
- If `online: true`, also calls `/validate` endpoint to check revocation
- Does NOT throw on invalid - returns `{ valid: false, reason: "..." }`
- `reason` is only set for actual errors (expired, revoked, mismatch), not for "no license yet"

---

### `isLicensed() -> Promise<boolean>` (async)

Returns true if there's a valid, signature-verified license.

**Behavior:**
- Calls `validate()` internally
- Returns `result.valid`

---

### `sync() -> Promise<SyncResult>`

Syncs with server and validates the license. Recommended for online/subscription apps.

```
SyncResult:
  valid: boolean            # Whether the license is valid
  claims?: LicenseClaims    # Decoded claims if valid
  synced: boolean           # Whether the server was reached
  offline: boolean          # Whether operating in offline mode
  reason?: string           # Reason for invalidity
```

**Behavior:**
1. If no token stored, returns `{ valid: false }` (no reason - this is not an error)
2. Verifies Ed25519 signature locally
3. Verifies `device_id` in claims matches current device
4. Tries to reach server to check for updates (renewals, revocation)
5. Refreshes token if server has newer expiration dates
6. Falls back to offline validation if server unreachable
- Does NOT throw for network failures - always returns a result
- Use `synced` to know if server was contacted
- Use `offline` to show "offline mode" indicator to users
- `reason` is only set for actual errors, not for "no license yet"

---

### `importToken(token: string) -> Promise<ImportResult>`

Imports a JWT token directly (offline activation).

```
ImportResult:
  valid: boolean            # Whether the token was valid and imported
  claims?: LicenseClaims    # Decoded claims if valid
  reason?: string           # Reason for invalidity
```

**Behavior:**
- Verifies Ed25519 signature using the public key
- Verifies `device_id` in claims matches current device
- Checks `license_exp` for expiration
- Stores token if valid
- Does NOT require network - fully offline operation
- Use for: clipboard paste, QR code scan, file import, enterprise distribution

---

## Quick License Queries

Sync convenience methods for reading claims after validation. Call `validate()` first, then use these for fast access.

### `getLicense() -> LicenseClaims | null`

Returns the decoded JWT claims, or null if no token.

```
LicenseClaims:
  # Standard JWT claims
  iss: string               # Issuer ("paycheck")
  sub: string               # Subject (license_id)
  aud: string               # Audience (project name, for debugging)
  jti: string               # JWT ID (unique per device activation)
  iat: number               # Issued at (Unix timestamp)
  exp: number               # JWT expiration (~1 hour). Used for token freshness and
                            # revocation propagation. NOT for license validity - see license_exp.
                            # Expired JWTs can still be refreshed if the license is valid.

  # Paycheck claims
  license_exp: number | null  # When license ACCESS ends (null = perpetual/never expires).
                              # This is the business logic expiration - check this for "is user licensed?"
  updates_exp: number | null  # When VERSION ACCESS ends (null = all versions covered).
                              # Check this against your app's build timestamp for "can user use this version?"
  tier: string                # Product tier (e.g., "free", "pro", "enterprise")
  features: string[]          # Enabled feature flags for hasFeature() checks
  device_id: string           # Device identifier (verified against current device)
  device_type: "uuid" | "machine"
  product_id: string          # Product UUID
```

---

### `hasFeature(feature: string) -> boolean`

Checks if the license includes a specific feature.

**Behavior:**
- Returns false if no license
- Case-sensitive match against `features` array

---

### `getTier() -> string | null`

Returns the current tier, or null if no license.

---

### `isExpired() -> boolean`

Checks if `license_exp` has passed.

**Behavior:**
- Returns true if no license (conservative default)
- Returns false if `license_exp` is null (perpetual)
- Compares against current time

---

### `coversVersion(versionTimestamp: number) -> boolean`

Checks if `updates_exp` covers the given version timestamp.

**Behavior:**
- Returns false if no license
- Returns true if `updates_exp` is null (all versions covered)
- Returns `versionTimestamp <= updates_exp`

---

## Online Operations

### `validateOnline() -> Promise<ValidateResult>` (Rust only)

Performs online validation (checks revocation, updates last_seen).

```
ValidateResult:
  valid: boolean
  licenseExp?: number | null
  updatesExp?: number | null
```

**Behavior:**
- GET `/validate` with `public_key` and `jti` from token
- Updates last_seen timestamp on server
- Does NOT throw on invalid - returns `{ valid: false }`

---

### `getLicenseInfo() -> Promise<LicenseInfo>`

Gets full license information including devices.

```
LicenseInfo:
  status: "active" | "expired" | "revoked"
  createdAt: number
  expiresAt: number | null
  updatesExpiresAt: number | null
  activationCount: number
  activationLimit: number
  deviceCount: number
  deviceLimit: number
  devices: DeviceInfo[]

DeviceInfo:
  deviceId: string
  deviceType: "uuid" | "machine"
  name: string | null
  activatedAt: number
  lastSeenAt: number
```

**Behavior:**
- GET `/license` with JWT token in Authorization header
- Includes `public_key` in query params
- Server extracts license from JWT's JTI (device → license relationship)
- Throws if no token stored

---

### `deactivate() -> Promise<DeactivateResult>`

Self-deactivates the current device.

```
DeactivateResult:
  deactivated: boolean
  remainingDevices: number
```

**Behavior:**
- POST `/devices/deactivate` with JWT in Authorization header
- Clears stored token after successful deactivation
- JWT's JTI proves device identity

---

## Feedback & Crash Reporting

SDKs provide passthrough feedback collection and crash reporting. Data is forwarded to the developer via their configured webhook or email - Paycheck does not store this data.

### `submitFeedback(options: FeedbackOptions) -> Promise<void>`

Submits user feedback to the developer.

```
FeedbackOptions:
  message: string             # Required. The feedback message
  email?: string              # Optional. User's email for follow-up
  type?: FeedbackType         # Optional. "bug" | "feature" | "question" | "other" (default: "other")
  priority?: Priority         # Optional. "low" | "medium" | "high"
  appVersion?: string         # Optional. App version
  os?: string                 # Optional. Operating system (auto-detected if not provided)
  metadata?: object           # Optional. Arbitrary metadata
```

**Behavior:**
- POST to `/feedback` with JWT in Authorization header
- Auto-detects OS if not provided
- Server extracts license context (tier, features, device_id) from JWT
- Forwards to developer's configured webhook/email
- Throws if no token stored or delivery fails

---

### `reportCrash(options: CrashOptions) -> Promise<void>`

Reports a crash or error to the developer.

```
CrashOptions:
  errorType: string           # Required. Error type/class (e.g., "TypeError", "NullPointerException")
  errorMessage: string        # Required. Error message
  stackTrace?: StackFrame[]   # Optional. Parsed stack trace
  fingerprint?: string        # Optional. Deduplication key (auto-generated if not provided)
  userEmail?: string          # Optional. User's email for follow-up
  appVersion?: string         # Optional. App version
  os?: string                 # Optional. Operating system (auto-detected if not provided)
  metadata?: object           # Optional. Arbitrary metadata
  breadcrumbs?: Breadcrumb[]  # Optional. Event trail leading up to crash

StackFrame:
  file?: string               # Source file path
  function?: string           # Function name
  line?: number               # Line number
  column?: number             # Column number

Breadcrumb:
  timestamp: number           # Unix timestamp in ms
  category?: string           # Event category (ui, http, console, navigation)
  message: string             # Event description
```

**Behavior:**
- POST to `/crash` with JWT in Authorization header
- Auto-detects OS if not provided
- Auto-generates fingerprint from error type + message + top stack frame if not provided
- Server extracts license context from JWT
- Forwards to developer's configured webhook/email
- Throws if no token stored or delivery fails

---

### `reportError(error: Error, options?: CrashOptions) -> Promise<void>`

Convenience method for reporting errors with automatic type extraction.

**Behavior:**
- Extracts error type and message from the error object
- Calls `reportCrash()` with the extracted info
- Options override auto-extracted values if provided

**Example (TypeScript):**
```typescript
try {
  await riskyOperation();
} catch (e) {
  await paycheck.reportError(e as Error, { appVersion: "1.2.3" });
}
```

**Example (Rust):**
```rust
if let Err(e) = process() {
    paycheck.report_error(&*e, None)?;
}
```

---

### Helper Functions

#### `generateFingerprint(errorType: string, errorMessage: string, stackTrace?: StackFrame[]) -> string`

Creates a SHA-256 based fingerprint for crash deduplication.

**Behavior:**
- Hashes error type + message + top stack frame (file, function, line)
- Returns first 16 hex characters
- Consistent fingerprints allow grouping duplicate crashes

---

#### `sanitizePath(path: string) -> string`

Sanitizes file paths by replacing home directory with `~`.

**Behavior:**
- Replaces `$HOME` or `%USERPROFILE%` with `~`
- Useful for stack trace sanitization before sending crash reports
- Especially important for Electron apps where paths contain user home directories

**Example (TypeScript):**
```typescript
import { sanitizePath } from '@anthropic/paycheck-sdk';

sanitizePath('/Users/john/projects/myapp/src/main.ts')
// Returns: '~/projects/myapp/src/main.ts'
```

---

#### `sanitizeStackTrace(frames: StackFrame[]) -> StackFrame[]` (TypeScript only)

Convenience function to sanitize all file paths in a stack trace.

**Example:**
```typescript
import { sanitizeStackTrace } from '@anthropic/paycheck-sdk';

const sanitizedFrames = sanitizeStackTrace(stackFrames);
await paycheck.reportCrash({
  errorType: 'Error',
  errorMessage: 'Something went wrong',
  stackTrace: sanitizedFrames,
});
```

---

#### `detectOS() -> string`

Returns the current operating system.

**Behavior:**
- Returns values like "linux", "macos", "windows", "ios", "android"
- Used by `submitFeedback()` and `reportCrash()` when `os` is not provided

---

## Storage Adapter Interface

SDKs must support custom storage adapters:

```
StorageAdapter:
  get(key: string) -> string | null | Promise<string | null>
  set(key: string, value: string) -> void | Promise<void>
  remove(key: string) -> void | Promise<void>
```

**Storage Keys:**
- `paycheck:token` - JWT token
- `paycheck:device_id` - Device identifier

Note: License keys are intentionally NOT stored to prevent exposure via XSS attacks. The JWT contains everything needed for validation and the server can derive license info from the JWT's JTI.

**Default Implementations:**
- Web: `localStorage`
- Desktop: App data directory file (e.g., `~/.config/appname/paycheck.json`)
- Testing: In-memory

---

## Error Handling

All SDKs should use consistent error types:

```
PaycheckError:
  code: string              # Machine-readable error code
  message: string           # Human-readable message
  statusCode?: number       # HTTP status code (for API errors)

Error Codes:
  NO_TOKEN              # No token stored (used by methods that throw, not validate/sync)
  TOKEN_EXPIRED         # Token's JWT exp has passed (try refresh)
  LICENSE_EXPIRED       # License exp has passed
  LICENSE_REVOKED       # License has been revoked
  DEVICE_LIMIT_REACHED  # Cannot activate more devices
  ACTIVATION_LIMIT_REACHED # Cannot activate license anymore
  INVALID_LICENSE_KEY   # License key not found
  INVALID_CODE          # Redemption code invalid or expired
  NETWORK_ERROR         # Network request failed
  VALIDATION_ERROR      # Invalid request parameters or signature verification failed
```

**Note on "no license" vs errors:**

`validate()` and `sync()` return `{ valid: false }` without a `reason` when no token is stored. This is intentional - having no license yet is not an error, it's the initial state. The `reason` field is only populated for actual problems (expired, revoked, device mismatch).

```
// Pattern for handling results:
if (!result.valid) {
  if (result.reason) {
    showError(result.reason);   // Actual problem
  } else {
    showActivationPrompt();      // Just needs to activate
  }
}
```

---

## Device ID Generation

### Web (UUID type)
- Generate random UUID v4
- Store in localStorage
- Persists across page loads, clears on storage clear

### Desktop (Machine type)
- Derive from hardware identifiers:
  - macOS: IOPlatformSerialNumber
  - Linux: /etc/machine-id
  - Windows: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
- Hash the identifier for privacy
- Consistent across app reinstalls

---

## Implementation Notes

### JWT Signature Verification
- Decode JWT and verify Ed25519 signature using the public key
- Public key is provided at initialization time
- Verification is performed locally, enabling secure offline validation
- Use `@noble/ed25519` (TypeScript) or `ed25519-dalek` (Rust)

### Device ID Verification
- After signature verification, check that `device_id` in claims matches current device
- Prevents token theft: a JWT stolen from one device cannot be used on another
- Returns `{ valid: false, reason: "Device mismatch" }` on mismatch
- Applied in `validate()`, `sync()`, and `importToken()`

### Token Refresh Strategy
- If `autoRefresh` is true:
  - Check token's `exp` before API calls
  - If expired, call `refreshToken()` automatically
  - Retry the original call
- Refresh works for tokens up to 10 years old

### Offline Behavior
- `validate()` performs signature verification offline
- `isExpired()`, `hasFeature()`, `getTier()` work offline (no signature check)
- Only check `license_exp`, not JWT `exp`, for license validity
- JWT `exp` is for transport security, not license validity

### Thread Safety (Rust)
- Storage adapter must be `Send + Sync`
- Use `Arc<Mutex<>>` or `RwLock` for shared state
- Consider async storage for file I/O
