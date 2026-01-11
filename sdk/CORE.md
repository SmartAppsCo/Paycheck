# Paycheck SDK Core Specification

This document defines the core functions that every Paycheck SDK must implement. All SDKs should maintain consistent naming, behavior, and error handling.

## Design Principles

1. **Offline-first**: License checks work without network access, with Ed25519 signature verification
2. **Minimal config**: Just `publicKey` to get started
3. **Sensible defaults**: Auto-generate device IDs, use localStorage/files
4. **Override capability**: Custom storage, device IDs when needed
5. **Type-safe**: Strong typing for all public APIs
6. **Secure**: Ed25519 signature verification ensures JWT authenticity offline

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

Exchanges a short-lived redemption code for a JWT.

**Behavior:**
- POST to `/redeem` with code in JSON body (not URL params for security)
- Includes `public_key`, `device_id`, `device_type` in request body
- Redemption codes expire in 30 minutes and are single-use

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
  exp: number               # Expires (Unix timestamp, ~1 hour)

  # Paycheck claims
  license_exp: number | null  # When license access ends
  updates_exp: number | null  # When version access ends
  tier: string                # Product tier
  features: string[]          # Enabled features
  device_id: string           # Device identifier
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
