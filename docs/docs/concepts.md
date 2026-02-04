---
sidebar_position: 2
---

# Core Concepts

Deep dive into how Paycheck works.

## Offline-First Design

Paycheck is built around a simple principle: **after activation, your app should work without network access.**

The license is a signed JWT. Your app embeds the project's public key at build time and validates locally. No server round-trip needed.

```
┌─────────────────┐     ┌─────────────────┐
│   Your App      │     │  Paycheck API   │
│                 │     │                 │
│  ┌───────────┐  │     │  ┌───────────┐  │
│  │Public Key │  │     │  │Private Key│  │
│  └───────────┘  │     │  └───────────┘  │
│        │        │     │        │        │
│        ▼        │     │        ▼        │
│   Validates     │◄────│   Signs JWT     │
│   JWT locally   │     │                 │
└─────────────────┘     └─────────────────┘
```

## JWT Expiration Model

Paycheck uses three distinct expiration concepts:

### 1. Token Expiration (`exp`)

**Purpose:** Controls how quickly revocation propagates.

When a license is revoked, active tokens remain valid until their `exp` claim. The SDK automatically refreshes tokens before expiration, picking up revocations on refresh.

- **Default:** 1 hour
- **Trade-off:** Shorter = faster revocation propagation, more refresh traffic

### 2. License Expiration (`license_exp`)

**Purpose:** When the customer's access ends.

For subscription products, this is set to the end of the billing period. For perpetual licenses, it's null.

- **Null:** Perpetual access
- **Timestamp:** Access ends at this time

### 3. Updates Expiration (`updates_exp`)

**Purpose:** Version entitlement for perpetual licenses.

Compare against your app's build timestamp to determine if this license covers the current version.

```rust
const BUILD_TIMESTAMP: i64 = 1704067200;

if license.updates_exp.map_or(true, |exp| BUILD_TIMESTAMP <= exp) {
    // User can use this version
} else {
    // Prompt to renew for updates
}
```

- **Null:** Access to all versions forever
- **Timestamp:** Access to versions released before this time

## Device Identity

### UUID (Web/Browser)

For web applications. Generated once, stored in `localStorage`.

- **Pros:** Works everywhere, no special permissions
- **Cons:** Lost if localStorage cleared, not tied to hardware

### Machine ID (Desktop)

Hardware-derived identifier, stable across reinstalls.

- **Pros:** Survives app reinstalls, tied to physical machine
- **Cons:** Requires read access to system identifiers

The SDK handles this automatically:

```rust
// Desktop apps
client.activate(code, DeviceType::Machine)?;

// Web apps
client.activate(code, DeviceType::Uuid)?;
```

## Email-Based Activation

Paycheck uses **no permanent license keys**. Instead:

1. Customer purchases → receives activation code via email
2. Code is short-lived (30 min TTL)
3. Code format: `PREFIX-XXXX-XXXX` (40 bits entropy)
4. Codes are single-use

### Recovery Flow

When a customer needs to reactivate (new device, lost data):

1. User provides purchase email
2. System looks up license by email hash (SHA-256)
3. New activation code sent to that email
4. User activates with new code

No license keys to manage, lose, or share.

## Device Limits

Checked server-side during activation, not stored in the JWT.

```
Activation Request
        │
        ▼
┌───────────────────┐
│ Check device count│
│ against limit     │
└───────────────────┘
        │
        ├── Under limit → Create device, issue JWT
        │
        └── At limit → Return error
```

### Self-Deactivation

Users can free up device slots:

```rust
client.deactivate_current_device()?;
// Requires the JWT (proves device identity via JTI)
```

### Remote Deactivation

Org admins can deactivate devices via the API (for lost device recovery).

## Revocation

### Token Revocation

Individual JWTs can be revoked by JTI. Tracked per-license.

### License Revocation

Revoked licenses:
- Cannot refresh tokens
- Cannot activate new devices
- Existing tokens remain valid until `exp`

### Revocation Propagation

Since tokens are validated locally, revocation isn't instant:

1. License revoked via admin API
2. Existing tokens still valid until `exp`
3. SDK attempts refresh → gets revoked error
4. App shows "license revoked" state

For apps requiring faster revocation, use online validation:

```rust
// Check revocation status with server
if !client.validate_online()? {
    show_license_revoked_ui();
}
```

## Multi-Tenant Architecture

```
Operators (Paycheck platform admins)
    │
    └── Organizations (indie dev companies)
            │
            ├── Members (owner, admin, member roles)
            │
            ├── Payment Config (Stripe/LemonSqueezy keys)
            │
            └── Projects (each software product)
                    │
                    ├── Products (pricing tiers)
                    │       │
                    │       └── Licenses → Devices
                    │
                    └── Ed25519 key pair
```

### Isolation

- Each project has its own signing key pair
- Keys are encrypted at rest (envelope encryption)
- Organizations configure their own payment providers
- Audit logs are per-organization

## Envelope Encryption

Sensitive data (private keys, payment credentials) is encrypted at rest:

```
Master Key (file)
       │
       ▼ HKDF-SHA256
Per-Entity DEK (derived from entity ID)
       │
       ▼ AES-256-GCM
Encrypted Data (stored in SQLite)
```

- **Master key:** Loaded from file, strict permissions (0400)
- **DEK derivation:** Uses entity ID as info parameter
- **Storage format:** `ENC1` || nonce || ciphertext

## Rate Limiting

Protects against abuse at multiple tiers:

| Tier | Limit | Endpoints |
|------|-------|-----------|
| Strict | 10 RPM | `/buy`, `/activation/request-code` |
| Standard | 30 RPM | `/redeem`, `/validate`, etc. |
| Relaxed | 60 RPM | `/health` |
| Org Ops | 3000 RPM | `/orgs/*` |

Limits are per-IP. Exceeded limits return `429 Too Many Requests`.

## Philosophy

Paycheck is a **payment flow with cryptographic receipts**, not DRM.

Design principles:

1. **Serve the honest majority** - The 95% who just want to pay and use your software
2. **Offline-first** - Network should be optional after activation
3. **No security theater** - Skip anti-tampering, obfuscation, or "protection" that only annoys legitimate users
4. **Privacy-respecting** - Store email hashes, not emails. No tracking.
5. **Developer-friendly** - Simple API, clear documentation, predictable behavior
