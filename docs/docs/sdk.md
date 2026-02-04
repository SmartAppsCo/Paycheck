---
sidebar_position: 4
---

# SDK Guide

Integrate Paycheck licensing into your application.

## Installation

### Rust

```bash
cargo add paycheck-sdk
```

### JavaScript/TypeScript

```bash
npm install @paycheck/sdk
```

## Quick Start

### Rust

```rust
use paycheck_sdk::{PaycheckClient, DeviceType};

// Initialize with your API endpoint and project public key
let client = PaycheckClient::builder()
    .api_url("https://api.yourdomain.com")
    .public_key(include_str!("../public_key.pem"))
    .build()?;

// Check for existing license on startup
if let Some(license) = client.load_license()? {
    if license.is_valid() {
        println!("Welcome back! Licensed for: {}", license.tier);
    } else if license.is_expired() {
        println!("License expired, attempting refresh...");
        client.refresh_license()?;
    }
} else {
    // No license found, prompt for activation
    show_activation_dialog();
}
```

### JavaScript

```typescript
import { PaycheckClient } from '@paycheck/sdk';

const client = new PaycheckClient({
  apiUrl: 'https://api.yourdomain.com',
  publicKey: PUBLIC_KEY,
});

// Check license status
const license = await client.loadLicense();
if (license?.isValid()) {
  console.log(`Licensed: ${license.tier}`);
}
```

## Activation Flow

### 1. User Enters Activation Code

After purchase, users receive an activation code via email (format: `PREFIX-XXXX-XXXX`).

```rust
// Activate with the code
let license = client.activate(
    "MYAPP-AB3D-EF5G",
    DeviceType::Machine,  // or DeviceType::Uuid for web
)?;

println!("Activated! Tier: {}", license.tier);
```

### 2. Automatic Refresh

The SDK automatically refreshes licenses before the JWT expires:

```rust
// Enable background refresh (recommended)
client.enable_auto_refresh()?;
```

### 3. Recovery Flow

If a user needs to reactivate (new device, lost data):

```rust
// Request new activation code sent to purchase email
client.request_activation_code("user@example.com")?;
// User receives email with new code, uses activate() again
```

## License Validation

### Local Validation (Offline)

```rust
let license = client.load_license()?;

// Check if license is valid (signature + not revoked + not expired)
if license.is_valid() {
    // Check tier for feature gating
    match license.tier.as_str() {
        "pro" => enable_pro_features(),
        "enterprise" => enable_enterprise_features(),
        _ => enable_basic_features(),
    }

    // Check feature flags
    if license.features.contains(&"export".to_string()) {
        enable_export();
    }
}
```

### Online Validation (Optional)

For apps that need real-time revocation checking:

```rust
// Validates against server, updates local cache
let is_valid = client.validate_online()?;
```

## Device Management

### Check Device Limits

```rust
let info = client.get_license_info()?;
println!("Devices: {}/{}", info.active_devices, info.max_devices);
```

### Self-Deactivation

Allow users to free up a device slot:

```rust
client.deactivate_current_device()?;
```

## Update Eligibility

Check if the current app version is covered by the license:

```rust
const BUILD_TIMESTAMP: i64 = 1704067200; // Set at compile time

if license.can_use_version(BUILD_TIMESTAMP) {
    // This version is covered
} else {
    // Prompt to renew for updates
    show_renewal_prompt();
}
```

## Error Handling

```rust
use paycheck_sdk::Error;

match client.activate(code, device_type) {
    Ok(license) => handle_success(license),
    Err(Error::InvalidCode) => show_error("Invalid activation code"),
    Err(Error::CodeExpired) => show_error("Code expired, request a new one"),
    Err(Error::DeviceLimitReached) => show_error("Too many devices activated"),
    Err(Error::Network(e)) => {
        // Offline - can't activate without network
        show_error("Network error, please try again")
    }
    Err(e) => show_error(&format!("Activation failed: {}", e)),
}
```

## Storage

### Rust (Desktop)

By default, the SDK stores licenses in:
- Linux: `~/.local/share/<app_name>/license.jwt`
- macOS: `~/Library/Application Support/<app_name>/license.jwt`
- Windows: `%APPDATA%\<app_name>\license.jwt`

### JavaScript (Web)

Licenses are stored in `localStorage` under the key `paycheck_license`.

### Custom Storage

```rust
let client = PaycheckClient::builder()
    .api_url("https://api.yourdomain.com")
    .public_key(PUBLIC_KEY)
    .storage(MyCustomStorage::new())
    .build()?;
```

## JWT Claims Reference

The license JWT contains:

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | License ID |
| `iss` | string | API endpoint |
| `aud` | string | Product ID |
| `exp` | number | JWT expiration (for refresh) |
| `iat` | number | Issued at |
| `jti` | string | Unique token ID |
| `license_exp` | number? | License expiration (null = perpetual) |
| `updates_exp` | number? | Updates expiration (null = all versions) |
| `tier` | string | Product tier |
| `features` | string[] | Enabled features |
| `device_id` | string | Device identifier |
| `device_type` | string | "uuid" or "machine" |
| `product_id` | string | Product ID |
