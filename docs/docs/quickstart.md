---
sidebar_position: 3
---

# Quick Start

Get licensing working in your app in under 10 minutes using [paycheck.dev](https://paycheck.dev).

## 1. Create an Account

Sign up at [paycheck.dev](https://paycheck.dev) and create your organization.

## 2. Create a Project

Each app you sell gets its own project. Projects have:
- Unique Ed25519 signing keys (auto-generated)
- Payment provider configuration
- Products (pricing tiers)

In the console:
1. Go to **Projects** → **New Project**
2. Enter your app name
3. Set the redirect URL (where customers land after payment)

## 3. Configure Payment Provider

Connect Stripe or LemonSqueezy to receive payments.

### Stripe

1. Go to **Project Settings** → **Payments**
2. Enter your Stripe secret key
3. Add webhook endpoint: `https://api.paycheck.dev/webhook/stripe`
4. Copy the webhook signing secret to Paycheck

### LemonSqueezy

1. Go to **Project Settings** → **Payments**
2. Enter your LemonSqueezy API key
3. Add webhook endpoint: `https://api.paycheck.dev/webhook/lemonsqueezy`
4. Copy the webhook signing secret to Paycheck

## 4. Create a Product

Products are your pricing tiers (free, pro, enterprise, etc.).

1. Go to **Products** → **New Product**
2. Set name, tier, and features
3. Link to your Stripe Price ID or LemonSqueezy Variant ID

## 5. Get Your Public Key

Download your project's public key from **Project Settings** → **Keys**.

This key is embedded in your app at build time for offline JWT validation.

## 6. Integrate the SDK

### Rust

```bash
cargo add paycheck-sdk
```

```rust
use paycheck_sdk::{PaycheckClient, DeviceType};

let client = PaycheckClient::builder()
    .api_url("https://api.paycheck.dev")
    .public_key(include_str!("../public_key.pem"))
    .build()?;

// Check for existing license
if let Some(license) = client.load_license()? {
    if license.is_valid() {
        println!("Licensed: {}", license.tier);
    }
}

// Activate with code from email
let license = client.activate("MYAPP-AB3D-EF5G", DeviceType::Machine)?;
```

### JavaScript

```bash
npm install @anthropic/paycheck-sdk
```

```typescript
import { PaycheckClient } from '@anthropic/paycheck-sdk';

const client = new PaycheckClient({
  apiUrl: 'https://api.paycheck.dev',
  publicKey: PUBLIC_KEY,
});

// Check license
const license = await client.loadLicense();
if (license?.isValid()) {
  console.log(`Licensed: ${license.tier}`);
}

// Activate
const newLicense = await client.activate('MYAPP-AB3D-EF5G', 'uuid');
```

## 7. Add Buy Button

Link customers to your payment page:

```html
<a href="https://api.paycheck.dev/buy?product_id=YOUR_PRODUCT_ID">
  Buy Now
</a>
```

Or use the SDK:

```rust
let checkout_url = client.get_checkout_url("prod_xxxxx")?;
```

## What Happens Next

1. Customer clicks buy → redirected to Stripe/LemonSqueezy
2. Customer pays → webhook creates license
3. Customer redirected to your app with activation code
4. Customer enters code → SDK exchanges for JWT
5. App validates JWT locally → customer is licensed

## Next Steps

- **[SDK Guide](/sdk)** — Full SDK documentation
- **[Console Guide](/console)** — Managing licenses and customers
- **[Core Concepts](/concepts)** — Understanding JWTs and expiration
