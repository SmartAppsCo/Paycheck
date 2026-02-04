---
sidebar_position: 1
sidebar_label: Overview
---

# Console

The Paycheck Console at [console.paycheck.dev](https://console.paycheck.dev) is where you manage your organization, projects, products, and licenses.

## Dashboard

Your home screen shows:
- Active licenses across all projects
- Recent transactions
- Revenue overview

## Organizations

Organizations are your billing entity. Most users have one organization, but agencies or holding companies might have multiple.

Each organization has:
- **Members** — Team access with roles (owner, admin, member)
- **Payment config** — Shared Stripe/LemonSqueezy credentials
- **Projects** — Your software products

## Projects

Each app you sell is a project. Projects contain:
- **Products** — Pricing tiers (free, pro, enterprise)
- **Licenses** — Customer entitlements
- **Keys** — Ed25519 signing keys (auto-generated)
- **Settings** — Redirect URLs, email configuration, webhooks

### Project Settings

| Setting | Description |
|---------|-------------|
| `redirect_url` | Where customers land after payment |
| `email_from` | Sender address for activation emails |
| `feedback_webhook_url` | Receive user feedback |
| `crash_webhook_url` | Receive crash reports |

## Products

Products define what you're selling:

| Field | Description |
|-------|-------------|
| `name` | Display name (e.g., "Pro Plan") |
| `tier` | Tier identifier used in JWT (e.g., "pro") |
| `features` | Feature flags included (e.g., ["export", "sync"]) |
| `stripe_price_id` | Stripe Price ID for checkout |
| `lemon_variant_id` | LemonSqueezy Variant ID |

## Licenses

Licenses are created automatically when customers pay. You can also create them manually for:
- Beta testers
- Lifetime deals
- Support cases

### License Actions

- **Send activation code** — Generate and email a new code
- **Revoke** — Disable the license
- **View devices** — See activated devices
- **Deactivate device** — Free up a device slot

## Transactions

Track revenue with full transaction history:
- Purchases, renewals, refunds
- Filter by product, date range, payment provider
- Export for accounting

## API Keys

Create API keys for programmatic access:
- Scoped to specific projects (optional)
- Set expiration dates
- Revoke anytime

See the [API Reference](/api) for endpoint documentation.
