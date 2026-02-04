---
sidebar_position: 1
slug: /
---

# Paycheck

Offline-first licensing for indie developers.

Paycheck is a payment flow with cryptographic receipts (signed JWTs) that work offline by default, with optional online features (validation, revocation, device limits) for apps that need them.

## Choose Your Path

### Hosted (paycheck.dev)

The fastest way to get started. We handle the infrastructure, you focus on your app.

- **[Quick Start](/quickstart)** — Sign up and integrate in minutes
- **[Console Guide](/console)** — Manage projects, products, and licenses

### Self-Hosted

Run Paycheck on your own infrastructure. Full control, same features.

- **[Deployment Guide](/self-hosted/deployment)** — Production deployment instructions

## Core Documentation

These apply to both hosted and self-hosted:

- **[SDK Guide](/sdk)** — Integrate licensing into your app
- **[API Reference](/api)** — Complete HTTP API documentation
- **[Core Concepts](/concepts)** — How Paycheck works under the hood

## How It Works

1. **Customer pays** via Stripe or LemonSqueezy
2. **Webhook creates license** with email hash (no PII stored)
3. **Customer receives activation code** (30 min TTL, sent via email)
4. **Customer activates** in your app, receives signed JWT
5. **Your app validates locally** using the public key embedded at build time

No server contact needed after activation. Revocation propagates within the JWT's `exp` window (typically 1 hour).

## Architecture

```
Payment Provider (Stripe/LemonSqueezy)
        ↓ webhook
    Paycheck API
        ↓ creates
      License → Activation Code → Email
        ↓ activates
    Signed JWT ← Your App validates locally
```

Each project gets its own Ed25519 key pair. The private key never leaves the server. Embed the public key in your app at build time.
