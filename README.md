# Paycheck

**Get paid for the software you build. Get back to building.**

Paycheck is licensing infrastructure for indie developers. One integration to accept payments and manage licenses. Validate licenses offline—no phone-home required. Built for the honest majority who just want a convenient way to pay and prove it.

## How It Works

```
Customer pays → Webhook creates license → User activates → JWT stored locally
```

After activation, the JWT contains everything needed for offline validation: tier, features, expiration—all signed with Ed25519. Your app validates locally. No server contact needed.

## Features

- **Offline by default** — Signed JWTs validate locally, no phone-home
- **Email-based recovery** — Lost access? Request activation code via email
- **Multi-tenant** — One server, many customers, isolated keys per project
- **Payment providers** — Stripe and LemonSqueezy supported
- **Device limits** — Optional concurrent device tracking
- **Audit logging** — Every action tracked in separate immutable database

## Quick Start

**Hosted service** — Get started at [paycheck.dev](https://paycheck.dev). See the [quickstart guide](https://paycheck.dev/docs/quickstart).

**Self-hosted:**

```bash
cargo build --release

# Configure master key (required)
openssl rand -base64 32 > master.key
chmod 400 master.key
export PAYCHECK_MASTER_KEY_FILE=./master.key
export BOOTSTRAP_OPERATOR_EMAIL=you@example.com

cargo run --release
```

See the [deployment guide](https://paycheck.dev/docs/self-hosted/deployment) for production setup.

## Documentation

- [Concepts](https://paycheck.dev/docs/concepts) — Architecture, JWT model, security
- [Quickstart](https://paycheck.dev/docs/quickstart) — Get up and running with the hosted service
- [SDK Integration](https://paycheck.dev/docs/sdk) — TypeScript and Rust SDK guides
- [API Reference](https://paycheck.dev/docs/api) — Public, operator, and organization endpoints
- [Self-Hosted Deployment](https://paycheck.dev/docs/self-hosted/deployment) — Production deployment guide

## SDKs

| SDK | Package | README |
|-----|---------|--------|
| TypeScript | `@paycheck/sdk` | [sdk/typescript](sdk/typescript) |
| Rust | `paycheck-sdk` | [sdk/rust](sdk/rust) |

## License

[Elastic License 2.0](LICENSE)
