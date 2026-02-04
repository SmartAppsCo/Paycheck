---
sidebar_position: 5
---

# API Reference

Complete reference for the Paycheck HTTP API.

## Authentication

### Public Endpoints

No authentication required. Called by end-user applications.

### Admin Endpoints

Use Bearer token authentication:

```
Authorization: Bearer pc_xxxxxxxxxxxx
```

API keys are created via the operator or org member API.

## Public Endpoints

### POST /buy

Initiate a payment session.

**Request:**
```json
{
  "product_id": "prod_xxxxx"
}
```

**Response:** Redirects to Stripe/LemonSqueezy checkout.

---

### GET /callback

Post-payment redirect. Returns activation code.

**Query Parameters:**
- `session_id` - Stripe session ID, or
- `order_id` - LemonSqueezy order ID

**Response:** Redirects to project's `redirect_url` with:
- `code` - Activation code
- `project_id` - Project ID
- `status` - "success" or "error"

---

### POST /redeem

Exchange activation code for JWT.

**Request:**
```json
{
  "code": "MYAPP-AB3D-EF5G",
  "device_id": "machine-id-hash",
  "device_type": "machine"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJFZDI1NTE5...",
  "expires_at": 1704070800
}
```

---

### POST /activation/request-code

Request activation code sent to purchase email.

**Request:**
```json
{
  "email": "user@example.com",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

**Response:**
```json
{
  "message": "If a license exists for this email, a code has been sent"
}
```

Rate limited to 3 requests per email per hour.

---

### POST /refresh

Refresh an existing JWT.

**Headers:**
```
Authorization: Bearer <current_jwt>
```

**Response:**
```json
{
  "token": "eyJhbGciOiJFZDI1NTE5...",
  "expires_at": 1704070800
}
```

---

### GET /license

Get license info from JWT.

**Query Parameters:**
- `token` - The JWT
- `public_key` - Project public key (for verification)

**Response:**
```json
{
  "valid": true,
  "license_id": "lic_xxxxx",
  "tier": "pro",
  "features": ["export", "sync"],
  "license_exp": null,
  "updates_exp": 1735689600,
  "device_id": "machine-id-hash",
  "device_type": "machine"
}
```

---

### POST /validate

Online license validation.

**Headers:**
```
Authorization: Bearer <jwt>
```

**Response:**
```json
{
  "valid": true,
  "revoked": false,
  "license_exp": null
}
```

---

### POST /devices/deactivate

Self-deactivate current device.

**Headers:**
```
Authorization: Bearer <jwt>
```

**Response:**
```json
{
  "message": "Device deactivated"
}
```

---

### POST /feedback

Submit user feedback.

**Headers:**
```
Authorization: Bearer <jwt>
```

**Request:**
```json
{
  "message": "Great app!",
  "type": "feedback",
  "email": "user@example.com",
  "app_version": "1.2.3"
}
```

---

### POST /crash

Report crash/error.

**Headers:**
```
Authorization: Bearer <jwt>
```

**Request:**
```json
{
  "error_type": "panic",
  "error_message": "index out of bounds",
  "stack_trace": "...",
  "app_version": "1.2.3"
}
```

---

## Webhook Endpoints

### POST /webhook/stripe

Stripe webhook handler. Configure in Stripe Dashboard.

**Events handled:**
- `checkout.session.completed` - Creates license
- `invoice.paid` - Records renewal transaction
- `charge.refunded` - Records refund transaction

---

### POST /webhook/lemonsqueezy

LemonSqueezy webhook handler.

**Events handled:**
- `order_created` - Creates license
- `subscription_payment_success` - Records renewal
- `order_refunded` - Records refund

---

## Operator API

Requires operator-level API key.

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/operators/users` | Create user |
| GET | `/operators/users` | List users |
| GET | `/operators/users?email={email}` | Find by email |
| GET | `/operators/users/{id}` | Get user |
| PUT | `/operators/users/{id}` | Update user |
| DELETE | `/operators/users/{id}` | Delete user |

### Organizations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/operators/organizations` | Create org |
| GET | `/operators/organizations` | List orgs |
| GET | `/operators/organizations/{id}` | Get org |
| PUT | `/operators/organizations/{id}` | Update org |
| DELETE | `/operators/organizations/{id}` | Delete org |

### Operators

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/operators` | Create operator |
| GET | `/operators` | List operators |
| GET | `/operators/{user_id}` | Get operator |
| PUT | `/operators/{user_id}` | Update operator |
| DELETE | `/operators/{user_id}` | Remove operator |

### API Keys (for Users)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/operators/users/{user_id}/api-keys` | Create key |
| GET | `/operators/users/{user_id}/api-keys` | List keys |
| DELETE | `/operators/users/{user_id}/api-keys/{key_id}` | Revoke key |

### Audit Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/operators/audit-logs` | Query logs (JSON) |
| GET | `/operators/audit-logs/text` | Query logs (plain text) |

---

## Organization API

Requires org member API key.

### Members

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/orgs/{org_id}/members` | Add member |
| GET | `/orgs/{org_id}/members` | List members |
| GET | `/orgs/{org_id}/members/{user_id}` | Get member |
| PUT | `/orgs/{org_id}/members/{user_id}` | Update member |
| DELETE | `/orgs/{org_id}/members/{user_id}` | Remove member |

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/orgs/{org_id}/projects` | Create project |
| GET | `/orgs/{org_id}/projects` | List projects |
| GET | `/orgs/{org_id}/projects/{id}` | Get project |
| PUT | `/orgs/{org_id}/projects/{id}` | Update project |
| DELETE | `/orgs/{org_id}/projects/{id}` | Delete project |

### Products

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/orgs/{org_id}/projects/{id}/products` | Create product |
| GET | `/orgs/{org_id}/projects/{id}/products` | List products |
| GET | `/orgs/{org_id}/projects/{id}/products/{pid}` | Get product |
| PUT | `/orgs/{org_id}/projects/{id}/products/{pid}` | Update product |
| DELETE | `/orgs/{org_id}/projects/{id}/products/{pid}` | Delete product |

### Licenses

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/orgs/{org_id}/projects/{id}/licenses` | Create license |
| GET | `/orgs/{org_id}/projects/{id}/licenses` | List licenses |
| GET | `/orgs/{org_id}/projects/{id}/licenses/{lid}` | Get license |
| PATCH | `/orgs/{org_id}/projects/{id}/licenses/{lid}` | Update license |
| POST | `/orgs/{org_id}/projects/{id}/licenses/{lid}/revoke` | Revoke license |
| POST | `/orgs/{org_id}/projects/{id}/licenses/{lid}/send-code` | Send activation code |

**Query filters for list:**
- `email` - Filter by purchase email
- `payment_provider_order_id` - Filter by order ID

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| DELETE | `/orgs/{org_id}/projects/{id}/licenses/{lid}/devices/{did}` | Deactivate device |

### Transactions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/orgs/{org_id}/transactions` | List org transactions |
| GET | `/orgs/{org_id}/transactions/stats` | Org revenue stats |
| GET | `/orgs/{org_id}/projects/{id}/transactions` | List project transactions |
| GET | `/orgs/{org_id}/projects/{id}/transactions/stats` | Project revenue stats |
| GET | `/orgs/{org_id}/projects/{id}/transactions/{tid}` | Get transaction |
| GET | `/orgs/{org_id}/projects/{id}/licenses/{lid}/transactions` | License transactions |

---

## Operator Impersonation

Operators can access org endpoints on behalf of members:

```
GET /orgs/{org_id}/members
Authorization: Bearer pc_operator_key
X-On-Behalf-Of: {user_id}
```

Requires `admin` or `owner` operator role. The impersonated user must be a member of the org.

---

## Error Responses

All errors return JSON:

```json
{
  "error": "invalid_code",
  "message": "Activation code is invalid or expired"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_code` | 400 | Invalid activation code |
| `code_expired` | 400 | Activation code expired |
| `device_limit_reached` | 400 | Max devices activated |
| `license_revoked` | 400 | License has been revoked |
| `unauthorized` | 401 | Missing or invalid auth |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Resource not found |
| `rate_limited` | 429 | Too many requests |

---

## Rate Limits

| Tier | Default RPM | Endpoints |
|------|-------------|-----------|
| Strict | 10 | `/buy`, `/activation/request-code` |
| Standard | 30 | `/callback`, `/redeem`, `/validate`, etc. |
| Relaxed | 60 | `/health` |
| Org Ops | 3000 | `/orgs/*` |

Rate limits are per-IP. Returns `429 Too Many Requests` when exceeded.
