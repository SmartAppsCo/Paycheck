# Bruno Collection Organization

This document describes the conventions used to organize the Paycheck API collection in Bruno.

## Folder Order

Top-level folders are ordered to follow a logical workflow from customer-facing to admin operations:

| Seq | Folder | Purpose |
|-----|--------|---------|
| 1 | Public | Customer-facing endpoints |
| 2 | Webhooks | Payment provider webhooks |
| 3 | Organization API | Org member operations |
| 4 | Operator API | Platform admin operations |

## Request Ordering Convention

Within each folder, requests follow a consistent CRUD pattern:

1. **List** - View existing resources
2. **Create** - Make new resources
3. **Get** - View single resource details
4. **Update** - Modify existing resources
5. **Delete** - Soft-delete resources
6. **Restore** - Restore soft-deleted resources
7. **Hard Delete** - Permanent deletion (if applicable)
8. **Special operations** - Resource-specific actions (Revoke, Send Code, etc.)

## Public API Order

Follows the customer journey:

1. Health Check
2. Buy (initiate payment)
3. Callback (post-payment redirect)
4. Redeem with Code (activate license)
5. Request Activation Code (recovery)
6. Refresh Token
7. Validate License
8. License Info
9. Deactivate Device

## Organization API Subfolders

| Seq | Folder | Contents |
|-----|--------|----------|
| 1 | Members | Org member CRUD + API keys |
| 2 | Projects | Project CRUD + project members |
| 3 | Products | Product CRUD + Payment Config subfolder |
| 4 | Licenses | License CRUD + Revoke, Send Code, Deactivate |
| 5 | Audit Logs | Query audit logs |
| 6 | Impersonation | Operator impersonation examples |
| 7 | (root file) | Get Payment Config (Masked) |

## Operator API Grouping

Requests are grouped by resource type:

| Seq Range | Resource |
|-----------|----------|
| 1-7 | Users |
| 8-15 | Organizations |
| 16-20 | Operators |
| 21-23 | Operator API Keys |
| 24-26 | Utilities (Lookup, Audit Logs) |

## How Ordering Works

Bruno uses `folder.bru` files and `meta { seq: N }` blocks to control order:

**Folder ordering** - Create a `folder.bru` file in the folder:
```
meta {
  name: Folder Name
  seq: 1
}
```

**Request ordering** - Each `.bru` file has a meta block:
```
meta {
  name: Request Name
  type: http
  seq: 1
}
```

Lower `seq` values appear first in the sidebar.

## Adding New Requests

1. Determine which folder the request belongs in
2. Follow the CRUD ordering convention (List=1, Create=2, Get=3, etc.)
3. For new operations that don't fit CRUD, add them at the end
4. If inserting between existing requests, renumber subsequent requests

## Adding New Folders

1. Create the folder
2. Add a `folder.bru` file with appropriate `seq` value
3. Renumber sibling folders if inserting in the middle
