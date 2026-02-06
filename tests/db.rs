//! Database tests - CRUD operations, licensing, devices, soft delete

#[path = "db/crud.rs"]
mod crud;

#[path = "db/license.rs"]
mod license;

#[path = "db/device.rs"]
mod device;

#[path = "db/soft_delete.rs"]
mod soft_delete;

#[path = "db/from_row_panic.rs"]
mod from_row_panic;

#[path = "db/api_key_atomicity.rs"]
mod api_key_atomicity;

#[path = "db/service_config_inheritance.rs"]
mod service_config_inheritance;

#[path = "db/bulk_license_atomicity.rs"]
mod bulk_license_atomicity;

#[path = "db/tags.rs"]
mod tags;

#[path = "db/payment_session.rs"]
mod payment_session;
