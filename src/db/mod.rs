mod schema;
pub mod queries;

pub use schema::init_db;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn create_pool(database_path: &str) -> Result<DbPool, r2d2::Error> {
    let manager = SqliteConnectionManager::file(database_path);
    Pool::builder().max_size(10).build(manager)
}
