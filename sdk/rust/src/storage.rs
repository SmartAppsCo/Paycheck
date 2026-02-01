//! Storage adapters for the Paycheck SDK

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

/// Storage keys
pub mod keys {
    pub const TOKEN: &str = concat!("paycheck:", "token");
    pub const DEVICE_ID: &str = concat!("paycheck:", "device_id");
}

/// Storage adapter trait for custom storage implementations
pub trait StorageAdapter: Send + Sync {
    /// Get a value by key
    fn get(&self, key: &str) -> Option<String>;

    /// Set a value by key
    fn set(&self, key: &str, value: &str);

    /// Remove a value by key
    fn remove(&self, key: &str);
}

/// File-based storage adapter
///
/// Stores license data in `paycheck.json` within the specified directory.
pub struct FileStorage {
    path: std::path::PathBuf,
    cache: RwLock<HashMap<String, String>>,
}

impl FileStorage {
    /// Create a new file storage in the given directory.
    ///
    /// The directory must exist and be writable. License data will be stored
    /// in `{storage_dir}/paycheck.json`.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store license data (must exist)
    ///
    /// # Returns
    /// `None` if the directory doesn't exist or isn't accessible.
    pub fn new(storage_dir: &Path) -> Option<Self> {
        if !storage_dir.is_dir() {
            return None;
        }

        let path = storage_dir.join("paycheck.json");

        // Load existing data
        let cache = if path.exists() {
            let contents = std::fs::read_to_string(&path).ok()?;
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Some(Self {
            path,
            cache: RwLock::new(cache),
        })
    }

    /// Save the cache to disk
    fn save(&self) {
        if let Ok(cache) = self.cache.read()
            && let Ok(contents) = serde_json::to_string_pretty(&*cache)
        {
            let _ = std::fs::write(&self.path, contents);
        }
    }
}

impl StorageAdapter for FileStorage {
    fn get(&self, key: &str) -> Option<String> {
        self.cache.read().ok()?.get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(key.to_string(), value.to_string());
        }
        self.save();
    }

    fn remove(&self, key: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(key);
        }
        self.save();
    }
}

impl std::fmt::Debug for FileStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStorage")
            .field("path", &self.path)
            .finish()
    }
}
