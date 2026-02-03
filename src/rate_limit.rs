//! Rate limiting configuration for API endpoints.
//!
//! Rate limits are applied per-IP address to protect against DoS attacks.
//! Brute force is not a concern due to high-entropy keys (80+ bits).
//!
//! Tiers:
//! - Strict: /buy - external API calls
//! - Standard: /callback, /redeem/*, /validate, /license, /devices/*
//! - Relaxed: /health
//! - Org Ops: /orgs/* - authenticated org member operations (high limit, stops extreme abuse)
//!
//! Configure via environment variables:
//! - RATE_LIMIT_STRICT_RPM (default: 10)
//! - RATE_LIMIT_STANDARD_RPM (default: 30)
//! - RATE_LIMIT_RELAXED_RPM (default: 60)
//! - RATE_LIMIT_ORG_OPS_RPM (default: 3000)
//! - RATE_LIMIT_ACTIVATION_MAX_ENTRIES (default: 10000) - caps memory for per-email tracking

use std::sync::Arc;
use std::time::Duration;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

/// Rate limiter layer type alias using governor types directly
pub type RateLimitLayer = GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    axum::body::Body,
>;

/// Creates a rate limiter layer with the specified requests per minute.
///
/// Returns `None` if `requests_per_minute` is 0 (rate limiting disabled).
///
/// Uses millisecond-precision periods to correctly handle high RPM values.
/// For 3000 RPM, period = 20ms (50 requests/second sustained).
/// For 10 RPM, period = 6000ms (1 request every 6 seconds).
fn create_layer(requests_per_minute: u32) -> Option<RateLimitLayer> {
    if requests_per_minute == 0 {
        return None;
    }

    // Use milliseconds for sub-second precision with high RPM values.
    // Old formula (60 / rpm) gave 0 for rpm > 60, breaking high-rate limits.
    let period_ms = 60_000 / requests_per_minute as u64;
    let config = GovernorConfigBuilder::default()
        .period(Duration::from_millis(period_ms.max(1)))
        .burst_size(requests_per_minute)
        .finish()
        .expect("Failed to build rate limiter config");

    Some(GovernorLayer::new(Arc::new(config)))
}

/// Creates a rate limiter layer with the specified requests per minute.
/// Returns `None` if `requests_per_minute` is 0 (rate limiting disabled).
///
/// Tier documentation (for reference):
/// - Strict (10 RPM default): External API calls like /buy, /activation/request-code
/// - Standard (30 RPM default): Crypto/DB operations like /redeem, /validate
/// - Relaxed (60 RPM default): Lightweight endpoints like /health
/// - Org ops (3000 RPM default): Authenticated /orgs/* endpoints
pub fn strict_layer(requests_per_minute: u32) -> Option<RateLimitLayer> {
    create_layer(requests_per_minute)
}

pub fn standard_layer(requests_per_minute: u32) -> Option<RateLimitLayer> {
    create_layer(requests_per_minute)
}

pub fn relaxed_layer(requests_per_minute: u32) -> Option<RateLimitLayer> {
    create_layer(requests_per_minute)
}

pub fn org_ops_layer(requests_per_minute: u32) -> Option<RateLimitLayer> {
    create_layer(requests_per_minute)
}

// ============ Activation Code Rate Limiter ============

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Default maximum number of unique email hashes to track.
/// Prevents unbounded memory growth from distributed attacks.
/// Override with RATE_LIMIT_ACTIVATION_MAX_ENTRIES env var.
pub const DEFAULT_ACTIVATION_MAX_ENTRIES: usize = 10_000;

/// In-memory rate limiter for activation code requests.
/// Limits by email hash to prevent abuse of /activation/request-code.
///
/// Memory is bounded by `max_entries` to prevent DoS via unique email flooding.
/// When at capacity, new email hashes are rejected until cleanup runs.
pub struct ActivationRateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    max_requests: usize,
    window_secs: u64,
    max_entries: usize,
}

impl ActivationRateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self::with_max_entries(max_requests, window_secs, DEFAULT_ACTIVATION_MAX_ENTRIES)
    }

    pub fn with_max_entries(max_requests: usize, window_secs: u64, max_entries: usize) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_requests,
            window_secs,
            max_entries,
        }
    }

    /// Check if a request is allowed for the given email hash.
    /// Returns Ok(()) if allowed, Err with message if rate limited.
    ///
    /// Note: This method recovers from mutex poisoning to prevent cascading failures.
    /// If a thread panics while holding the lock, subsequent calls will still work.
    pub fn check(&self, email_hash: &str) -> Result<(), &'static str> {
        let mut map = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        // Check if this email is already tracked
        if let Some(timestamps) = map.get_mut(email_hash) {
            // Remove old entries for this email
            timestamps.retain(|t| *t > cutoff);

            if timestamps.len() >= self.max_requests {
                return Err("Rate limit exceeded. Please try again later.");
            }

            timestamps.push(now);
            return Ok(());
        }

        // New email hash - check if we're at capacity
        if map.len() >= self.max_entries {
            return Err("Rate limit exceeded. Please try again later.");
        }

        // Add new entry
        map.insert(email_hash.to_string(), vec![now]);
        Ok(())
    }

    /// Clean up expired entries to prevent memory growth.
    /// Call periodically (e.g., every few minutes).
    ///
    /// Note: This method recovers from mutex poisoning to prevent cascading failures.
    pub fn cleanup(&self) {
        let mut map = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }

    /// Returns the number of unique keys (email hashes) currently tracked.
    /// Useful for monitoring memory usage and testing cleanup behavior.
    ///
    /// Note: This method recovers from mutex poisoning to prevent cascading failures.
    pub fn entry_count(&self) -> usize {
        self.requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

impl Default for ActivationRateLimiter {
    fn default() -> Self {
        // 3 requests per email per hour
        Self::new(3, 3600)
    }
}
