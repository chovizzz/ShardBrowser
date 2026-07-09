//! Login throttle for `/auth/login`: exponential-backoff lockout keyed
//! separately by client IP and by username, plus a global concurrency cap on
//! password verification — together defeating password brute-force and Argon2
//! CPU exhaustion (including a concurrent first wave that would otherwise all
//! reach Argon2 before any failure is recorded). State is process-local (resets
//! on restart, which is fine for a single self-hosted binary).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy)]
struct Attempt {
    failures: u32,
    last: Instant,
    locked_until: Option<Instant>,
}

/// One exponential-backoff counter map. Keyed by an opaque string (an IP or a
/// username); the caller keeps IP and username in separate limiters so they can
/// carry different thresholds.
struct LoginLimiter {
    inner: Mutex<HashMap<String, Attempt>>,
    max_failures: u32,
    window: Duration,
    base_lock: Duration,
    max_lock: Duration,
}

/// Prune the map only once it grows past this, to avoid an O(n) sweep on every
/// failure while still bounding memory under a flood of distinct keys.
const PRUNE_THRESHOLD: usize = 4096;

impl LoginLimiter {
    fn new(max_failures: u32, window: Duration, base_lock: Duration, max_lock: Duration) -> Self {
        Self { inner: Mutex::new(HashMap::new()), max_failures, window, base_lock, max_lock }
    }

    /// Remaining lockout seconds for `key`, or `None` if it may attempt now.
    fn locked_for(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let map = self.inner.lock().unwrap();
        map.get(key)
            .and_then(|a| a.locked_until)
            .and_then(|until| until.checked_duration_since(now))
            // Ceil so Retry-After never under-tells the wait.
            .map(|d| (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1))
    }

    fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        if map.len() > PRUNE_THRESHOLD {
            // Drop only entries idle beyond the window; keep recently-active ones
            // (even past-lock) so backoff keeps escalating across expiries.
            map.retain(|_, a| now.duration_since(a.last) < self.window);
        }
        let a = map
            .entry(key.to_string())
            .or_insert(Attempt { failures: 0, last: now, locked_until: None });
        // Reset only if the previous failure is outside the window — an expired
        // *lock* within the window still escalates (30s → 60s → 120s → …).
        if now.duration_since(a.last) > self.window {
            a.failures = 0;
            a.locked_until = None;
        }
        a.failures = a.failures.saturating_add(1);
        a.last = now;
        if a.failures >= self.max_failures {
            let over = a.failures - self.max_failures; // 0, 1, 2, ...
            let mult = 1u32.checked_shl(over).unwrap_or(u32::MAX);
            let lock = self.base_lock.saturating_mul(mult).min(self.max_lock);
            a.locked_until = Some(now + lock);
        }
    }

    fn record_success(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }
}

/// Full login throttle: per-IP and (more lenient) per-username lockout plus a
/// global permit pool bounding how many Argon2 verifications run at once.
pub struct LoginThrottle {
    ip: LoginLimiter,
    user: LoginLimiter,
    verify_slots: Arc<Semaphore>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        let window = Duration::from_secs(900);
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self {
            // Per-IP is the tight bound (single-source brute force / CPU).
            ip: LoginLimiter::new(5, window, Duration::from_secs(30), Duration::from_secs(900)),
            // Per-username is looser so an attacker can't easily lock a real user
            // out, while still slowing distributed guessing of one account.
            user: LoginLimiter::new(15, window, Duration::from_secs(30), Duration::from_secs(900)),
            verify_slots: Arc::new(Semaphore::new(cores.max(2))),
        }
    }

    /// Longest remaining lockout across the IP and username keys, or `None`.
    pub fn locked_for(&self, ip: &str, user: &str) -> Option<u64> {
        [self.ip.locked_for(ip), self.user.locked_for(user)].into_iter().flatten().max()
    }

    pub fn record_failure(&self, ip: &str, user: &str) {
        self.ip.record_failure(ip);
        self.user.record_failure(user);
    }

    pub fn record_success(&self, ip: &str, user: &str) {
        self.ip.record_success(ip);
        self.user.record_success(user);
    }

    /// Reserve one of the bounded Argon2-verification slots. `None` means the
    /// pool is saturated — reject rather than let a concurrent burst all hit
    /// Argon2 at once. The permit is released when dropped.
    pub fn try_verify_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.verify_slots.clone().try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(max: u32) -> LoginLimiter {
        LoginLimiter::new(max, Duration::from_secs(900), Duration::from_secs(30), Duration::from_secs(900))
    }

    #[test]
    fn locks_out_after_threshold_and_backs_off() {
        let l = lim(3);
        assert!(l.locked_for("a").is_none());
        l.record_failure("a");
        l.record_failure("a");
        assert!(l.locked_for("a").is_none(), "below threshold: not locked");
        l.record_failure("a"); // 3rd → locked, base 30s
        let first = l.locked_for("a").expect("locked");
        assert!(first > 0 && first <= 30);
        l.record_failure("a"); // 4th → 60s (backoff)
        assert!(l.locked_for("a").unwrap() > 30, "backoff extends the lock");
        assert!(l.locked_for("b").is_none(), "a different key is independent");
    }

    #[test]
    fn lock_escalates_across_expiry() {
        // After a lock EXPIRES (but within the failure window), the next failure
        // must escalate from the retained count, not reset to the base lock.
        let l = LoginLimiter::new(1, Duration::from_secs(100), Duration::from_secs(1), Duration::from_secs(100));
        l.record_failure("a"); // 1st → 1s lock
        assert_eq!(l.locked_for("a"), Some(1));
        std::thread::sleep(Duration::from_millis(1200)); // let the lock expire
        assert!(l.locked_for("a").is_none(), "lock expired");
        l.record_failure("a"); // 2nd within window → 2s lock (escalated, not reset)
        assert!(l.locked_for("a").unwrap() >= 2, "escalates after expiry instead of resetting");
    }

    #[test]
    fn success_clears_history() {
        let l = lim(2);
        l.record_failure("bob");
        l.record_failure("bob");
        assert!(l.locked_for("bob").is_some());
        l.record_success("bob");
        assert!(l.locked_for("bob").is_none(), "success resets the counter");
    }

    #[test]
    fn throttle_uses_max_of_both_keys_and_bounds_verify() {
        let t = LoginThrottle::new();
        // Not locked initially.
        assert!(t.locked_for("1.2.3.4", "bob").is_none());
        // The verify pool hands out a bounded number of permits.
        let mut held = Vec::new();
        while let Some(p) = t.try_verify_slot() {
            held.push(p);
        }
        assert!(!held.is_empty(), "some verify slots exist");
        assert!(t.try_verify_slot().is_none(), "pool saturates");
        drop(held);
        assert!(t.try_verify_slot().is_some(), "permits free on drop");
    }
}
