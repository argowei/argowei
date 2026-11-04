//! Per-account backoff after failed logins.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failures allowed before any delay is imposed.
const FREE_ATTEMPTS: u32 = 3;
const MAX_DELAY: Duration = Duration::from_secs(300);

struct Entry {
    failures: u32,
    locked_until: Instant,
}

/// Exponential backoff for repeated authentication failures.
///
/// Keyed by account (not client address), because Argowei sits behind
/// proxies where the address is unreliable. The caller maps all unknown
/// usernames to one shared key, which keeps the map bounded. The delay is
/// capped, so an attacker can slow the admin's login but never lock it out.
///
/// Time is passed in so the schedule is testable without sleeping.
#[derive(Default)]
pub struct LoginThrottle {
    entries: Mutex<HashMap<String, Entry>>,
}

impl LoginThrottle {
    /// `Err(wait)` if the key is currently locked out.
    pub fn check(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let entries = self.entries.lock().expect("throttle lock poisoned");
        match entries.get(key) {
            Some(entry) if entry.locked_until > now => Err(entry.locked_until - now),
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, key: &str, now: Instant) {
        let mut entries = self.entries.lock().expect("throttle lock poisoned");
        let entry = entries.entry(key.to_owned()).or_insert(Entry {
            failures: 0,
            locked_until: now,
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.locked_until = now + delay_for(entry.failures);
    }

    pub fn record_success(&self, key: &str) {
        self.entries
            .lock()
            .expect("throttle lock poisoned")
            .remove(key);
    }
}

fn delay_for(failures: u32) -> Duration {
    if failures <= FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    let exponent = (failures - FREE_ATTEMPTS).min(16);
    Duration::from_secs(1u64 << exponent).min(MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempts_are_free() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();

        for _ in 0..FREE_ATTEMPTS {
            assert!(throttle.check("admin", now).is_ok());
            throttle.record_failure("admin", now);
        }
        assert!(throttle.check("admin", now).is_ok());
    }

    #[test]
    fn delay_grows_exponentially_then_caps() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();

        for _ in 0..FREE_ATTEMPTS + 1 {
            throttle.record_failure("admin", now);
        }
        assert_eq!(throttle.check("admin", now), Err(Duration::from_secs(2)));

        throttle.record_failure("admin", now);
        assert_eq!(throttle.check("admin", now), Err(Duration::from_secs(4)));

        for _ in 0..40 {
            throttle.record_failure("admin", now);
        }
        assert_eq!(throttle.check("admin", now), Err(MAX_DELAY));
    }

    #[test]
    fn lockout_expires() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS + 1 {
            throttle.record_failure("admin", now);
        }

        assert!(throttle
            .check("admin", now + Duration::from_secs(3))
            .is_ok());
    }

    #[test]
    fn success_resets_and_keys_are_independent() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..FREE_ATTEMPTS + 3 {
            throttle.record_failure("admin", now);
        }

        assert!(throttle.check("other", now).is_ok());

        throttle.record_success("admin");
        assert!(throttle.check("admin", now).is_ok());
    }
}
