//! Token-bucket primitive + idle-bucket sweep helper.
//!
//! `TokenBucket` itself is pure logic — no async, no shared state. The
//! owner is responsible for synchronization and for deciding what a
//! "token" means (per-client query, per-IP, per-domain, etc.). One
//! bucket = one independent rate limit.
//!
//! Tokens are stored as `f64` so partial accrual between full-token
//! boundaries is preserved across `try_acquire` calls; otherwise a slow
//! refill rate (e.g. 0.5 tok/s) would round to zero forever.
//!
//! `sweep` is provided as a helper for callers that store buckets in a
//! `Mutex<HashMap<K, TokenBucket>>` and need a periodic eviction task to
//! keep memory bounded. A bucket that is fully refilled and idle carries
//! no state, so dropping it is observationally identical to keeping it.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Build a full bucket with `capacity` tokens that refills at
    /// `refill_rate` tokens per second.
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: f64::from(capacity),
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Timestamp of the last refill (i.e. the last `try_acquire` call,
    /// successful or not). Exposed so a sweep task can identify idle
    /// buckets without poking at `try_acquire`'s mutating side effects.
    pub fn last_refill(&self) -> Instant {
        self.last_refill
    }

    /// Number of tokens currently in the bucket. Used by `sweep` to
    /// decide whether a bucket is "full and idle" — if so, dropping it
    /// is observationally identical to keeping it.
    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    /// Configured capacity. The bucket is "full" when `tokens >= capacity`.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Refill based on wall-clock elapsed time, then attempt to consume
    /// one token. Returns `true` if a token was taken, `false` if the
    /// bucket was empty.
    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let cap = f64::from(self.capacity);
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(cap);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Drop entries that have been untouched for at least `max_age` AND are
/// at full capacity. The "full" predicate matters: an idle but partially
/// drained bucket still carries state (a client recently consumed tokens
/// and may return), while a full bucket can always be reconstructed
/// identically on demand. So this never changes rate-limit semantics.
///
/// Held lock duration is O(n). Caller is expected to invoke this from a
/// background task on a coarse cadence (tens of seconds), not the hot
/// path.
pub fn sweep<K: Eq + Hash>(map: &Mutex<HashMap<K, TokenBucket>>, max_age: Duration) {
    let now = Instant::now();
    let mut guard = map.lock().expect("ratelimit map mutex poisoned");
    guard.retain(|_, b| {
        let idle = now.duration_since(b.last_refill()) >= max_age;
        let full = b.tokens() >= f64::from(b.capacity());
        !(idle && full)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn full_bucket_grants_capacity_then_denies() {
        // Refill rate of 1 tok/s — within microseconds of `new()` the
        // accrued fraction is negligible, so the 6th call cleanly fails.
        let mut b = TokenBucket::new(5, 1.0);
        for i in 0..5 {
            assert!(b.try_acquire(), "acquire {i} should succeed on full bucket");
        }
        assert!(!b.try_acquire(), "6th acquire should fail when drained");
    }

    #[test]
    fn token_regenerates_after_refill_interval() {
        // 10 tok/s ⇒ one token per 100 ms.
        let mut b = TokenBucket::new(1, 10.0);
        assert!(b.try_acquire(), "initial token");
        assert!(!b.try_acquire(), "bucket drained");

        // Sleep well past one refill interval — wall-clock jitter in CI
        // makes a hair-thin margin flaky, so we wait 150 ms.
        sleep(Duration::from_millis(150));
        assert!(b.try_acquire(), "token should regenerate after interval");
    }

    #[test]
    fn sweep_drops_idle_full_buckets_keeps_active_or_drained() {
        // Build a map with three buckets in distinct states, then sweep
        // with a tiny max_age so the time gate trivially trips.
        //
        // 1) "idle-full" — full bucket, last_refill far in the past → evicted
        // 2) "active" — full but recent → kept (fails the idle gate)
        // 3) "drained" — old but partially drained → kept (fails the full gate)
        let map: Mutex<HashMap<&'static str, TokenBucket>> = Mutex::new(HashMap::new());
        {
            let mut guard = map.lock().unwrap();
            let past = Instant::now() - Duration::from_secs(600);

            // idle-full: full tokens, ancient last_refill
            let mut b1 = TokenBucket::new(5, 1.0);
            b1.last_refill = past;
            guard.insert("idle-full", b1);

            // active: full tokens, last_refill = now
            let b2 = TokenBucket::new(5, 1.0);
            guard.insert("active", b2);

            // drained: ancient last_refill but partially consumed
            let mut b3 = TokenBucket::new(5, 1.0);
            b3.tokens = 2.0;
            b3.last_refill = past;
            guard.insert("drained", b3);
        }

        sweep(&map, Duration::from_secs(60));

        let guard = map.lock().unwrap();
        assert!(
            !guard.contains_key("idle-full"),
            "idle full bucket should be evicted"
        );
        assert!(
            guard.contains_key("active"),
            "recently-touched bucket must remain"
        );
        assert!(
            guard.contains_key("drained"),
            "drained-but-old bucket must remain — it still carries state"
        );
    }

    #[test]
    fn tokens_cap_at_capacity() {
        // 100 tok/s for 200 ms would mint 20 tokens if uncapped — must
        // clamp to capacity (2) so the 3rd acquire fails.
        let mut b = TokenBucket::new(2, 100.0);
        sleep(Duration::from_millis(200));
        assert!(b.try_acquire(), "first cap-bounded token");
        assert!(b.try_acquire(), "second cap-bounded token");
        assert!(
            !b.try_acquire(),
            "3rd acquire must fail — tokens should not have accumulated past capacity"
        );
    }
}
