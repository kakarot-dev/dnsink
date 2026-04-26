//! Token-bucket primitive.
//!
//! Pure logic — no async, no shared state, no integration. The owner is
//! responsible for synchronization and for deciding what a "token" means
//! (per-client query, per-IP, per-domain, etc.). One bucket = one
//! independent rate limit.
//!
//! Tokens are stored as `f64` so partial accrual between full-token
//! boundaries is preserved across `try_acquire` calls; otherwise a slow
//! refill rate (e.g. 0.5 tok/s) would round to zero forever.

use std::time::Instant;

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
