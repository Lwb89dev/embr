//! A small token-bucket rate limiter with injected time (milliseconds).

use std::collections::BTreeMap;

/// Per-key token buckets. `capacity` tokens burst, refilled at `refill_per_sec`.
#[derive(Debug)]
pub struct RateLimiter<K: Ord + Clone> {
    capacity_milli: u64,
    refill_milli_per_sec: u64,
    buckets: BTreeMap<K, (u64, u64)>, // (milli-tokens, last_ms)
    max_keys: usize,
}

impl<K: Ord + Clone> RateLimiter<K> {
    /// `capacity` = burst size in requests; `refill_per_sec` = sustained rate.
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        Self {
            capacity_milli: u64::from(capacity) * 1000,
            refill_milli_per_sec: u64::from(refill_per_sec) * 1000,
            buckets: BTreeMap::new(),
            max_keys: 4096,
        }
    }

    /// Takes one token for `key` at time `now_ms`. `Err(retry_after_ms)` if the bucket is empty.
    pub fn check(&mut self, key: &K, now_ms: u64) -> Result<(), u64> {
        if self.buckets.len() >= self.max_keys && !self.buckets.contains_key(key) {
            // Bound memory: forget buckets that have fully refilled (they carry no information).
            let cap = self.capacity_milli;
            let rate = self.refill_milli_per_sec;
            self.buckets.retain(|_, (tokens, last)| {
                tokens.saturating_add(now_ms.saturating_sub(*last).saturating_mul(rate) / 1000)
                    < cap
            });
        }
        let cap = self.capacity_milli;
        let rate = self.refill_milli_per_sec;
        let (tokens, last) = self.buckets.entry(key.clone()).or_insert((cap, now_ms));
        let elapsed = now_ms.saturating_sub(*last);
        *tokens = (*tokens)
            .saturating_add(elapsed.saturating_mul(rate) / 1000)
            .min(cap);
        *last = now_ms;
        if *tokens >= 1000 {
            *tokens -= 1000;
            Ok(())
        } else if rate == 0 {
            Err(u64::MAX)
        } else {
            Err(((1000 - *tokens) * 1000).div_ceil(rate))
        }
    }

    /// Number of tracked keys (for tests/diagnostics).
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_throttle_then_refill() {
        let mut rl = RateLimiter::new(3, 1);
        for _ in 0..3 {
            assert!(rl.check(&"a", 0).is_ok());
        }
        let retry = rl.check(&"a", 0).unwrap_err();
        assert_eq!(retry, 1000);
        assert!(rl.check(&"a", 999).is_err());
        assert!(rl.check(&"a", 1000).is_ok());
        assert!(rl.check(&"a", 1000).is_err());
        // Another key is independent.
        assert!(rl.check(&"b", 1000).is_ok());
    }

    #[test]
    fn tokens_never_exceed_capacity() {
        let mut rl = RateLimiter::new(2, 100);
        assert!(rl.check(&1u8, 0).is_ok());
        for _ in 0..2 {
            assert!(rl.check(&1u8, 1_000_000).is_ok());
        }
        assert!(
            rl.check(&1u8, 1_000_000).is_err(),
            "idle time must not bank more than the burst"
        );
    }

    #[test]
    fn memory_is_bounded() {
        let mut rl = RateLimiter::new(1, 1000);
        for i in 0..10_000u32 {
            let _ = rl.check(&i, u64::from(i) * 10);
        }
        assert!(rl.tracked() <= 4096 + 1);
    }
}
