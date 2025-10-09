use std::cmp;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

const PACKETS_PER_SECOND: u64 = 20;
const N_PACKETS_BURSTABLE: u64 = 5;
const MIN_PACKET_DELAY: Duration = Duration::from_millis(1000 / PACKETS_PER_SECOND);

pub struct RateLimiter {
    table: DashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    /// Create an empty RateLimiter object.
    pub fn new() -> Self {
        RateLimiter {
            table: DashMap::default(),
        }
    }

    /// Check if a packet from the given IP address
    /// is allowed through the rate limiter at the given time.
    pub fn check(&self, addr: &IpAddr) -> bool {
        self.check_at(addr, Instant::now())
    }

    fn check_at(&self, addr: &IpAddr, time: Instant) -> bool {
        match self.table.entry(*addr) {
            Entry::Occupied(mut entry) => entry.get_mut().check(time),
            Entry::Vacant(entry) => {
                entry.insert(Bucket::new(time));
                true
            }
        }
    }
}

struct Bucket {
    last_refill: Instant,
    tokens: u64,
}

impl Bucket {
    fn new(time: Instant) -> Self {
        Bucket {
            last_refill: time,
            tokens: N_PACKETS_BURSTABLE - 1,
        }
    }

    fn check(&mut self, time: Instant) -> bool {
        // Try to take a token:
        // this has the effect of only refilling the
        // bucket for every N_PACKETS_BURSTABLE packets
        match self.tokens.checked_sub(1) {
            Some(token) => {
                self.tokens = token;
                return true;
            }
            None => (),
        }

        // LLVM should optimize this away
        assert_eq!(self.tokens, 0);

        // Try to refill the bucket:
        let delta = time.duration_since(self.last_refill);
        let delta = delta.as_millis() as u64;
        let tokens = delta / (MIN_PACKET_DELAY.as_millis() as u64);

        // Check if there are tokens available after refilling
        if tokens > 0 {
            self.tokens = cmp::min(tokens, N_PACKETS_BURSTABLE) - 1;
            self.last_refill = time;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct Result {
        allowed: bool,
        text: &'static str,
        wait: Duration,
    }

    #[test]
    fn test_ratelimiter() {
        let ratelimiter = RateLimiter::new();
        let ips = vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "172.167.2.3".parse().unwrap(),
            "97.231.252.215".parse().unwrap(),
            "248.97.91.167".parse().unwrap(),
            "188.208.233.47".parse().unwrap(),
            "104.2.183.179".parse().unwrap(),
            "72.129.46.120".parse().unwrap(),
            "2001:0db8:0a0b:12f0:0000:0000:0000:0001".parse().unwrap(),
            "f5c2:818f:c052:655a:9860:b136:6894:25f0".parse().unwrap(),
            "b2d7:15ab:48a7:b07c:a541:f144:a9fe:54fc".parse().unwrap(),
            "a47b:786e:1671:a22b:d6f9:4ab0:abc7:c918".parse().unwrap(),
            "ea1e:d155:7f7a:98fb:2bf5:9483:80f6:5445".parse().unwrap(),
            "3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4".parse().unwrap(),
        ];

        let mut expected = vec![];

        for _ in 0..N_PACKETS_BURSTABLE {
            expected.push(Result {
                allowed: true,
                wait: Duration::new(0, 0),
                text: "initial burst",
            });
        }

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "after burst",
        });

        expected.push(Result {
            allowed: true,
            wait: MIN_PACKET_DELAY,
            text: "filling tokens for single packet",
        });

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "not having refilled enough",
        });

        expected.push(Result {
            allowed: true,
            wait: 2 * MIN_PACKET_DELAY,
            text: "filling tokens for 2 * packet burst",
        });

        expected.push(Result {
            allowed: true,
            wait: Duration::new(0, 0),
            text: "second packet in 2 packet burst",
        });

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "packet following 2 packet burst",
        });

        let mut time = Instant::now();

        for item in expected {
            time += item.wait;

            for ip in ips.iter() {
                assert_eq!(
                    ratelimiter.check_at(&ip, time),
                    item.allowed,
                    "test failed for {} on {}. expected: {}, got: {}",
                    ip,
                    item.text,
                    item.allowed,
                    !item.allowed
                )
            }
        }
    }
}
