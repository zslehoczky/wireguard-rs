use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

const N_PACKETS_BURSTABLE: usize = 5;
const PACKETS_PER_SECOND: u32 = 20;
const MIN_PACKET_DELAY_NS: u32 = 1_000_000_000 / PACKETS_PER_SECOND;

pub struct RateLimiter {
    table: spin::RwLock<HashMap<IpAddr, spin::Mutex<RecordedTimes>>>,
}

impl RateLimiter {
    /// Create an empty RateLimiter object.
    pub fn new() -> Self {
        RateLimiter {
            table: spin::RwLock::new(HashMap::new()),
        }
    }

    /// Check if a packet is allowed at this moment.
    ///
    /// If 'ip_address' is not already registered, register it.
    pub fn try_register_new_packet(&mut self, ip_address: &IpAddr) -> bool {
        self.try_register_new_packet_at(ip_address, Instant::now())
    }

    /// Check if 'ip_address' is already registered into the RateLimiter.
    pub fn is_registered(&self, ip_address: &IpAddr) -> bool {
        self.table.read().contains_key(ip_address)
    }

    /// Register 'ip_address' into the RateLimiter.
    pub fn register(&mut self, ip_address: &IpAddr) {
        self.table
            .write()
            .insert(*ip_address, spin::Mutex::new(RecordedTimes::new()));
    }

    fn try_register_new_packet_at(&mut self, ip_address: &IpAddr, time: Instant) -> bool {
        // check for existing entry (only requires read lock)
        if !self.is_registered(ip_address) {
            // add new entry (write lock)
            self.register(ip_address);
        }

        let table = self.table.read();

        let mut recorded_times = table
            .get(ip_address)
            .expect("Table should contain address")
            .lock();

        recorded_times.record(time).is_ok()
    }
}

struct RecordedTimes(VecDeque<Instant>);

impl RecordedTimes {
    fn new() -> Self {
        Self(VecDeque::new())
    }

    fn is_allowed(&self, time: Instant) -> bool {
        let mut result = false;

        let queue = &self.0;

        for i in 0..N_PACKETS_BURSTABLE {
            let allowed_for_i = queue.get(i).map_or(true, |then| {
                time.duration_since(*then).as_nanos()
                    >= MIN_PACKET_DELAY_NS as u128 * (i + 1) as u128
            });

            if allowed_for_i {
                result = true;

                break;
            }
        }

        result
    }

    fn record(&mut self, time: Instant) -> Result<(), &'static str> {
        if !self.is_allowed(time) {
            return Err("not allowed");
        }

        let queue = &mut self.0;

        // shrink size to 4 by removing from the back
        while queue.len() > 4 {
            queue.pop_back();
        }

        queue.push_front(time);

        return Ok(());
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
        let mut ratelimiter = RateLimiter::new();
        let mut expected = vec![];
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

        ips.iter().for_each(|addr| {
            ratelimiter.register(addr);
        });

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
            wait: Duration::new(0, MIN_PACKET_DELAY_NS),
            text: "filling tokens for single packet",
        });

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "not having refilled enough",
        });

        expected.push(Result {
            allowed: true,
            wait: Duration::new(0, 2 * MIN_PACKET_DELAY_NS),
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
                    ratelimiter.try_register_new_packet_at(&ip, time),
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
