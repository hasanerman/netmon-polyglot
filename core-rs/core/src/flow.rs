use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub a: Endpoint,
    pub b: Endpoint,
    pub proto: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    AtoB = 0,
    BtoA = 1,
}

impl FlowKey {
    pub fn canonical(src: Endpoint, dst: Endpoint, proto: u8) -> (Self, Direction) {
        if src <= dst {
            (FlowKey { a: src, b: dst, proto }, Direction::AtoB)
        } else {
            (FlowKey { a: dst, b: src, proto }, Direction::BtoA)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowStats {
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub tcp_flags: u8,
}

impl FlowStats {
    pub fn total_packets(&self) -> u64 {
        self.packets[0] + self.packets[1]
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes[0] + self.bytes[1]
    }

    pub fn duration_us(&self) -> u64 {
        self.last_seen_us - self.first_seen_us
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowUpdate {
    pub key: FlowKey,
    pub direction: Direction,
    pub ts_us: u64,
    pub bytes: u32,
    pub tcp_flags: u8,
}

pub struct FlowTable {
    flows: LruCache<FlowKey, FlowStats>,
    idle_timeout_us: u64,
    evicted: u64,
    expired: u64,
}

impl FlowTable {
    pub fn new(capacity: NonZeroUsize, idle_timeout_us: u64) -> Self {
        FlowTable {
            flows: LruCache::new(capacity),
            idle_timeout_us,
            evicted: 0,
            expired: 0,
        }
    }

    pub fn update(&mut self, u: &FlowUpdate) -> FlowStats {
        let dir = u.direction as usize;
        if let Some(stats) = self.flows.get_mut(&u.key) {
            stats.last_seen_us = stats.last_seen_us.max(u.ts_us);
            stats.packets[dir] += 1;
            stats.bytes[dir] += u64::from(u.bytes);
            stats.tcp_flags |= u.tcp_flags;
            return *stats;
        }

        let mut stats = FlowStats {
            first_seen_us: u.ts_us,
            last_seen_us: u.ts_us,
            tcp_flags: u.tcp_flags,
            ..FlowStats::default()
        };
        stats.packets[dir] = 1;
        stats.bytes[dir] = u64::from(u.bytes);
        if self.flows.push(u.key, stats).is_some() {
            self.evicted += 1;
        }
        stats
    }

    pub fn expire(&mut self, now_us: u64) -> usize {
        let mut removed = 0;
        while let Some((_, stats)) = self.flows.peek_lru() {
            if stats.last_seen_us + self.idle_timeout_us > now_us {
                break;
            }
            self.flows.pop_lru();
            removed += 1;
        }
        self.expired += removed as u64;
        removed
    }

    pub fn top_by_bytes(&self, n: usize) -> Vec<(FlowKey, FlowStats)> {
        if n == 0 {
            return Vec::new();
        }
        let mut heap = BinaryHeap::with_capacity(n + 1);
        for (key, stats) in self.flows.iter() {
            heap.push(Reverse((stats.total_bytes(), *key)));
            if heap.len() > n {
                heap.pop();
            }
        }
        let mut top: Vec<_> = heap
            .into_iter()
            .filter_map(|Reverse((_, key))| self.flows.peek(&key).map(|s| (key, *s)))
            .collect();
        top.sort_by(|x, y| y.1.total_bytes().cmp(&x.1.total_bytes()).then(x.0.cmp(&y.0)));
        top
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowStats)> {
        self.flows.iter()
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.peek(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    pub fn expired(&self) -> u64 {
        self.expired
    }
}
