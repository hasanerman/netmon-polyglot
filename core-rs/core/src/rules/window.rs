use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

pub const MAX_EVENTS_PER_SOURCE: usize = 65_536;

pub struct DistinctWindow<K> {
    events: VecDeque<(u64, K)>,
    counts: HashMap<K, u32>,
}

impl<K: Copy + Eq + Hash> DistinctWindow<K> {
    pub fn new() -> Self {
        DistinctWindow {
            events: VecDeque::new(),
            counts: HashMap::new(),
        }
    }

    pub fn add(&mut self, ts_us: u64, key: K, window_us: u64) -> usize {
        self.evict_before(ts_us.saturating_sub(window_us));
        if self.events.len() == MAX_EVENTS_PER_SOURCE {
            self.pop_oldest();
        }
        self.events.push_back((ts_us, key));
        *self.counts.entry(key).or_insert(0) += 1;
        self.counts.len()
    }

    fn evict_before(&mut self, cutoff: u64) {
        while self.events.front().is_some_and(|&(ts, _)| ts < cutoff) {
            self.pop_oldest();
        }
    }

    fn pop_oldest(&mut self) {
        let Some((_, key)) = self.events.pop_front() else { return };
        if let Some(n) = self.counts.get_mut(&key) {
            *n -= 1;
            if *n == 0 {
                self.counts.remove(&key);
            }
        }
    }
}

pub struct CountWindow {
    events: VecDeque<u64>,
}

impl CountWindow {
    pub fn new() -> Self {
        CountWindow { events: VecDeque::new() }
    }

    pub fn add(&mut self, ts_us: u64, window_us: u64) -> usize {
        let cutoff = ts_us.saturating_sub(window_us);
        while self.events.front().is_some_and(|&ts| ts < cutoff) {
            self.events.pop_front();
        }
        if self.events.len() == MAX_EVENTS_PER_SOURCE {
            self.events.pop_front();
        }
        self.events.push_back(ts_us);
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_counts_expire_with_the_window() {
        let mut w = DistinctWindow::new();
        assert_eq!(w.add(0, 1u16, 10), 1);
        assert_eq!(w.add(5, 2, 10), 2);
        assert_eq!(w.add(6, 2, 10), 2);
        assert_eq!(w.add(12, 3, 10), 2);
        assert_eq!(w.add(16, 3, 10), 2);
        assert_eq!(w.add(30, 4, 10), 1);
    }

    #[test]
    fn count_window_slides() {
        let mut w = CountWindow::new();
        assert_eq!(w.add(0, 10), 1);
        assert_eq!(w.add(10, 10), 2);
        assert_eq!(w.add(11, 10), 2);
    }
}
