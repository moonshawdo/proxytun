//! Reporting what can repeat at packet, query or accept rate (a full table,
//! an exhausted pool, no fd left) at a bounded rate instead: the counters
//! still count every occurrence.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How often such a report may repeat.
pub const EVERY: Duration = Duration::from_secs(10);

/// One kind of report, made at most once every `EVERY` by whoever makes it.
#[derive(Default)]
pub struct Throttle(Mutex<Option<Instant>>);

impl Throttle {
    pub const fn new() -> Self {
        Throttle(Mutex::new(None))
    }

    /// Is the report due now? Records it if so.
    pub fn due(&self) -> bool {
        // A poisoned lock only means a panic between two reports.
        let mut last = self.0.lock().unwrap_or_else(|e| e.into_inner());
        due(&mut last, Instant::now(), EVERY)
    }
}

/// Is a report due, `every` after the last one? Records it if so.
fn due(last: &mut Option<Instant>, now: Instant, every: Duration) -> bool {
    if last.is_some_and(|t| now.saturating_duration_since(t) < every) {
        return false;
    }
    *last = Some(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_comes_now_and_then_not_every_time() {
        let mut last = None;
        let t = Instant::now();
        assert!(due(&mut last, t, EVERY), "the first time");
        assert!(!due(&mut last, t + Duration::from_secs(1), EVERY));
        assert!(!due(&mut last, t + Duration::from_secs(9), EVERY));
        assert!(due(&mut last, t + EVERY, EVERY));
        assert!(!due(&mut last, t + EVERY, EVERY));
    }

    #[test]
    fn one_throttle_reports_once_whoever_asks() {
        let t = Throttle::new();
        assert!(t.due(), "the first time");
        let others: Vec<bool> = std::thread::scope(|s| {
            let asks: Vec<_> = (0..4).map(|_| s.spawn(|| t.due())).collect();
            asks.into_iter().map(|a| a.join().unwrap()).collect()
        });
        assert_eq!(others, [false; 4], "within the same {}s", EVERY.as_secs());
    }
}
