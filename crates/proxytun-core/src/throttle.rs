//! Reporting what can repeat at packet, query or accept rate (a full table,
//! an exhausted pool, no fd left) at a bounded rate instead: the counters
//! still count every occurrence.

use std::time::{Duration, Instant};

/// How often such a report may repeat.
pub const EVERY: Duration = Duration::from_secs(10);

/// Is a report due, `every` after the last one? Records it if so.
pub fn due(last: &mut Option<Instant>, now: Instant, every: Duration) -> bool {
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
}
