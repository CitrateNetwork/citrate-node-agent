//! `clock` — derive the current UTC hour-of-day and weekday from a UNIX
//! timestamp, with no third-party date library.
//!
//! The bidder's schedule gate needs `(hour, weekday)`. Rather than pull in a
//! timezone crate for S1, we compute UTC values from the epoch with the
//! standard civil-from-days algorithm (Howard Hinnant's `civil_from_days`,
//! public domain). The agent samples `SystemTime::now()`; this module makes the
//! conversion a pure, unit-tested function. (Local-timezone handling is a later
//! refinement; UTC is honest and deterministic for S1.)

use config::Weekday;

/// `(hour, weekday)` in UTC for a given UNIX timestamp (seconds since epoch).
pub fn utc_hour_and_weekday(unix_secs: u64) -> (u8, Weekday) {
    let secs_of_day = unix_secs % 86_400;
    let hour = (secs_of_day / 3600) as u8;

    let days = (unix_secs / 86_400) as i64;
    // 1970-01-01 (epoch day 0) was a Thursday.
    // 0=Thu,1=Fri,2=Sat,3=Sun,4=Mon,5=Tue,6=Wed.
    let dow = ((days % 7) + 7) % 7; // 0..=6, 0 == Thursday
    let weekday = match dow {
        0 => Weekday::Thu,
        1 => Weekday::Fri,
        2 => Weekday::Sat,
        3 => Weekday::Sun,
        4 => Weekday::Mon,
        5 => Weekday::Tue,
        6 => Weekday::Wed,
        _ => unreachable!(),
    };
    (hour, weekday)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_thursday_midnight() {
        let (hour, day) = utc_hour_and_weekday(0);
        assert_eq!(hour, 0);
        assert_eq!(day, Weekday::Thu);
    }

    #[test]
    fn computes_hour_of_day() {
        // 13:00:00 UTC on epoch day.
        let (hour, _) = utc_hour_and_weekday(13 * 3600);
        assert_eq!(hour, 13);
        // 23:59:59.
        let (hour, _) = utc_hour_and_weekday(86_399);
        assert_eq!(hour, 23);
    }

    #[test]
    fn weekday_progression() {
        // 1970-01-01 Thu, +1 day Fri, +2 Sat, +3 Sun, +4 Mon.
        assert_eq!(utc_hour_and_weekday(0).1, Weekday::Thu);
        assert_eq!(utc_hour_and_weekday(86_400).1, Weekday::Fri);
        assert_eq!(utc_hour_and_weekday(2 * 86_400).1, Weekday::Sat);
        assert_eq!(utc_hour_and_weekday(3 * 86_400).1, Weekday::Sun);
        assert_eq!(utc_hour_and_weekday(4 * 86_400).1, Weekday::Mon);
    }

    #[test]
    fn known_recent_date_is_correct() {
        // 2026-06-03T12:00:00Z = 1780488000 (Wednesday).
        let (hour, day) = utc_hour_and_weekday(1_780_488_000);
        assert_eq!(hour, 12);
        assert_eq!(day, Weekday::Wed);
    }
}
