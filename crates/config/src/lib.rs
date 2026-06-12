//! `config` — the `compute.json` reader for the Citrate node agent.
//!
//! `compute.json` is the single "set and forget" settings file gui-native
//! persists for a node operator. Its canonical shape (SELL planset / design
//! doc) is `{ enabled, allocation_percent, schedule }`. This crate parses that
//! file into a typed [`ComputeSettings`] and exposes the [`Schedule`] window
//! logic the bidder consults to decide whether the machine should participate
//! at the current local hour.
//!
//! Hours are expressed in 24h local-clock terms (0..=23). The schedule windows
//! are intentionally simple and total (every hour resolves to in/out of window)
//! so the bidder's gating is deterministic and unit-testable offline.

use serde::{Deserialize, Serialize};

/// When the agent is allowed to participate in the marketplace.
///
/// - `Always`   — participate every hour.
/// - `Nights`   — participate only during night hours (`22:00`..=`05:59`).
/// - `Weekends` — participate only on Saturday/Sunday.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Schedule {
    Always,
    Nights,
    Weekends,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule::Always
    }
}

/// Day of week for schedule evaluation, ISO order (`Mon`=1 .. `Sun`=7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Schedule {
    /// The inclusive night window start hour (22:00).
    pub const NIGHT_START_HOUR: u8 = 22;
    /// The inclusive night window end hour (05:59 — last in-window hour is 5).
    pub const NIGHT_END_HOUR: u8 = 5;

    /// Is the agent allowed to participate at the given local `hour` (0..=23)
    /// and `day`?
    ///
    /// `hour` values outside `0..=23` are treated as out-of-window (defensive;
    /// a malformed clock should never let the machine bid when it shouldn't).
    pub fn in_window(self, hour: u8, day: Weekday) -> bool {
        if hour > 23 {
            return false;
        }
        match self {
            Schedule::Always => true,
            // Night window wraps midnight: [22:00, 24:00) ∪ [00:00, 06:00).
            Schedule::Nights => hour >= Self::NIGHT_START_HOUR || hour <= Self::NIGHT_END_HOUR,
            Schedule::Weekends => matches!(day, Weekday::Sat | Weekday::Sun),
        }
    }

    /// Seconds until the current schedule window closes, from `hour:minute`
    /// on `day` (SELL-S3 pause-before-close).
    ///
    /// - `Always` never closes → `u64::MAX`.
    /// - Outside the window (or a malformed minute) → `0` — nothing can be
    ///   finished in a window we are not in; the safe answer for a
    ///   misordered caller.
    /// - Granularity is one minute, rounding the remaining time DOWN (may
    ///   under-report by up to 59 s — conservative for an anti-slash margin,
    ///   never optimistic).
    pub fn secs_until_window_close(self, hour: u8, minute: u8, day: Weekday) -> u64 {
        if !self.in_window(hour, day) || minute > 59 {
            return 0;
        }
        let minutes_since_midnight = u64::from(hour) * 60 + u64::from(minute);
        let remaining_minutes = match self {
            Schedule::Always => return u64::MAX,
            Schedule::Nights => {
                // Window closes at 06:00 (NIGHT_END_HOUR 5 is the last
                // in-window hour). The evening side wraps midnight.
                let close = (u64::from(Self::NIGHT_END_HOUR) + 1) * 60;
                if hour >= Self::NIGHT_START_HOUR {
                    (24 * 60 - minutes_since_midnight) + close
                } else {
                    close - minutes_since_midnight
                }
            }
            Schedule::Weekends => {
                // Window closes Monday 00:00.
                let full_days_left: u64 = match day {
                    Weekday::Sat => 1,
                    _ => 0, // Sun (weekdays already returned 0 above)
                };
                full_days_left * 24 * 60 + (24 * 60 - minutes_since_midnight)
            }
        };
        remaining_minutes * 60
    }
}

/// Parsed `compute.json`.
///
/// Unknown fields are ignored so the agent stays forward-compatible with newer
/// gui-native writers. Missing fields fall back to safe defaults (disabled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeSettings {
    /// Master participation switch. Defaults to `false` (fail-safe: an absent
    /// or partial file must not silently start selling compute).
    #[serde(default)]
    pub enabled: bool,

    /// Fraction of the machine's GPU the operator allots, as a percent
    /// (`0..=100`). Enforcement is platform-specific (S4); in S1 this is read
    /// and surfaced but not yet hardware-enforced.
    #[serde(default)]
    pub allocation_percent: u8,

    /// When the agent may participate.
    #[serde(default)]
    pub schedule: Schedule,
}

impl Default for ComputeSettings {
    fn default() -> Self {
        ComputeSettings {
            enabled: false,
            allocation_percent: 0,
            schedule: Schedule::default(),
        }
    }
}

/// Error parsing `compute.json`.
#[derive(Debug)]
pub enum ConfigError {
    /// The bytes were not valid JSON in the `compute.json` shape.
    Parse(serde_json::Error),
    /// `allocation_percent` was out of the `0..=100` range.
    AllocationOutOfRange(u8),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Parse(e) => write!(f, "compute.json parse error: {e}"),
            ConfigError::AllocationOutOfRange(v) => {
                write!(f, "allocation_percent {v} out of range (0..=100)")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl ComputeSettings {
    /// Parse `compute.json` from raw bytes/string, validating ranges.
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        let settings: ComputeSettings = serde_json::from_str(s).map_err(ConfigError::Parse)?;
        if settings.allocation_percent > 100 {
            return Err(ConfigError::AllocationOutOfRange(settings.allocation_percent));
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_shape() {
        let s = ComputeSettings::from_json(
            r#"{ "enabled": true, "allocation_percent": 50, "schedule": "always" }"#,
        )
        .expect("valid");
        assert!(s.enabled);
        assert_eq!(s.allocation_percent, 50);
        assert_eq!(s.schedule, Schedule::Always);
    }

    #[test]
    fn parses_all_schedule_variants() {
        for (raw, want) in [
            ("always", Schedule::Always),
            ("nights", Schedule::Nights),
            ("weekends", Schedule::Weekends),
        ] {
            let json = format!(r#"{{ "enabled": true, "schedule": "{raw}" }}"#);
            let s = ComputeSettings::from_json(&json).expect("valid");
            assert_eq!(s.schedule, want, "schedule {raw}");
        }
    }

    #[test]
    fn missing_fields_are_failsafe_disabled() {
        // An empty object must parse to disabled, not accidentally enabled.
        let s = ComputeSettings::from_json("{}").expect("valid");
        assert!(!s.enabled);
        assert_eq!(s.allocation_percent, 0);
        assert_eq!(s.schedule, Schedule::Always);
        assert_eq!(s, ComputeSettings::default());
    }

    #[test]
    fn rejects_out_of_range_allocation() {
        let err = ComputeSettings::from_json(r#"{ "allocation_percent": 250 }"#);
        assert!(matches!(err, Err(ConfigError::AllocationOutOfRange(250))));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            ComputeSettings::from_json("not json"),
            Err(ConfigError::Parse(_))
        ));
    }

    // ---- SELL-S3 pause-before-close: secs_until_window_close ----

    #[test]
    fn always_never_closes() {
        assert_eq!(
            Schedule::Always.secs_until_window_close(12, 30, Weekday::Wed),
            u64::MAX
        );
    }

    #[test]
    fn nights_window_close_is_six_am() {
        // 05:00 → one hour left.
        assert_eq!(
            Schedule::Nights.secs_until_window_close(5, 0, Weekday::Wed),
            3600
        );
        // 05:30 → thirty minutes left.
        assert_eq!(
            Schedule::Nights.secs_until_window_close(5, 30, Weekday::Wed),
            1800
        );
        // 22:00 (evening side, wraps midnight) → 8 hours left.
        assert_eq!(
            Schedule::Nights.secs_until_window_close(22, 0, Weekday::Wed),
            8 * 3600
        );
        // 23:15 → 6h45m left.
        assert_eq!(
            Schedule::Nights.secs_until_window_close(23, 15, Weekday::Wed),
            6 * 3600 + 45 * 60
        );
    }

    #[test]
    fn nights_outside_window_closes_now() {
        assert_eq!(
            Schedule::Nights.secs_until_window_close(12, 0, Weekday::Wed),
            0
        );
    }

    #[test]
    fn weekends_close_monday_midnight() {
        // Saturday 00:00 → 48h left.
        assert_eq!(
            Schedule::Weekends.secs_until_window_close(0, 0, Weekday::Sat),
            48 * 3600
        );
        // Sunday 23:00 → one hour left.
        assert_eq!(
            Schedule::Weekends.secs_until_window_close(23, 0, Weekday::Sun),
            3600
        );
        // Tuesday → not in window.
        assert_eq!(
            Schedule::Weekends.secs_until_window_close(10, 0, Weekday::Tue),
            0
        );
    }

    #[test]
    fn malformed_minute_closes_now() {
        assert_eq!(
            Schedule::Nights.secs_until_window_close(5, 75, Weekday::Wed),
            0
        );
    }

    #[test]
    fn always_is_in_window_every_hour() {
        for hour in 0u8..24 {
            assert!(Schedule::Always.in_window(hour, Weekday::Wed));
        }
    }

    #[test]
    fn nights_window_wraps_midnight() {
        // In-window: 22, 23, 0..=5.
        for hour in [22u8, 23, 0, 1, 2, 3, 4, 5] {
            assert!(
                Schedule::Nights.in_window(hour, Weekday::Mon),
                "hour {hour} should be in the nights window"
            );
        }
        // Out-of-window: noon and the daytime band 6..=21.
        for hour in 6u8..=21 {
            assert!(
                !Schedule::Nights.in_window(hour, Weekday::Mon),
                "hour {hour} should be outside the nights window"
            );
        }
    }

    #[test]
    fn nights_at_noon_is_out_of_window() {
        // Directly mirrors the SELL-S1 scenario "schedule window is honored".
        assert!(!Schedule::Nights.in_window(12, Weekday::Tue));
    }

    #[test]
    fn weekends_only_on_sat_sun() {
        for day in [Weekday::Sat, Weekday::Sun] {
            assert!(Schedule::Weekends.in_window(12, day));
        }
        for day in [
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
            Weekday::Fri,
        ] {
            assert!(!Schedule::Weekends.in_window(12, day));
        }
    }

    #[test]
    fn out_of_clock_hour_is_never_in_window() {
        assert!(!Schedule::Always.in_window(24, Weekday::Mon));
        assert!(!Schedule::Nights.in_window(99, Weekday::Mon));
    }
}
