//! Clock helpers: unix seconds and UTC formatting without a date crate.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds; 0 when the clock is before 1970.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Broken-down UTC time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Civil {
    pub fn from_unix(secs: u64) -> Civil {
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let (year, month, day) = civil_from_days(days);
        Civil {
            year,
            month,
            day,
            hour: (rem / 3600) as u32,
            minute: (rem % 3600 / 60) as u32,
            second: (rem % 60) as u32,
        }
    }
}

/// Days since 1970-01-01 → (year, month 1–12, day 1–31), proleptic
/// Gregorian. Howard Hinnant's `civil_from_days`, exact for all i64 inputs
/// that fit the era arithmetic (far beyond any u64 timestamp we format).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `2026-10-08 15:04:05 UTC`
pub fn format_utc(secs: u64) -> String {
    let c = Civil::from_unix(secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// `20261008T150405Z` (sortable; used in file names).
pub fn format_compact(secs: u64) -> String {
    let c = Civil::from_unix(secs);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        for (secs, utc, compact) in [
            (0, "1970-01-01 00:00:00 UTC", "19700101T000000Z"),
            (951_782_400, "2000-02-29 00:00:00 UTC", "20000229T000000Z"),
            (1_791_471_845, "2026-10-08 15:04:05 UTC", "20261008T150405Z"),
            (4_107_542_399, "2100-02-28 23:59:59 UTC", "21000228T235959Z"),
            (4_107_542_400, "2100-03-01 00:00:00 UTC", "21000301T000000Z"),
            (1_709_251_199, "2024-02-29 23:59:59 UTC", "20240229T235959Z"),
        ] {
            assert_eq!(format_utc(secs), utc, "{secs}");
            assert_eq!(format_compact(secs), compact, "{secs}");
        }
    }

    #[test]
    fn civil_days_round_trip_month_boundaries() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn now_is_after_2020() {
        assert!(now() > 1_577_836_800);
    }
}
