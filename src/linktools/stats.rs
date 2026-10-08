//! Report statistics: 3-decimal rounding and latency distributions.
//!
//! Changes from v2: `p95` is rounded like `median` (D-8.1#5); the values
//! are unchanged for inputs that already had at most 3 decimals.

use serde::Serialize;

/// Round to 3 decimals, as every `*_ms` / `*_mbps` report value (v2).
pub fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Median and nearest-rank 95th percentile of a sample.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct Distribution {
    pub median: f64,
    pub p95: f64,
}

/// `None` for an empty sample (reported as `null`). The median of an even
/// count is the mean of the two middle values; p95 is
/// `sorted[ceil(0.95 n) - 1]`. Non-finite values are ignored.
pub fn distribution(values: &[f64]) -> Option<Distribution> {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let middle = n / 2;
    let median = if n % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    // ceil(0.95 n) is in 1..=n for n >= 1, so the index is in bounds.
    let rank = ((n as f64) * 0.95).ceil() as usize;
    let p95 = sorted[rank.clamp(1, n) - 1];
    Some(Distribution {
        median: round3(median),
        p95: round3(p95),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn v2_golden_distribution() {
        let d = distribution(&[4.0, 1.0, 2.0, 3.0]).unwrap();
        assert_eq!(serde_json::to_value(d).unwrap(), json!({"median":2.5,"p95":4.0}));
        assert_eq!(distribution(&[]), None);
    }

    #[test]
    fn nearest_rank_and_rounding() {
        let cases: [(&[f64], f64, f64); 7] = [
            (&[7.0], 7.0, 7.0),
            (&[1.0, 2.0], 1.5, 2.0),
            (&[3.0, 1.0, 2.0], 2.0, 3.0),
            // n = 20: ceil(19.0) = 19 → the 19th value, not the maximum.
            (
                &[
                    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0,
                    15.0, 16.0, 17.0, 18.0, 19.0, 20.0,
                ],
                10.5,
                19.0,
            ),
            (&[1.23456, 2.0], 1.617, 2.0),
            (&[1.23456], 1.235, 1.235),
            (&[1.0, f64::NAN, 3.0], 2.0, 3.0),
        ];
        for (values, median, p95) in cases {
            let d = distribution(values).unwrap();
            assert_eq!((d.median, d.p95), (median, p95), "{values:?}");
        }
        assert_eq!(distribution(&[f64::INFINITY]), None);
    }

    #[test]
    fn round3_matches_v2() {
        assert_eq!(round3(151.23449), 151.234);
        assert_eq!(round3(0.0005), 0.001);
        assert_eq!(round3(2.0), 2.0);
    }
}
