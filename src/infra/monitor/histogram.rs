//! 固定分桶的延迟直方图(毫秒)。够算 p50 / p95 / p99,内存恒定、可加可减(窗口统计 = 两次累计快照相减)。

/// 桶上界(毫秒);最后还有一个溢出桶(> 10s)。
pub const BOUNDS_MS: [f64; 13] = [
    1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];
const SLOTS: usize = BOUNDS_MS.len() + 1;

/// 延迟直方图:[`BOUNDS_MS`] 各桶 + 溢出桶的累计计数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Histogram {
    counts: [u64; SLOTS],
}

impl Histogram {
    /// 记一个样本(毫秒),落进第一个上界不小于它的桶,超过 10s 的进溢出桶。
    pub fn record(&mut self, millis: f64) {
        let slot = BOUNDS_MS
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(SLOTS - 1);
        self.counts[slot] += 1;
    }

    /// 样本总数。
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// 逐桶累加另一份直方图(合并两段时间 / 多个来源)。
    pub fn add(&mut self, other: &Histogram) {
        for (mine, theirs) in self.counts.iter_mut().zip(other.counts.iter()) {
            *mine += theirs;
        }
    }

    /// `self - earlier`(累计值只增不减;饱和减法防御重置)。
    #[must_use]
    pub fn since(&self, earlier: &Histogram) -> Histogram {
        let mut out = Histogram::default();
        for (index, slot) in out.counts.iter_mut().enumerate() {
            *slot = self.counts[index].saturating_sub(earlier.counts[index]);
        }
        out
    }

    /// 各桶计数(持久化用;顺序 = [`BOUNDS_MS`] + 溢出桶)。
    #[must_use]
    pub fn counts(&self) -> Vec<i64> {
        self.counts.iter().map(|&count| count as i64).collect()
    }

    /// 从持久化的桶计数还原;长度不符(桶界改过)时多余的丢弃、缺的补 0。
    #[must_use]
    pub fn from_counts(counts: &[i64]) -> Histogram {
        let mut histogram = Histogram::default();
        for (slot, &count) in histogram.counts.iter_mut().zip(counts.iter()) {
            *slot = u64::try_from(count).unwrap_or(0);
        }
        histogram
    }

    /// 分位数估计(桶内线性插值);没有样本 → None。落在溢出桶 → 返回最后一个上界(10s)。
    #[must_use]
    pub fn quantile(&self, quantile: f64) -> Option<f64> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        let target = quantile.clamp(0.0, 1.0) * total as f64;
        let mut cumulative = 0.0;
        for (index, &count) in self.counts.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let next = cumulative + count as f64;
            if next >= target {
                if index == SLOTS - 1 {
                    return Some(BOUNDS_MS[BOUNDS_MS.len() - 1]);
                }
                let lower = if index == 0 {
                    0.0
                } else {
                    BOUNDS_MS[index - 1]
                };
                let upper = BOUNDS_MS[index];
                let fraction = ((target - cumulative) / count as f64).clamp(0.0, 1.0);
                return Some(lower + (upper - lower) * fraction);
            }
            cumulative = next;
        }
        Some(BOUNDS_MS[BOUNDS_MS.len() - 1])
    }
}

/// 持久化桶计数 → 直方图(值到值的转换,同 [`Histogram::from_counts`])。
impl From<&[i64]> for Histogram {
    fn from(counts: &[i64]) -> Self {
        Histogram::from_counts(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_matches_from_counts() {
        let mut recorded = Histogram::default();
        recorded.record(3.0);
        recorded.record(800.0);
        let counts = recorded.counts();
        let converted: Histogram = Histogram::from(counts.as_slice());
        assert_eq!(converted.counts(), Histogram::from_counts(&counts).counts());
        assert_eq!(converted.total(), 2);
    }

    #[test]
    fn empty_has_no_quantile() {
        assert_eq!(Histogram::default().quantile(0.95), None);
    }

    #[test]
    fn quantile_interpolates_within_bucket() {
        let mut histogram = Histogram::default();
        for _ in 0..100 {
            histogram.record(7.0); // 落在 (5, 10] 桶
        }
        let p50 = histogram.quantile(0.5).unwrap();
        assert!((5.0..=10.0).contains(&p50), "p50={p50}");
    }

    #[test]
    fn slow_tail_moves_p95_not_p50() {
        let mut histogram = Histogram::default();
        for _ in 0..90 {
            histogram.record(3.0);
        }
        for _ in 0..10 {
            histogram.record(800.0);
        }
        assert!(histogram.quantile(0.5).unwrap() <= 5.0);
        assert!(histogram.quantile(0.95).unwrap() > 500.0);
    }

    #[test]
    fn since_subtracts_and_saturates() {
        let mut larger = Histogram::default();
        larger.record(1.0);
        larger.record(1.0);
        let mut smaller = Histogram::default();
        smaller.record(1.0);
        assert_eq!(larger.since(&smaller).total(), 1);
        assert_eq!(smaller.since(&larger).total(), 0);
    }

    #[test]
    fn overflow_reports_last_bound() {
        let mut histogram = Histogram::default();
        histogram.record(60_000.0);
        assert_eq!(histogram.quantile(0.99), Some(10_000.0));
    }
}
