//! 固定分桶的延迟直方图(毫秒)。够算 p50 / p95 / p99,内存恒定、可加可减(窗口统计 = 两次累计快照相减)。

/// 桶上界(毫秒);最后还有一个溢出桶(> 10s)。
pub const BOUNDS_MS: [f64; 13] = [
    1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];
const SLOTS: usize = BOUNDS_MS.len() + 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hist {
    counts: [u64; SLOTS],
}

impl Hist {
    pub fn record(&mut self, ms: f64) {
        let slot = BOUNDS_MS.iter().position(|b| ms <= *b).unwrap_or(SLOTS - 1);
        self.counts[slot] += 1;
    }

    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    pub fn add(&mut self, other: &Hist) {
        for (a, b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a += b;
        }
    }

    /// `self - earlier`(累计值只增不减;饱和减法防御重置)。
    pub fn since(&self, earlier: &Hist) -> Hist {
        let mut out = Hist::default();
        for (i, slot) in out.counts.iter_mut().enumerate() {
            *slot = self.counts[i].saturating_sub(earlier.counts[i]);
        }
        out
    }

    /// 各桶计数(持久化用;顺序 = [`BOUNDS_MS`] + 溢出桶)。
    pub fn counts(&self) -> Vec<i64> {
        self.counts.iter().map(|c| *c as i64).collect()
    }

    /// 从持久化的桶计数还原;长度不符(桶界改过)时多余的丢弃、缺的补 0。
    pub fn from_counts(counts: &[i64]) -> Hist {
        let mut h = Hist::default();
        for (slot, c) in h.counts.iter_mut().zip(counts.iter()) {
            *slot = (*c).max(0) as u64;
        }
        h
    }

    /// 分位数估计(桶内线性插值);没有样本 → None。落在溢出桶 → 返回最后一个上界(10s)。
    pub fn quantile(&self, q: f64) -> Option<f64> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        let target = q.clamp(0.0, 1.0) * total as f64;
        let mut cum = 0.0;
        for (i, &c) in self.counts.iter().enumerate() {
            if c == 0 {
                continue;
            }
            let next = cum + c as f64;
            if next >= target {
                if i == SLOTS - 1 {
                    return Some(BOUNDS_MS[BOUNDS_MS.len() - 1]);
                }
                let lower = if i == 0 { 0.0 } else { BOUNDS_MS[i - 1] };
                let upper = BOUNDS_MS[i];
                let frac = ((target - cum) / c as f64).clamp(0.0, 1.0);
                return Some(lower + (upper - lower) * frac);
            }
            cum = next;
        }
        Some(BOUNDS_MS[BOUNDS_MS.len() - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_quantile() {
        assert_eq!(Hist::default().quantile(0.95), None);
    }

    #[test]
    fn quantile_interpolates_within_bucket() {
        let mut h = Hist::default();
        for _ in 0..100 {
            h.record(7.0); // 落在 (5, 10] 桶
        }
        let p50 = h.quantile(0.5).unwrap();
        assert!((5.0..=10.0).contains(&p50), "p50={p50}");
    }

    #[test]
    fn slow_tail_moves_p95_not_p50() {
        let mut h = Hist::default();
        for _ in 0..90 {
            h.record(3.0);
        }
        for _ in 0..10 {
            h.record(800.0);
        }
        assert!(h.quantile(0.5).unwrap() <= 5.0);
        assert!(h.quantile(0.95).unwrap() > 500.0);
    }

    #[test]
    fn since_subtracts_and_saturates() {
        let mut a = Hist::default();
        a.record(1.0);
        a.record(1.0);
        let mut b = Hist::default();
        b.record(1.0);
        assert_eq!(a.since(&b).total(), 1);
        assert_eq!(b.since(&a).total(), 0);
    }

    #[test]
    fn overflow_reports_last_bound() {
        let mut h = Hist::default();
        h.record(60_000.0);
        assert_eq!(h.quantile(0.99), Some(10_000.0));
    }
}
