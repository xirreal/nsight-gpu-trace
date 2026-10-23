//! Capture identity and measurement-quality evidence.
//!
//! Quality checks describe whether a capture can support a claim. They do not
//! choose an optimization or decide that a change is good.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Value, json};

use crate::{Analysis, InfoTable, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityStatus {
    Pass,
    Warn,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct QualityCheck {
    pub code: String,
    pub status: QualityStatus,
    pub message: String,
    pub evidence: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CaptureEnvironment {
    pub computer: Option<String>,
    pub operating_system: Option<String>,
    pub gpu: Option<String>,
    pub chip: Option<String>,
    pub driver: Option<String>,
    pub product_version: Option<String>,
    pub api: Option<String>,
    pub process: Option<String>,
    pub command_line: Option<String>,
    pub settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CounterCoverage {
    pub available: bool,
    pub chip_name: Option<String>,
    pub total_ranges: usize,
    pub populated_ranges: usize,
    pub completed_ranges: usize,
    pub timestamped_ranges: usize,
    pub sample_duration_ns: u64,
    pub median_sample_duration_ns: Option<u64>,
    pub max_sample_gap_ns: Option<u64>,
    pub populated_pct: f64,
    pub complete_pct: f64,
    pub timestamped_pct: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TimingCoverage {
    pub calls: usize,
    pub timestamped_calls: usize,
    pub timestamped_call_pct: f64,
    pub timing_buckets: usize,
    pub single_call_buckets: usize,
    pub shared_call_buckets: usize,
    pub frames: usize,
    pub debug_groups: usize,
    pub nvtx_ranges: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureQuality {
    pub status: QualityStatus,
    pub environment: CaptureEnvironment,
    pub counters: CounterCoverage,
    pub timing: TimingCoverage,
    pub checks: Vec<QualityCheck>,
}

impl Analysis {
    pub fn environment(&self) -> CaptureEnvironment {
        environment_from_tables(&self.info_tables())
    }

    /// Materialize counter metadata to describe measurement coverage. This does
    /// not evaluate metrics and does not choose a limiter.
    pub fn quality(&mut self) -> Result<CaptureQuality> {
        let environment = self.environment();
        let mut counters = CounterCoverage::default();
        let mut checks = Vec::new();

        match self.counter_info() {
            Ok(info) => {
                let info = info.clone();
                let samples = self.counter_samples()?.to_vec();
                let populated = info.periodic_sampler.populated_ranges;
                let completed = info.periodic_sampler.completed_ranges;
                let timestamped = samples
                    .iter()
                    .filter(|sample| sample.timestamp_valid)
                    .count();
                let mut durations: Vec<u64> = samples
                    .iter()
                    .filter_map(|sample| sample.duration_ns)
                    .collect();
                durations.sort_unstable();
                let median = durations.get(durations.len() / 2).copied();
                let mut max_gap = 0u64;
                let mut previous_end = None;
                for sample in samples.iter().filter(|sample| sample.timestamp_valid) {
                    if let Some(end) = previous_end {
                        max_gap = max_gap.max(sample.timestamp_start_ns.saturating_sub(end));
                    }
                    previous_end = Some(sample.timestamp_end_ns);
                }
                counters = CounterCoverage {
                    available: true,
                    chip_name: Some(info.chip_name.clone()),
                    total_ranges: info.periodic_sampler.total_ranges,
                    populated_ranges: populated,
                    completed_ranges: completed,
                    timestamped_ranges: timestamped,
                    sample_duration_ns: durations.iter().sum(),
                    median_sample_duration_ns: median,
                    max_sample_gap_ns: (max_gap > 0).then_some(max_gap),
                    populated_pct: percent(populated, info.periodic_sampler.total_ranges),
                    complete_pct: percent(completed, populated),
                    timestamped_pct: percent(timestamped, populated),
                };
                checks.push(quality_check(
                    "counter_image",
                    QualityStatus::Pass,
                    "PerfWorks counter image is available.",
                    json!({ "chip_name": info.chip_name, "ranges": info.periodic_sampler.total_ranges }),
                ));
                checks.push(threshold_check(
                    "counter_completeness",
                    counters.complete_pct,
                    90.0,
                    50.0,
                    "Completed periodic samples",
                    json!({
                        "completed_ranges": completed,
                        "populated_ranges": populated,
                    }),
                ));
                checks.push(threshold_check(
                    "counter_timestamps",
                    counters.timestamped_pct,
                    90.0,
                    50.0,
                    "Timestamped periodic samples",
                    json!({
                        "timestamped_ranges": timestamped,
                        "populated_ranges": populated,
                    }),
                ));
                let timing_span = self
                    .timing_buckets()
                    .iter()
                    .filter_map(|bucket| bucket.interval())
                    .fold(None::<(u64, u64)>, |span, interval| {
                        Some(match span {
                            Some((start, end)) => (start.min(interval.0), end.max(interval.1)),
                            None => interval,
                        })
                    });
                let sample_span = samples
                    .iter()
                    .find(|sample| sample.timestamp_valid)
                    .zip(samples.iter().rev().find(|sample| sample.timestamp_valid))
                    .map(|(first, last)| (first.timestamp_start_ns, last.timestamp_end_ns));
                if let (Some((timing_start, timing_end)), Some((sample_start, sample_end))) =
                    (timing_span, sample_span)
                {
                    let outside = timing_start < sample_start || timing_end > sample_end;
                    if outside {
                        checks.push(quality_check(
                            "counter_timing_window",
                            QualityStatus::Warn,
                            "API timing buckets extend outside the periodic counter window; metrics for regions near the edges may be null or partial.",
                            json!({
                                "timing_window_ns": [timing_start, timing_end],
                                "counter_window_ns": [sample_start, sample_end],
                            }),
                        ));
                    } else {
                        checks.push(quality_check(
                            "counter_timing_window",
                            QualityStatus::Pass,
                            "API timing buckets fit inside the periodic counter window.",
                            json!({
                                "timing_window_ns": [timing_start, timing_end],
                                "counter_window_ns": [sample_start, sample_end],
                            }),
                        ));
                    }
                }
                if let Some(median) = median {
                    let gap = max_gap;
                    let ratio = if median == 0 {
                        0.0
                    } else {
                        gap as f64 / median as f64
                    };
                    if ratio > 4.0 {
                        checks.push(quality_check(
                            "counter_window_gaps",
                            QualityStatus::Warn,
                            &format!(
                                "The largest gap between timestamped samples is {gap} ns ({ratio:.1}x the median sample duration); the counter window is not continuous."
                            ),
                            json!({ "max_gap_ns": gap, "median_sample_duration_ns": median }),
                        ));
                    } else {
                        checks.push(quality_check(
                            "counter_window_gaps",
                            QualityStatus::Pass,
                            "Timestamped samples form a continuous window.",
                            json!({ "max_gap_ns": gap, "median_sample_duration_ns": median }),
                        ));
                    }
                }
            }
            Err(error) => {
                counters.available = false;
                checks.push(quality_check(
                    "counter_image",
                    QualityStatus::Warn,
                    &format!("Counter/metric evidence is unavailable: {error}"),
                    json!(null),
                ));
            }
        }

        let calls = self.calls().len();
        let covered: std::collections::BTreeSet<_> = self
            .timing_buckets()
            .iter()
            .flat_map(|bucket| bucket.first_global_call_index..bucket.next_global_call_index)
            .collect();
        let shared = self
            .timing_buckets()
            .iter()
            .filter(|bucket| bucket.call_count > 1)
            .count();
        let timing = TimingCoverage {
            calls,
            timestamped_calls: covered.len(),
            timestamped_call_pct: percent(covered.len(), calls),
            timing_buckets: self.timing_buckets().len(),
            single_call_buckets: self.timing_buckets().len().saturating_sub(shared),
            shared_call_buckets: shared,
            frames: self.frames().len(),
            debug_groups: self.debug_groups().len(),
            nvtx_ranges: self.nvtx_ranges().len(),
        };
        checks.push(threshold_check(
            "call_timestamp_coverage",
            timing.timestamped_call_pct,
            90.0,
            50.0,
            "Calls covered by timestamp buckets",
            json!({
                "timestamped_calls": timing.timestamped_calls,
                "calls": timing.calls,
            }),
        ));
        if timing.timing_buckets == 0 {
            checks.push(quality_check(
                "timing_buckets",
                QualityStatus::Fail,
                "No timestamp buckets are available; scope timing cannot be computed.",
                json!(null),
            ));
        } else if timing.shared_call_buckets * 2 > timing.timing_buckets {
            checks.push(quality_check(
                "action_attribution",
                QualityStatus::Warn,
                &format!(
                    "{} of {} timing buckets contain multiple calls; per-action timing and metric attribution is unavailable for those buckets.",
                    timing.shared_call_buckets, timing.timing_buckets
                ),
                json!({
                    "shared_call_buckets": timing.shared_call_buckets,
                    "timing_buckets": timing.timing_buckets,
                }),
            ));
        } else {
            checks.push(quality_check(
                "action_attribution",
                QualityStatus::Pass,
                "Most timing buckets contain a single call.",
                json!({
                    "shared_call_buckets": timing.shared_call_buckets,
                    "timing_buckets": timing.timing_buckets,
                }),
            ));
        }
        if timing.frames == 0 {
            checks.push(quality_check(
                "frame_markers",
                QualityStatus::Warn,
                "No presented or application frames were captured; frame pacing and frame-level deltas are unavailable.",
                json!(null),
            ));
        }

        if environment.gpu.is_none() || environment.driver.is_none() {
            checks.push(quality_check(
                "environment_identity",
                QualityStatus::Warn,
                "GPU or driver identity is missing from the capture info tables; A/B comparability cannot be checked.",
                json!({
                    "gpu": environment.gpu,
                    "driver": environment.driver,
                }),
            ));
        }
        if let Some(clocks) = environment.settings.get("GPU Clocks") {
            let clocks_lower = clocks.to_ascii_lowercase();
            if !clocks_lower.contains("locked") {
                checks.push(quality_check(
                    "gpu_clocks",
                    QualityStatus::Warn,
                    &format!("GPU clocks are not reported as locked ({clocks}); timing deltas may include clock variation."),
                    json!({ "GPU Clocks": clocks }),
                ));
            } else if clocks_lower.contains("boost") {
                checks.push(quality_check(
                    "gpu_clocks",
                    QualityStatus::Warn,
                    &format!("GPU clocks are locked to boost ({clocks}); this measures attainable peak rather than a fixed-base A/B comparison."),
                    json!({ "GPU Clocks": clocks }),
                ));
            }
        }
        if let Some(vsync) = environment.settings.get("V-Sync Mode")
            && !vsync.to_ascii_lowercase().contains("off")
        {
            checks.push(quality_check(
                "vsync",
                QualityStatus::Warn,
                &format!("V-Sync is not disabled ({vsync}); frame timing may be quantized."),
                json!({ "V-Sync Mode": vsync }),
            ));
        }
        if let Some(every_action) = environment.settings.get("Time Every Action")
            && every_action.eq_ignore_ascii_case("no")
        {
            checks.push(quality_check(
                "time_every_action",
                QualityStatus::Warn,
                "Time Every Action was disabled; action-level timing depends on shared timestamp buckets.",
                json!({ "Time Every Action": every_action }),
            ));
        }

        let status = checks
            .iter()
            .map(|check| check.status)
            .max()
            .unwrap_or(QualityStatus::Unknown);
        Ok(CaptureQuality {
            status,
            environment,
            counters,
            timing,
            checks,
        })
    }
}

fn environment_from_tables(tables: &[InfoTable]) -> CaptureEnvironment {
    let mut environment = CaptureEnvironment::default();
    let mut settings = BTreeMap::new();
    for table in tables {
        let table_name = table.name.as_deref().unwrap_or_default();
        for entry in &table.entries {
            let name = entry.name.as_deref().unwrap_or_default().trim();
            let value = entry.value.as_deref().unwrap_or_default().trim();
            match (table_name, name) {
                ("System", "Computer Name") => environment.computer = Some(value.into()),
                ("System", "Operating System") => environment.operating_system = Some(value.into()),
                ("GPU", "Device Name") => environment.gpu = Some(value.into()),
                ("GPU", "Chip Name") => environment.chip = Some(value.into()),
                ("GPU", "Driver Version") => environment.driver = Some(value.into()),
                ("Session", "Product Version") => environment.product_version = Some(value.into()),
                ("Session", "API") => environment.api = Some(value.into()),
                ("Session", "Process File Name") => environment.process = Some(value.into()),
                ("Session", "Command Line") => environment.command_line = Some(value.into()),
                ("Session Settings", _) => {
                    settings.insert(name.to_owned(), value.to_owned());
                }
                _ => {}
            }
        }
    }
    environment.settings = settings;
    environment
}

fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * part as f64 / total as f64
    }
}

fn threshold_check(
    code: &str,
    value: f64,
    pass_at: f64,
    fail_below: f64,
    label: &str,
    evidence: Value,
) -> QualityCheck {
    let (status, message) = if value >= pass_at {
        (QualityStatus::Pass, format!("{label}: {value:.1}%."))
    } else if value < fail_below {
        (
            QualityStatus::Fail,
            format!("{label}: {value:.1}% is below the usable threshold of {fail_below:.0}%."),
        )
    } else {
        (
            QualityStatus::Warn,
            format!("{label}: {value:.1}% is below the preferred {pass_at:.0}%."),
        )
    };
    quality_check(code, status, &message, evidence)
}

fn quality_check(
    code: &str,
    status: QualityStatus,
    message: &str,
    evidence: Value,
) -> QualityCheck {
    QualityCheck {
        code: code.into(),
        status,
        message: message.into(),
        evidence,
    }
}
