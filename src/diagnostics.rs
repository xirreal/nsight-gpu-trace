//! Evidence-labeled, top-down views over a complete metric scan.
//!
//! This module is deliberately secondary to the raw catalog and evaluator.
//! Metric availability and values are facts; thresholds here are heuristics.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{MetricAvailability, MetricKind, MetricScan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticFinding {
    pub severity: DiagnosticSeverity,
    pub category: String,
    pub metric_name: String,
    pub sample_mean: f64,
    pub sample_p95: Option<f64>,
    pub sample_max: Option<f64>,
    pub sample_coverage_pct: f64,
    pub heuristic_threshold: String,
    pub message: String,
    pub heuristic: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricCategorySummary {
    pub category: String,
    pub available_metrics: usize,
    pub nonzero_metrics: usize,
    pub top_percent_of_peak: Vec<MetricAvailability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SamplingSummary {
    pub selected_samples: usize,
    pub timestamped_samples: usize,
    pub complete_samples: usize,
    pub sample_duration_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEvidence {
    pub active_metric: String,
    pub elapsed_metric: String,
    pub active_ratio: f64,
    pub idle_ratio: f64,
    pub heuristic: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopDownReport {
    pub chip_name: String,
    pub selected_samples: usize,
    pub sampling: SamplingSummary,
    pub scanned_metric_bases: usize,
    pub available_metric_bases: usize,
    pub unavailable_metric_bases: usize,
    pub activity: Option<ActivityEvidence>,
    pub methodology: Vec<String>,
    pub categories: Vec<MetricCategorySummary>,
    pub top_percent_of_peak: Vec<MetricAvailability>,
    pub throughput_cluster: Vec<MetricAvailability>,
    pub throughput_cluster_spread_pct_points: Option<f64>,
    pub findings: Vec<DiagnosticFinding>,
    pub limitations: Vec<String>,
}

/// Build a compact report from a scan of arbitrary metric bases.
pub fn top_down_report(scan: &MetricScan, top: usize) -> TopDownReport {
    let top = top.max(1);
    let available_metric_bases = scan
        .metrics
        .iter()
        .filter(|metric| metric.valid_samples > 0)
        .count();
    let mut grouped: BTreeMap<&str, Vec<&MetricAvailability>> = BTreeMap::new();
    for metric in scan
        .metrics
        .iter()
        .filter(|metric| metric.valid_samples > 0)
    {
        grouped
            .entry(metric_category(&metric.base_name))
            .or_default()
            .push(metric);
    }

    let mut findings = Vec::new();
    let mut categories = Vec::new();
    for (category, metrics) in grouped {
        let mut throughputs: Vec<_> = metrics
            .iter()
            .filter(|metric| metric.kind == MetricKind::Throughput)
            .map(|metric| (*metric).clone())
            .collect();
        sort_by_pressure_desc(&mut throughputs);
        throughputs.truncate(top);
        if let Some(hottest) = throughputs.first()
            && hottest.sample_coverage_pct >= 50.0
        {
            let mean = pressure_mean(hottest);
            let p95 = hottest.p95;
            if let Some(mean) = mean
                && mean >= 60.0
            {
                let (severity, threshold) = if mean >= 80.0 {
                    (
                        DiagnosticSeverity::High,
                        ">= 80% of peak, duration weighted",
                    )
                } else {
                    (
                        DiagnosticSeverity::Medium,
                        ">= 60% of peak, duration weighted",
                    )
                };
                findings.push(DiagnosticFinding {
                    severity,
                    category: category.to_owned(),
                    metric_name: hottest.metric_name.clone(),
                    sample_mean: mean,
                    sample_p95: p95,
                    sample_max: hottest.max,
                    sample_coverage_pct: hottest.sample_coverage_pct,
                    heuristic_threshold: threshold.to_owned(),
                    message: format!(
                        "The highest collected {category} throughput was {mean:.2}% of peak on a duration-weighted basis (p95 {:.2}%); use timing and neighboring subsystem metrics to test whether it is the active limiter.",
                        p95.unwrap_or(mean)
                    ),
                    heuristic: true,
                });
            } else if let Some(p95) = p95
                && p95 >= 60.0
            {
                let severity = if p95 >= 80.0 {
                    DiagnosticSeverity::High
                } else {
                    DiagnosticSeverity::Medium
                };
                findings.push(DiagnosticFinding {
                    severity,
                    category: category.to_owned(),
                    metric_name: hottest.metric_name.clone(),
                    sample_mean: mean.unwrap_or(0.0),
                    sample_p95: Some(p95),
                    sample_max: hottest.max,
                    sample_coverage_pct: hottest.sample_coverage_pct,
                    heuristic_threshold: "p95 >= 60% of peak while the duration-weighted mean is lower"
                        .into(),
                    message: format!(
                        "Burst pressure: {category} throughput reached {p95:.2}% of peak at p95 but averaged {:.2}% over the window. Mean-only thresholds hide short saturated phases; inspect timing buckets and per-sample series before treating this as sustained pressure.",
                        mean.unwrap_or(0.0)
                    ),
                    heuristic: true,
                });
            }
        }
        categories.push(MetricCategorySummary {
            category: category.to_owned(),
            available_metrics: metrics.len(),
            nonzero_metrics: metrics
                .iter()
                .filter(|metric| metric.nonzero_samples > 0)
                .count(),
            top_percent_of_peak: throughputs,
        });
    }

    let activity = activity_evidence(scan);
    if let Some(activity) = &activity {
        let (severity, threshold) = if activity.active_ratio < 0.20 {
            (DiagnosticSeverity::High, "active ratio < 0.20")
        } else if activity.active_ratio < 0.50 {
            (DiagnosticSeverity::Medium, "active ratio < 0.50")
        } else {
            (DiagnosticSeverity::Info, "active ratio >= 0.50")
        };
        findings.push(DiagnosticFinding {
            severity,
            category: "activity_sync".into(),
            metric_name: activity.active_metric.clone(),
            sample_mean: activity.active_ratio,
            sample_p95: None,
            sample_max: None,
            sample_coverage_pct: 100.0,
            heuristic_threshold: threshold.into(),
            message: format!(
                "The GR compute queue was active for {:.1}% of elapsed cycles (idle {:.1}%); investigate submission gaps, waits, and CPU feed before attributing the window to shader or memory pressure.",
                activity.active_ratio * 100.0,
                activity.idle_ratio * 100.0
            ),
            heuristic: true,
        });
    }

    let category_pressure: BTreeMap<_, _> = categories
        .iter()
        .map(|category| {
            (
                category.category.as_str(),
                category
                    .top_percent_of_peak
                    .first()
                    .and_then(pressure_mean)
                    .unwrap_or(0.0),
            )
        })
        .collect();
    let mut low_hit_rates: Vec<_> = scan
        .metrics
        .iter()
        .filter(|metric| {
            metric.kind == MetricKind::Ratio
                && metric.valid_samples > 0
                && metric.nonzero_samples > 0
                && metric.sample_coverage_pct >= 50.0
                && metric.base_name.to_ascii_lowercase().contains("hit_rate")
                && pressure_mean(metric).is_some_and(|mean| mean < 0.5)
                && category_pressure
                    .get(metric_category(&metric.base_name))
                    .is_some_and(|throughput| *throughput >= 20.0)
        })
        .collect();
    low_hit_rates.sort_by(|left, right| {
        pressure_mean(left)
            .unwrap_or(f64::INFINITY)
            .total_cmp(&pressure_mean(right).unwrap_or(f64::INFINITY))
    });
    for metric in low_hit_rates.into_iter().take(3) {
        let mean = pressure_mean(metric).unwrap();
        findings.push(DiagnosticFinding {
            severity: DiagnosticSeverity::Medium,
            category: metric_category(&metric.base_name).to_owned(),
            metric_name: metric.metric_name.clone(),
            sample_mean: mean,
            sample_p95: metric.p95,
            sample_max: metric.max,
            sample_coverage_pct: metric.sample_coverage_pct,
            heuristic_threshold: "< 0.50 ratio".into(),
            message: format!(
                "The collected cache hit ratio averaged {mean:.3}; correlate misses with L2/VRAM traffic before changing access patterns."
            ),
            heuristic: true,
        });
    }

    let mut top_percent_of_peak: Vec<_> = scan
        .metrics
        .iter()
        .filter(|metric| metric.kind == MetricKind::Throughput && metric.valid_samples > 0)
        .cloned()
        .collect();
    sort_by_pressure_desc(&mut top_percent_of_peak);
    top_percent_of_peak.truncate(top);
    let cluster_reference = top_percent_of_peak
        .first()
        .and_then(|metric| metric.p95.or(metric.time_weighted_mean));
    let throughput_cluster: Vec<_> = cluster_reference
        .map(|reference| {
            top_percent_of_peak
                .iter()
                .take(5)
                .filter(|metric| {
                    metric
                        .p95
                        .or(metric.time_weighted_mean)
                        .is_some_and(|value| reference - value <= 10.0)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let throughput_cluster_spread_pct_points = throughput_cluster
        .first()
        .and_then(|metric| metric.p95.or(metric.time_weighted_mean))
        .zip(
            throughput_cluster
                .iter()
                .filter_map(|metric| metric.p95.or(metric.time_weighted_mean))
                .reduce(f64::min),
        )
        .map(|(highest, lowest)| highest - lowest);
    if throughput_cluster.len() > 1
        && let Some(reference) = cluster_reference
    {
        findings.push(DiagnosticFinding {
            severity: DiagnosticSeverity::Info,
            category: "limiter_cluster".into(),
            metric_name: throughput_cluster[0].metric_name.clone(),
            sample_mean: reference,
            sample_p95: throughput_cluster[0].p95,
            sample_max: throughput_cluster[0].max,
            sample_coverage_pct: throughput_cluster[0].sample_coverage_pct,
            heuristic_threshold: "top throughputs within 10 percentage points at p95".into(),
            message: format!(
                "{} collected throughputs are within {:.2} percentage points at p95. Treat them as a limiter cluster rather than forcing a single winner; use timing and neighboring units to separate pressure from backpressure.",
                throughput_cluster.len(),
                throughput_cluster_spread_pct_points.unwrap_or(0.0)
            ),
            heuristic: true,
        });
    }
    findings.sort_by_key(|finding| match finding.severity {
        DiagnosticSeverity::High => 0,
        DiagnosticSeverity::Medium => 1,
        DiagnosticSeverity::Info => 2,
    });

    TopDownReport {
        chip_name: scan.chip_name.clone(),
        selected_samples: scan.selected_samples,
        sampling: SamplingSummary {
            selected_samples: scan.selected_samples,
            timestamped_samples: scan.timestamped_samples,
            complete_samples: scan.complete_samples,
            sample_duration_ns: scan.sample_duration_ns,
        },
        scanned_metric_bases: scan.metrics.len(),
        available_metric_bases,
        unavailable_metric_bases: scan.metrics.len() - available_metric_bases,
        activity,
        methodology: vec![
            "Check GPU activity, timing buckets, synchronization, and frame pacing.".into(),
            "Compare SM and fixed-function percent-of-peak throughputs, including p95/max bursts.".into(),
            "Follow memory traffic through L1TEX, L2, VRAM, and PCIe.".into(),
            "Inspect occupancy, launch limits, warp stalls, and shader source/debug evidence.".into(),
        ],
        categories,
        top_percent_of_peak,
        throughput_cluster,
        throughput_cluster_spread_pct_points,
        findings,
        limitations: vec![
            "A finite metric value means the evaluator could compute it from this capture; null/unavailable never means zero.".into(),
            "A high utilization value identifies pressure, not causality. Confirm it in a timestamped scope and compare adjacent pipeline units.".into(),
            "Duration-weighted means and weighted p50/p95 describe the sampling window. A high p95 with a lower mean is burst pressure, not sustained pressure.".into(),
            "Canonical counter scans use native units; only throughput metrics in this report are directly ranked as percent of peak.".into(),
            "The activity ratio uses GR compute active cycles over elapsed cycles when both are collected; it is not a whole-GPU idle measurement.".into(),
            "Warp-state/source conclusions require shader-profiler payloads and matching debug information in the trace.".into(),
            "Coalesced timestamp buckets cannot be attributed to individual actions unless the capture timed every action.".into(),
        ],
    }
}

fn pressure_mean(metric: &MetricAvailability) -> Option<f64> {
    metric.time_weighted_mean.or(metric.sample_mean)
}

fn sort_by_pressure_desc(metrics: &mut [MetricAvailability]) {
    metrics.sort_by(|left, right| {
        right
            .p95
            .or(right.time_weighted_mean)
            .unwrap_or(f64::NEG_INFINITY)
            .total_cmp(
                &left
                    .p95
                    .or(left.time_weighted_mean)
                    .unwrap_or(f64::NEG_INFINITY),
            )
    });
}

fn activity_evidence(scan: &MetricScan) -> Option<ActivityEvidence> {
    let find = |name: &str| {
        scan.metrics
            .iter()
            .find(|metric| metric.base_name == name && metric.valid_samples > 0)
    };
    let active = find("gr__compute_cycles_active_queue_sync")
        .or_else(|| find("gr__compute_cycles_active"))
        .or_else(|| find("gpu__cycles_active"))?;
    let elapsed = find("gr__cycles_elapsed").or_else(|| find("gpu__cycles_elapsed"))?;
    let active_value = pressure_mean(active)?;
    let elapsed_value = pressure_mean(elapsed)?;
    if elapsed_value <= 0.0 {
        return None;
    }
    let active_ratio = (active_value / elapsed_value).clamp(0.0, 1.0);
    Some(ActivityEvidence {
        active_metric: active.metric_name.clone(),
        elapsed_metric: elapsed.metric_name.clone(),
        active_ratio,
        idle_ratio: 1.0 - active_ratio,
        heuristic: true,
    })
}

pub(crate) fn metric_category(name: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    if name.starts_with("sm__") || name.starts_with("smsp__") || name.starts_with("tpc__") {
        "shader"
    } else if name.starts_with("l1tex__") || name.starts_with("tex__") {
        "memory_l1tex"
    } else if name.starts_with("lts__") || name.starts_with("ltc__") || name.starts_with("syslts__")
    {
        "memory_l2"
    } else if name.starts_with("dram__") || name.starts_with("fbpa__") {
        "memory_vram"
    } else if name.starts_with("pcie__")
        || name.starts_with("nvlink__")
        || name.starts_with("sys__")
    {
        "interconnect"
    } else if name.starts_with("rtcore__") || name.contains("ray") {
        "ray_tracing"
    } else if ["pd__", "vaf__", "vpc__", "pes__", "gcc__"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        "geometry_frontend"
    } else if ["raster__", "prop__", "zrop__", "crop__"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        "raster_backend"
    } else if name.starts_with("ce__") || name.starts_with("copy__") {
        "copy_engines"
    } else if name.starts_with("nvenc__")
        || name.starts_with("nvdec__")
        || name.starts_with("display__")
    {
        "video_display"
    } else if name.starts_with("gpu__")
        || name.starts_with("gr__")
        || name.contains("idle")
        || name.contains("wait")
    {
        "activity_sync"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_throughput_is_labeled_as_a_heuristic() {
        let scan = MetricScan {
            chip_name: "test".into(),
            sample_start: 0,
            sample_stop: 4,
            selected_samples: 4,
            timestamped_samples: 4,
            complete_samples: 4,
            sample_duration_ns: 40,
            metrics: vec![MetricAvailability {
                base_name: "sm__throughput".into(),
                metric_name: "sm__throughput.avg.pct_of_peak_sustained_elapsed".into(),
                kind: MetricKind::Throughput,
                unit_hint: "percent_of_peak".into(),
                valid_samples: 4,
                selected_samples: 4,
                sample_coverage_pct: 100.0,
                nonzero_samples: 4,
                sample_mean: Some(85.0),
                time_weighted_mean: Some(85.0),
                min: Some(80.0),
                max: Some(90.0),
                p50: Some(85.0),
                p95: Some(90.0),
                stddev: Some(3.5),
                burst_ratio: Some(90.0 / 85.0),
                peak_sample_index: Some(3),
            }],
        };
        let report = top_down_report(&scan, 10);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].heuristic);
        assert_eq!(report.findings[0].severity, DiagnosticSeverity::High);
    }
}
