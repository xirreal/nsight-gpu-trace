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
pub struct TopDownReport {
    pub chip_name: String,
    pub selected_samples: usize,
    pub scanned_metric_bases: usize,
    pub available_metric_bases: usize,
    pub unavailable_metric_bases: usize,
    pub methodology: Vec<String>,
    pub categories: Vec<MetricCategorySummary>,
    pub top_percent_of_peak: Vec<MetricAvailability>,
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
        sort_by_mean_desc(&mut throughputs);
        throughputs.truncate(top);
        if let Some(hottest) = throughputs.first()
            && let Some(mean) = hottest.sample_mean
            && hottest.sample_coverage_pct >= 50.0
            && mean >= 60.0
        {
            let (severity, threshold) = if mean >= 80.0 {
                (DiagnosticSeverity::High, ">= 80% of peak")
            } else {
                (DiagnosticSeverity::Medium, ">= 60% of peak")
            };
            findings.push(DiagnosticFinding {
                severity,
                category: category.to_owned(),
                metric_name: hottest.metric_name.clone(),
                sample_mean: mean,
                sample_coverage_pct: hottest.sample_coverage_pct,
                heuristic_threshold: threshold.to_owned(),
                message: format!(
                    "The highest collected {category} throughput averaged {mean:.2}% of peak; use timing and neighboring subsystem metrics to test whether it is the active limiter."
                ),
                heuristic: true,
            });
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

    let category_pressure: BTreeMap<_, _> = categories
        .iter()
        .map(|category| {
            (
                category.category.as_str(),
                category
                    .top_percent_of_peak
                    .first()
                    .and_then(|metric| metric.sample_mean)
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
                && metric.sample_mean.is_some_and(|mean| mean < 0.5)
                && category_pressure
                    .get(metric_category(&metric.base_name))
                    .is_some_and(|throughput| *throughput >= 20.0)
        })
        .collect();
    low_hit_rates.sort_by(|left, right| {
        left.sample_mean
            .unwrap_or(f64::INFINITY)
            .total_cmp(&right.sample_mean.unwrap_or(f64::INFINITY))
    });
    for metric in low_hit_rates.into_iter().take(3) {
        let mean = metric.sample_mean.unwrap();
        findings.push(DiagnosticFinding {
            severity: DiagnosticSeverity::Medium,
            category: metric_category(&metric.base_name).to_owned(),
            metric_name: metric.metric_name.clone(),
            sample_mean: mean,
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
    sort_by_mean_desc(&mut top_percent_of_peak);
    top_percent_of_peak.truncate(top);
    findings.sort_by_key(|finding| match finding.severity {
        DiagnosticSeverity::High => 0,
        DiagnosticSeverity::Medium => 1,
        DiagnosticSeverity::Info => 2,
    });

    TopDownReport {
        chip_name: scan.chip_name.clone(),
        selected_samples: scan.selected_samples,
        scanned_metric_bases: scan.metrics.len(),
        available_metric_bases,
        unavailable_metric_bases: scan.metrics.len() - available_metric_bases,
        methodology: vec![
            "Check GPU activity, timing buckets, synchronization, and frame pacing.".into(),
            "Compare SM and fixed-function percent-of-peak throughputs.".into(),
            "Follow memory traffic through L1TEX, L2, VRAM, and PCIe.".into(),
            "Inspect occupancy, launch limits, warp stalls, and shader source/debug evidence.".into(),
        ],
        categories,
        top_percent_of_peak,
        findings,
        limitations: vec![
            "A finite metric value means the evaluator could compute it from this capture; null/unavailable never means zero.".into(),
            "A high utilization value identifies pressure, not causality. Confirm it in a timestamped scope and compare adjacent pipeline units.".into(),
            "Canonical counter scans use native units; only throughput metrics in this report are directly ranked as percent of peak.".into(),
            "Warp-state/source conclusions require shader-profiler payloads and matching debug information in the trace.".into(),
            "Coalesced timestamp buckets cannot be attributed to individual actions unless the capture timed every action.".into(),
        ],
    }
}

fn sort_by_mean_desc(metrics: &mut [MetricAvailability]) {
    metrics.sort_by(|left, right| {
        right
            .sample_mean
            .unwrap_or(f64::NEG_INFINITY)
            .total_cmp(&left.sample_mean.unwrap_or(f64::NEG_INFINITY))
    });
}

fn metric_category(name: &str) -> &'static str {
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
            metrics: vec![MetricAvailability {
                base_name: "sm__throughput".into(),
                metric_name: "sm__throughput.avg.pct_of_peak_sustained_elapsed".into(),
                kind: MetricKind::Throughput,
                valid_samples: 4,
                selected_samples: 4,
                sample_coverage_pct: 100.0,
                nonzero_samples: 4,
                sample_mean: Some(85.0),
                min: Some(80.0),
                max: Some(90.0),
            }],
        };
        let report = top_down_report(&scan, 10);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].heuristic);
        assert_eq!(report.findings[0].severity, DiagnosticSeverity::High);
    }
}
