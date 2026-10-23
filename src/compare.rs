//! Side-by-side capture evidence for the external optimization loop.
//!
//! The comparison reports deltas and uncertainty. It does not accept or reject
//! a change; that decision belongs to the caller.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::Serialize;

use crate::{
    Analysis, CaptureEnvironment, CaptureQuality, CounterCoverage, MetricAvailability, MetricKind,
    QualityStatus, Result, Scope, ScopeKind, ScopeMetricAggregation, ScopedMetrics, ShaderCatalog,
    TimingCoverage,
};

#[derive(Debug, Clone)]
pub struct CompareOptions {
    pub top: usize,
    pub scope_kind: Option<ScopeKind>,
    pub scope_pattern: Option<Regex>,
    pub include_shaders: bool,
    /// Optional exact metric names for scope-level deltas. When empty, the
    /// comparison selects the most changed capture-wide metrics.
    pub scope_metrics: Vec<String>,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            top: 20,
            scope_kind: None,
            scope_pattern: None,
            include_shaders: true,
            scope_metrics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureReference {
    pub path: String,
    pub quality: QualityStatus,
    pub environment: CaptureEnvironment,
    pub counters: CounterCoverage,
    pub timing: TimingCoverage,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparabilityWarning {
    pub code: String,
    pub message: String,
    pub baseline: serde_json::Value,
    pub candidate: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparability {
    /// False when the captures differ on identity fields that cannot be
    /// normalized by the analyzer (GPU, driver, API, product version).
    pub comparable: bool,
    pub warnings: Vec<ComparabilityWarning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricValues {
    pub sample_mean: Option<f64>,
    pub time_weighted_mean: Option<f64>,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub max: Option<f64>,
    pub coverage_pct: f64,
    pub valid_samples: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricDelta {
    pub base_name: String,
    pub metric_name: String,
    pub kind: MetricKind,
    pub baseline: MetricValues,
    pub candidate: MetricValues,
    pub mean_delta: Option<f64>,
    pub mean_relative_pct: Option<f64>,
    pub p95_delta: Option<f64>,
    pub p95_relative_pct: Option<f64>,
    pub coverage_delta_pct: f64,
    /// Weighted bootstrap interval for the difference in means.
    pub mean_delta_ci95: Option<(f64, f64)>,
    pub ci_includes_zero: Option<bool>,
    pub bootstrap_iterations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeMetricDelta {
    pub metric_name: String,
    pub baseline_mean: Option<f64>,
    pub candidate_mean: Option<f64>,
    pub delta: Option<f64>,
    pub relative_pct: Option<f64>,
    pub baseline_coverage_pct: f64,
    pub candidate_coverage_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeDelta {
    pub scope_id: String,
    pub label: String,
    pub kind: ScopeKind,
    pub baseline_duration_ns: Option<u64>,
    pub candidate_duration_ns: Option<u64>,
    pub duration_delta_ns: Option<i64>,
    pub duration_relative_pct: Option<f64>,
    pub metrics: Vec<ScopeMetricDelta>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShaderValues {
    pub cubin_sha256: Option<String>,
    pub cubin_size: Option<usize>,
    pub registers_per_thread: Option<u32>,
    pub sm: Option<String>,
    pub stage: String,
    pub entry_point: Option<String>,
    pub source_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShaderChange {
    Unchanged,
    Changed,
    Added,
    Removed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShaderDelta {
    pub name: String,
    pub entry_point: Option<String>,
    pub stage: String,
    pub change: ShaderChange,
    pub baseline: Option<ShaderValues>,
    pub candidate: Option<ShaderValues>,
    pub register_delta: Option<i32>,
    pub cubin_size_delta: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureComparison {
    pub baseline: CaptureReference,
    pub candidate: CaptureReference,
    pub comparability: Comparability,
    pub metric_summary: BTreeMap<String, usize>,
    pub metrics: Vec<MetricDelta>,
    pub scope_kind: Option<ScopeKind>,
    pub scopes: Vec<ScopeDelta>,
    pub shaders: Vec<ShaderDelta>,
    pub shader_note: Option<String>,
    pub limitations: Vec<String>,
}

pub fn compare_captures(
    baseline: &mut Analysis,
    candidate: &mut Analysis,
    options: &CompareOptions,
) -> Result<CaptureComparison> {
    let baseline_quality = baseline.quality()?;
    let candidate_quality = candidate.quality()?;
    let baseline_scan = baseline.scan_all_metrics()?;
    let candidate_scan = candidate.scan_all_metrics()?;

    let baseline_by_name: BTreeMap<_, _> = baseline_scan
        .metrics
        .iter()
        .filter(|metric| metric.valid_samples > 0)
        .map(|metric| (metric.metric_name.clone(), metric))
        .collect();
    let candidate_by_name: BTreeMap<_, _> = candidate_scan
        .metrics
        .iter()
        .filter(|metric| metric.valid_samples > 0)
        .map(|metric| (metric.metric_name.clone(), metric))
        .collect();
    let common: BTreeSet<_> = baseline_by_name
        .keys()
        .filter(|name| candidate_by_name.contains_key(*name))
        .cloned()
        .collect();

    let mut deltas: Vec<MetricDelta> = common
        .iter()
        .filter_map(|name| {
            let baseline_metric = *baseline_by_name.get(name)?;
            let candidate_metric = *candidate_by_name.get(name)?;
            Some(metric_delta(baseline_metric, candidate_metric))
        })
        .collect();
    deltas.sort_by(|left, right| {
        metric_priority(right)
            .cmp(&metric_priority(left))
            .then_with(|| change_score(right).total_cmp(&change_score(left)))
    });

    let selected: Vec<String> = deltas
        .iter()
        .take(options.top.max(8))
        .map(|delta| delta.metric_name.clone())
        .collect();
    if !selected.is_empty() {
        let baseline_scope = baseline.capture_scope();
        let candidate_scope = candidate.capture_scope();
        let baseline_eval = baseline.evaluate_scope(&baseline_scope, &selected)?;
        let candidate_eval = candidate.evaluate_scope(&candidate_scope, &selected)?;
        for delta in &mut deltas {
            let base_values = sample_values(&baseline_eval, &delta.metric_name);
            let cand_values = sample_values(&candidate_eval, &delta.metric_name);
            if let Some((low, high)) = weighted_bootstrap_ci(&base_values, &cand_values, 512) {
                delta.mean_delta_ci95 = Some((low, high));
                delta.ci_includes_zero = Some(low <= 0.0 && high >= 0.0);
                delta.bootstrap_iterations = 512;
            }
        }
    }
    deltas.truncate(options.top.max(1));

    let scope_metrics = if options.scope_metrics.is_empty() {
        let mut names: Vec<_> = deltas
            .iter()
            .filter(|delta| delta.kind != MetricKind::Counter)
            .map(|delta| delta.metric_name.clone())
            .collect();
        if names.len() < 8 {
            let mut candidates: Vec<_> = baseline_scan
                .metrics
                .iter()
                .filter(|metric| {
                    metric.valid_samples > 0
                        && matches!(metric.kind, MetricKind::Throughput | MetricKind::Ratio)
                })
                .collect();
            candidates.sort_by(|left, right| {
                right
                    .p95
                    .unwrap_or(f64::NEG_INFINITY)
                    .total_cmp(&left.p95.unwrap_or(f64::NEG_INFINITY))
            });
            for metric in candidates {
                if names.len() >= 16 {
                    break;
                }
                if !names.contains(&metric.metric_name) {
                    names.push(metric.metric_name.clone());
                }
            }
        }
        names.truncate(16);
        names
    } else {
        options.scope_metrics.clone()
    };

    let (scopes, scope_kind, scope_warning) =
        compare_scopes(baseline, candidate, options, &scope_metrics)?;

    let (shaders, shader_note) = if options.include_shaders {
        compare_shaders(baseline, candidate, options.top.max(1))
    } else {
        (
            Vec::new(),
            Some("Shader comparison disabled by options.".into()),
        )
    };

    let comparability = comparability(&baseline_quality, &candidate_quality);
    let metrics_count = baseline_scan.metrics.len();
    let candidate_metrics_count = candidate_scan.metrics.len();
    let mut metric_summary = BTreeMap::new();
    metric_summary.insert("baseline_metrics".into(), metrics_count);
    metric_summary.insert("candidate_metrics".into(), candidate_metrics_count);
    metric_summary.insert("common_metrics".into(), common.len());
    metric_summary.insert("returned_metrics".into(), deltas.len());

    let mut limitations = vec![
        "Capture-wide means are duration weighted; scope means use the metric sample overlap rule.".into(),
        "Bootstrap intervals describe sampling noise inside each capture, not run-to-run noise or code causality.".into(),
        "Scope matching uses kind, label, and occurrence order. Renamed or inserted regions reduce match quality.".into(),
        "The comparison reports evidence only. Accepting or rejecting a change requires an external decision policy and repeat captures.".into(),
    ];
    if let Some(warning) = scope_warning {
        limitations.push(warning);
    }
    if let Some(note) = &shader_note {
        limitations.push(note.clone());
    }

    Ok(CaptureComparison {
        baseline: capture_reference(baseline, baseline_quality),
        candidate: capture_reference(candidate, candidate_quality),
        comparability,
        metric_summary,
        metrics: deltas,
        scope_kind,
        scopes,
        shaders,
        shader_note,
        limitations,
    })
}

fn metric_delta(baseline: &MetricAvailability, candidate: &MetricAvailability) -> MetricDelta {
    let baseline_values = metric_values(baseline);
    let candidate_values = metric_values(candidate);
    let mean_delta = baseline_values
        .time_weighted_mean
        .zip(candidate_values.time_weighted_mean)
        .map(|(left, right)| right - left);
    let p95_delta = baseline_values
        .p95
        .zip(candidate_values.p95)
        .map(|(left, right)| right - left);
    MetricDelta {
        base_name: baseline.base_name.clone(),
        metric_name: baseline.metric_name.clone(),
        kind: baseline.kind,
        mean_delta,
        mean_relative_pct: relative_change(
            baseline_values.time_weighted_mean,
            candidate_values.time_weighted_mean,
        ),
        p95_delta,
        p95_relative_pct: relative_change(baseline_values.p95, candidate_values.p95),
        coverage_delta_pct: candidate_values.coverage_pct - baseline_values.coverage_pct,
        baseline: baseline_values,
        candidate: candidate_values,
        mean_delta_ci95: None,
        ci_includes_zero: None,
        bootstrap_iterations: 0,
    }
}

fn metric_values(metric: &MetricAvailability) -> MetricValues {
    MetricValues {
        sample_mean: metric.sample_mean,
        time_weighted_mean: metric.time_weighted_mean.or(metric.sample_mean),
        p50: metric.p50,
        p95: metric.p95,
        max: metric.max,
        coverage_pct: metric.sample_coverage_pct,
        valid_samples: metric.valid_samples,
    }
}

fn relative_change(baseline: Option<f64>, candidate: Option<f64>) -> Option<f64> {
    let baseline = baseline?;
    let candidate = candidate?;
    if baseline == 0.0 {
        return None;
    }
    Some((candidate - baseline) / baseline * 100.0)
}

fn metric_priority(delta: &MetricDelta) -> u8 {
    match delta.kind {
        MetricKind::Throughput => 4,
        MetricKind::Ratio => 3,
        MetricKind::Counter => {
            let name = delta.base_name.to_ascii_lowercase();
            if [
                "throughput",
                "duration",
                "time_",
                "_time",
                "active",
                "idle",
                "stall",
                "occupancy",
                "warp",
                "sector",
                "bytes",
                "cycles",
            ]
            .iter()
            .any(|token| name.contains(token))
            {
                2
            } else {
                1
            }
        }
    }
}

fn change_score(delta: &MetricDelta) -> f64 {
    let relative = delta
        .mean_relative_pct
        .or(delta.p95_relative_pct)
        .map(f64::abs)
        .unwrap_or(0.0);
    let absolute = delta.mean_delta.map(f64::abs).unwrap_or(0.0);
    relative.max(absolute)
}

fn sample_values(evaluation: &ScopedMetrics, metric: &str) -> Vec<(f64, f64)> {
    evaluation
        .samples
        .iter()
        .filter_map(|sample| {
            let value = sample.values.get(metric).copied().flatten()?;
            if !value.is_finite() {
                return None;
            }
            let weight = sample.duration_ns.unwrap_or(1).max(1) as f64;
            Some((value, weight))
        })
        .collect()
}

fn weighted_bootstrap_ci(
    baseline: &[(f64, f64)],
    candidate: &[(f64, f64)],
    iterations: usize,
) -> Option<(f64, f64)> {
    if baseline.len() < 2 || candidate.len() < 2 {
        return None;
    }
    let mut rng = Lcg::new(0x9e37_79b9_7f4a_7c15);
    let mut differences = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let baseline_mean = resampled_weighted_mean(baseline, &mut rng);
        let candidate_mean = resampled_weighted_mean(candidate, &mut rng);
        differences.push(candidate_mean - baseline_mean);
    }
    differences.sort_by(f64::total_cmp);
    let low = differences[(differences.len() as f64 * 0.025) as usize];
    let high = differences[((differences.len() - 1) as f64 * 0.975) as usize];
    Some((low, high))
}

fn resampled_weighted_mean(values: &[(f64, f64)], rng: &mut Lcg) -> f64 {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for _ in 0..values.len() {
        let (value, weight) = values[(rng.next() as usize) % values.len()];
        weighted_sum += value * weight;
        total_weight += weight;
    }
    if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    }
}

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

fn compare_scopes(
    baseline: &mut Analysis,
    candidate: &mut Analysis,
    options: &CompareOptions,
    metrics: &[String],
) -> Result<(Vec<ScopeDelta>, Option<ScopeKind>, Option<String>)> {
    let kind = options.scope_kind.or_else(|| {
        [
            ScopeKind::DebugGroup,
            ScopeKind::Frame,
            ScopeKind::TimingBucket,
            ScopeKind::NvtxRange,
            ScopeKind::Action,
        ]
        .into_iter()
        .find(|kind| {
            baseline
                .scopes(*kind)
                .map(|scopes| !scopes.is_empty())
                .unwrap_or(false)
        })
    });
    let Some(kind) = kind else {
        return Ok((
            Vec::new(),
            None,
            Some("No matching scope family is available for scope-level comparison.".into()),
        ));
    };
    let mut baseline_scopes = baseline.scopes(kind)?;
    let mut candidate_scopes = candidate.scopes(kind)?;
    let filter = |scopes: &mut Vec<Scope>| {
        if let Some(pattern) = &options.scope_pattern {
            scopes.retain(|scope| pattern.is_match(&scope.id) || pattern.is_match(&scope.label));
        }
        scopes.sort_by(|left, right| {
            right
                .duration_ns()
                .cmp(&left.duration_ns())
                .then_with(|| left.id.cmp(&right.id))
        });
        scopes.truncate(options.top.max(8) * 4);
    };
    filter(&mut baseline_scopes);
    filter(&mut candidate_scopes);
    if baseline_scopes.is_empty() || candidate_scopes.is_empty() {
        return Ok((
            Vec::new(),
            Some(kind),
            Some("The selected scope family is empty on one capture.".into()),
        ));
    }

    let baseline_keys = scope_keys(&baseline_scopes);
    let candidate_keys = scope_keys(&candidate_scopes);
    let mut matched = Vec::new();
    for (key, index) in &baseline_keys {
        if let Some(candidate_index) = candidate_keys.get(key) {
            matched.push((
                baseline_scopes[*index].clone(),
                candidate_scopes[*candidate_index].clone(),
            ));
        }
    }
    if matched.is_empty() {
        return Ok((
            Vec::new(),
            Some(kind),
            Some("No scopes matched by kind, label, and occurrence order.".into()),
        ));
    }
    let baseline_input: Vec<_> = matched.iter().map(|(scope, _)| scope.clone()).collect();
    let candidate_input: Vec<_> = matched.iter().map(|(_, scope)| scope.clone()).collect();
    let baseline_metrics = baseline.aggregate_scope_metrics(&baseline_input, metrics)?;
    let candidate_metrics = candidate.aggregate_scope_metrics(&candidate_input, metrics)?;
    let mut scopes =
        combine_scope_metrics(&matched, &baseline_metrics, &candidate_metrics, metrics);
    scopes.sort_by(|left, right| {
        let left_score = duration_score(left);
        let right_score = duration_score(right);
        right_score.total_cmp(&left_score)
    });
    scopes.truncate(options.top.max(1));
    Ok((scopes, Some(kind), None))
}

fn scope_keys(scopes: &[Scope]) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut keys = BTreeMap::new();
    for (index, scope) in scopes.iter().enumerate() {
        let base = format!("{:?}|{}", scope.kind, scope.label);
        let occurrence = counts.entry(base.clone()).or_default();
        let key = format!("{base}|{occurrence}");
        *occurrence += 1;
        keys.insert(key, index);
    }
    keys
}

fn combine_scope_metrics(
    matched: &[(Scope, Scope)],
    baseline: &ScopeMetricAggregation,
    candidate: &ScopeMetricAggregation,
    metrics: &[String],
) -> Vec<ScopeDelta> {
    matched
        .iter()
        .enumerate()
        .map(|(index, (baseline_scope, candidate_scope))| {
            let baseline_summary = baseline.scopes.get(index).map(|summary| &summary.summary);
            let candidate_summary = candidate.scopes.get(index).map(|summary| &summary.summary);
            let metric_deltas = metrics
                .iter()
                .map(|metric| {
                    let left = baseline_summary.and_then(|summary| summary.get(metric));
                    let right = candidate_summary.and_then(|summary| summary.get(metric));
                    ScopeMetricDelta {
                        metric_name: metric.clone(),
                        baseline_mean: left.and_then(|statistics| statistics.mean),
                        candidate_mean: right.and_then(|statistics| statistics.mean),
                        delta: left
                            .and_then(|left| left.mean)
                            .zip(right.and_then(|right| right.mean))
                            .map(|(left, right)| right - left),
                        relative_pct: relative_change(
                            left.and_then(|statistics| statistics.mean),
                            right.and_then(|statistics| statistics.mean),
                        ),
                        baseline_coverage_pct: left
                            .map(|statistics| statistics.coverage_pct)
                            .unwrap_or(0.0),
                        candidate_coverage_pct: right
                            .map(|statistics| statistics.coverage_pct)
                            .unwrap_or(0.0),
                    }
                })
                .collect();
            let baseline_duration = baseline_scope.duration_ns();
            let candidate_duration = candidate_scope.duration_ns();
            ScopeDelta {
                scope_id: baseline_scope.id.clone(),
                label: baseline_scope.label.clone(),
                kind: baseline_scope.kind,
                baseline_duration_ns: baseline_duration,
                candidate_duration_ns: candidate_duration,
                duration_delta_ns: baseline_duration
                    .zip(candidate_duration)
                    .map(|(left, right)| right as i64 - left as i64),
                duration_relative_pct: relative_change(
                    baseline_duration.map(|value| value as f64),
                    candidate_duration.map(|value| value as f64),
                ),
                metrics: metric_deltas,
            }
        })
        .collect()
}

fn duration_score(scope: &ScopeDelta) -> f64 {
    let duration = scope.duration_relative_pct.map(f64::abs).unwrap_or(0.0);
    let metric = scope
        .metrics
        .iter()
        .filter_map(|metric| metric.relative_pct)
        .map(f64::abs)
        .fold(0.0, f64::max);
    duration.max(metric)
}

fn compare_shaders(
    baseline: &Analysis,
    candidate: &Analysis,
    top: usize,
) -> (Vec<ShaderDelta>, Option<String>) {
    let baseline_catalog = match baseline.shader_catalog() {
        Ok(catalog) => catalog,
        Err(error) => {
            return (
                Vec::new(),
                Some(format!("Baseline shader inventory is unavailable: {error}")),
            );
        }
    };
    let candidate_catalog = match candidate.shader_catalog() {
        Ok(catalog) => catalog,
        Err(error) => {
            return (
                Vec::new(),
                Some(format!(
                    "Candidate shader inventory is unavailable: {error}"
                )),
            );
        }
    };
    let baseline_map = shader_map(&baseline_catalog);
    let candidate_map = shader_map(&candidate_catalog);
    let keys: BTreeSet<_> = baseline_map
        .keys()
        .chain(candidate_map.keys())
        .cloned()
        .collect();
    let mut shaders = Vec::new();
    for key in keys {
        let baseline = baseline_map.get(&key);
        let candidate = candidate_map.get(&key);
        let change = match (baseline, candidate) {
            (Some(left), Some(right)) if left.cubin_sha256 == right.cubin_sha256 => {
                ShaderChange::Unchanged
            }
            (Some(_), Some(_)) => ShaderChange::Changed,
            (Some(_), None) => ShaderChange::Removed,
            (None, Some(_)) => ShaderChange::Added,
            (None, None) => continue,
        };
        let name = baseline
            .or(candidate)
            .map(|shader| shader.name.clone())
            .unwrap_or_default();
        let entry_point = baseline
            .or(candidate)
            .and_then(|shader| shader.entry_point.clone());
        let stage = baseline
            .or(candidate)
            .map(|shader| shader.stage.clone())
            .unwrap_or_default();
        shaders.push(ShaderDelta {
            name,
            entry_point,
            stage,
            change,
            baseline: baseline.copied().map(shader_values),
            candidate: candidate.copied().map(shader_values),
            register_delta: baseline
                .and_then(|left| left.registers_per_thread)
                .zip(candidate.and_then(|right| right.registers_per_thread))
                .map(|(left, right)| right as i32 - left as i32),
            cubin_size_delta: baseline
                .and_then(|left| left.cubin_size)
                .zip(candidate.and_then(|right| right.cubin_size))
                .map(|(left, right)| right as i64 - left as i64),
        });
    }
    shaders.sort_by_key(|shader| match shader.change {
        ShaderChange::Changed => 0,
        ShaderChange::Added => 1,
        ShaderChange::Removed => 2,
        ShaderChange::Unchanged => 3,
    });
    shaders.truncate(top);
    (shaders, None)
}

fn shader_map(catalog: &ShaderCatalog) -> BTreeMap<String, &crate::ShaderInfo> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut map = BTreeMap::new();
    for shader in catalog.shaders() {
        let base = format!(
            "{}|{}|{}",
            shader.name,
            shader.entry_point.as_deref().unwrap_or_default(),
            shader.stage
        );
        let occurrence = counts.entry(base.clone()).or_default();
        map.insert(format!("{base}|{occurrence}"), shader);
        *occurrence += 1;
    }
    map
}

fn shader_values(shader: &crate::ShaderInfo) -> ShaderValues {
    ShaderValues {
        cubin_sha256: shader.cubin_sha256.clone(),
        cubin_size: shader.cubin_size,
        registers_per_thread: shader.registers_per_thread,
        sm: shader.sm.clone(),
        stage: shader.stage.clone(),
        entry_point: shader.entry_point.clone(),
        source_file: shader.source_file.clone(),
    }
}

fn capture_reference(analysis: &Analysis, quality: CaptureQuality) -> CaptureReference {
    CaptureReference {
        path: analysis.document().container().path.display().to_string(),
        quality: quality.status,
        environment: quality.environment,
        counters: quality.counters,
        timing: quality.timing,
        checks: quality
            .checks
            .iter()
            .filter(|check| check.status != QualityStatus::Pass)
            .map(|check| format!("{}: {}", check.code, check.message))
            .collect(),
    }
}

fn comparability(baseline: &CaptureQuality, candidate: &CaptureQuality) -> Comparability {
    let mut warnings = Vec::new();
    let mut compare = |code: &str, label: &str, left: &Option<String>, right: &Option<String>| {
        if left != right && (left.is_some() || right.is_some()) {
            warnings.push(ComparabilityWarning {
                code: code.into(),
                message: format!("{label} differs between captures."),
                baseline: serde_json::json!(left),
                candidate: serde_json::json!(right),
            });
        }
    };
    compare(
        "gpu",
        "GPU",
        &baseline.environment.gpu,
        &candidate.environment.gpu,
    );
    compare(
        "chip",
        "Chip",
        &baseline.environment.chip,
        &candidate.environment.chip,
    );
    compare(
        "driver",
        "Driver version",
        &baseline.environment.driver,
        &candidate.environment.driver,
    );
    compare(
        "product_version",
        "Nsight product version",
        &baseline.environment.product_version,
        &candidate.environment.product_version,
    );
    compare(
        "api",
        "Graphics API",
        &baseline.environment.api,
        &candidate.environment.api,
    );
    for key in [
        "V-Sync Mode",
        "GPU Clocks",
        "Time Every Action",
        "Metric Set",
    ] {
        let left = baseline.environment.settings.get(key);
        let right = candidate.environment.settings.get(key);
        if left != right && (left.is_some() || right.is_some()) {
            warnings.push(ComparabilityWarning {
                code: format!("setting:{key}"),
                message: format!("Capture setting {key} differs between captures."),
                baseline: serde_json::json!(left),
                candidate: serde_json::json!(right),
            });
        }
    }
    let identity_mismatch = warnings.iter().any(|warning| {
        matches!(
            warning.code.as_str(),
            "gpu" | "chip" | "driver" | "product_version" | "api"
        )
    });
    Comparability {
        comparable: !identity_mismatch,
        warnings,
    }
}
