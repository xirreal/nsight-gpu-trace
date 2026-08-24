use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use prost_reflect::{DynamicMessage, Kind, ReflectMessage, Value};
use serde::Serialize;

use crate::{
    Error, Result, TraceDocument,
    perfworks::{
        CounterImage, CounterImageInfo, MetricBase, MetricCatalog, MetricDescriptor,
        MetricEvaluation, MetricSample, MetricScan, MetricsApi, PerfWorks, SampleInfo,
    },
};

#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    pub schema_binary: Option<PathBuf>,
    pub nvperf_library: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Draw,
    Dispatch,
    Copy,
    Clear,
    Sync,
    Marker,
    Present,
    Other,
}

impl CallKind {
    pub fn classify(name: &str) -> Self {
        let name = name.to_ascii_lowercase();
        if name.contains("draw") {
            Self::Draw
        } else if name.contains("dispatch") {
            Self::Dispatch
        } else if ["copy", "blit", "resolve"]
            .iter()
            .any(|word| name.contains(word))
        {
            Self::Copy
        } else if name.contains("clear") {
            Self::Clear
        } else if ["barrier", "wait", "fence", "semaphore"]
            .iter()
            .any(|word| name.contains(word))
        {
            Self::Sync
        } else if ["marker", "debuggroup", "label", "beginevent", "endevent"]
            .iter()
            .any(|word| name.contains(word))
        {
            Self::Marker
        } else if name.contains("present") || name.contains("swapbuffers") {
            Self::Present
        } else {
            Self::Other
        }
    }

    pub fn is_action(self) -> bool {
        self != Self::Marker
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiCall {
    pub global_index: usize,
    pub device_index: usize,
    pub queue_index: usize,
    pub stream_index: usize,
    pub call_index: usize,
    pub name: String,
    pub kind: CallKind,
    pub interface: Option<String>,
    pub arguments: Vec<serde_json::Value>,
    pub return_value: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimestampValue {
    pub stage: String,
    pub ptimer: u64,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimestampBoundary {
    pub device_index: usize,
    pub queue_index: usize,
    pub stream_index: usize,
    pub timestamp_index: usize,
    pub next_call_index: usize,
    pub values: Vec<TimestampValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimingStage {
    pub stage: String,
    pub start_ptimer: u64,
    pub end_ptimer: u64,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimingBucket {
    pub index: usize,
    pub device_index: usize,
    pub queue_index: usize,
    pub stream_index: usize,
    pub start_timestamp_index: usize,
    pub end_timestamp_index: usize,
    pub first_call_index: usize,
    pub next_call_index: usize,
    pub first_global_call_index: usize,
    pub next_global_call_index: usize,
    pub call_count: usize,
    pub call_histogram: BTreeMap<String, usize>,
    pub call_kinds: BTreeMap<CallKind, usize>,
    pub stages: Vec<TimingStage>,
    pub max_duration_ns: Option<u64>,
}

impl TimingBucket {
    pub fn interval(&self) -> Option<(u64, u64)> {
        self.stages
            .iter()
            .find(|stage| stage.stage == "PB_PIPELINE_STAGE_BOTTOM_OF_PIPE")
            .or_else(|| self.stages.first())
            .map(|stage| (stage.start_ptimer, stage.end_ptimer))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Frame {
    pub id: String,
    pub device_index: usize,
    pub swapchain_index: usize,
    pub kind: String,
    pub index: usize,
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
    pub application_frame_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugGroup {
    pub id: String,
    pub name: String,
    pub device_index: usize,
    pub queue_index: usize,
    pub stream_index: usize,
    pub depth: usize,
    pub parent_id: Option<String>,
    pub open_call_index: usize,
    pub close_call_index: Option<usize>,
    pub call_start: usize,
    pub call_stop: usize,
    pub closed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NvtxRange {
    pub id: String,
    pub range_kind: String,
    pub index: usize,
    pub name: String,
    pub domain: String,
    pub start: u64,
    pub end: u64,
    pub thread_id: Option<u64>,
    pub start_thread_id: Option<u64>,
    pub end_thread_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Capture,
    SampleRange,
    TimeRange,
    CallRange,
    Action,
    DebugGroup,
    NvtxRange,
    Frame,
    TimingBucket,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scope {
    pub kind: ScopeKind,
    pub id: String,
    pub label: String,
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub call_start: Option<usize>,
    pub call_stop: Option<usize>,
    pub sample_start: Option<usize>,
    pub sample_stop: Option<usize>,
    pub precision: String,
    pub warnings: Vec<String>,
}

impl Scope {
    pub fn duration_ns(&self) -> Option<u64> {
        self.start_ns
            .zip(self.end_ns)
            .and_then(|(start, end)| end.checked_sub(start))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricStatistics {
    pub valid_samples: usize,
    pub selected_samples: usize,
    pub coverage_pct: f64,
    pub mean: Option<f64>,
    pub min: Option<f64>,
    pub min_range_index: Option<usize>,
    pub max: Option<f64>,
    pub max_range_index: Option<usize>,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub sum: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedMetrics {
    pub scope: Scope,
    pub metrics: Vec<String>,
    pub summary: BTreeMap<String, MetricStatistics>,
    pub samples: Vec<MetricSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeMetricSummary {
    pub scope: Scope,
    pub summary: BTreeMap<String, MetricStatistics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeMetricAggregation {
    pub metrics: Vec<String>,
    pub scope_count: usize,
    pub evaluated_scope_count: usize,
    pub sample_start: Option<usize>,
    pub sample_stop: Option<usize>,
    pub scopes: Vec<ScopeMetricSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricStatistic {
    Mean,
    Min,
    Max,
    P50,
    P95,
    Sum,
}

impl MetricStatistic {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "mean" => Ok(Self::Mean),
            "min" => Ok(Self::Min),
            "max" => Ok(Self::Max),
            "p50" => Ok(Self::P50),
            "p95" => Ok(Self::P95),
            "sum" => Ok(Self::Sum),
            _ => Err(Error::TracePath(format!(
                "unsupported metric statistic {value:?}"
            ))),
        }
    }

    fn value(self, statistics: &MetricStatistics) -> Option<f64> {
        match self {
            Self::Mean => statistics.mean,
            Self::Min => statistics.min,
            Self::Max => statistics.max,
            Self::P50 => statistics.p50,
            Self::P95 => statistics.p95,
            Self::Sum => statistics.sum,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RankedScope {
    pub scope: Scope,
    pub value: f64,
    pub statistics: MetricStatistics,
    pub equivalent_scope_count: usize,
    pub equivalent_scopes: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeRanking {
    pub metric: String,
    pub statistic: MetricStatistic,
    pub descending: bool,
    pub candidate_count: usize,
    pub rankable_count: usize,
    pub metric_value_count: usize,
    pub evidence_group_count: usize,
    pub unavailable_count: usize,
    pub ranked_scopes: Vec<RankedScope>,
}

struct CounterState {
    perfworks: PerfWorks,
    image: CounterImage,
    info: CounterImageInfo,
    sample_info: Vec<SampleInfo>,
}

/// Indexed, high-level view of one trace. Raw fields remain available through
/// [`Self::document`]; this index only adds convenient navigation and joins.
pub struct Analysis {
    document: TraceDocument,
    nvperf_library: Option<PathBuf>,
    api_names: Vec<String>,
    calls: Vec<ApiCall>,
    timestamps: Vec<TimestampBoundary>,
    timing_buckets: Vec<TimingBucket>,
    frames: Vec<Frame>,
    debug_groups: Vec<DebugGroup>,
    nvtx_ranges: Vec<NvtxRange>,
    counters: Option<CounterState>,
}

impl std::fmt::Debug for Analysis {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Analysis")
            .field("document", &self.document)
            .field("api_names", &self.api_names)
            .field("calls", &self.calls.len())
            .field("timestamps", &self.timestamps.len())
            .field("timing_buckets", &self.timing_buckets.len())
            .field("frames", &self.frames.len())
            .field("debug_groups", &self.debug_groups.len())
            .field("nvtx_ranges", &self.nvtx_ranges.len())
            .finish()
    }
}

impl Analysis {
    pub fn open(path: impl AsRef<Path>, options: AnalysisOptions) -> Result<Self> {
        let document = TraceDocument::open(path, options.schema_binary.as_deref())?;
        Self::from_document(document, options.nvperf_library)
    }

    pub fn from_document(document: TraceDocument, nvperf_library: Option<PathBuf>) -> Result<Self> {
        let (api_names, calls, timestamps, timing_buckets) = index_streams(document.message())?;
        let frames = index_frames(document.message())?;
        let debug_groups = index_debug_groups(&calls);
        let nvtx_ranges = index_nvtx(document.message())?;
        Ok(Self {
            document,
            nvperf_library,
            api_names,
            calls,
            timestamps,
            timing_buckets,
            frames,
            debug_groups,
            nvtx_ranges,
            counters: None,
        })
    }

    pub fn document(&self) -> &TraceDocument {
        &self.document
    }

    pub fn api_names(&self) -> &[String] {
        &self.api_names
    }

    pub fn calls(&self) -> &[ApiCall] {
        &self.calls
    }

    pub fn timestamps(&self) -> &[TimestampBoundary] {
        &self.timestamps
    }

    pub fn timing_buckets(&self) -> &[TimingBucket] {
        &self.timing_buckets
    }

    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }

    pub fn debug_groups(&self) -> &[DebugGroup] {
        &self.debug_groups
    }

    pub fn nvtx_ranges(&self) -> &[NvtxRange] {
        &self.nvtx_ranges
    }

    pub fn overview(&self) -> serde_json::Value {
        let call_histogram = histogram(self.calls.iter().map(|call| call.name.as_str()));
        let call_kinds = histogram(self.calls.iter().map(|call| call.kind));
        let longest: Vec<_> = {
            let mut values: Vec<_> = self.timing_buckets.iter().collect();
            values.sort_by_key(|bucket| std::cmp::Reverse(bucket.max_duration_ns));
            values.into_iter().take(20).collect()
        };
        serde_json::json!({
            "capture": self.document.container(),
            "schema_binary": self.document.schema_binary(),
            "protobuf_type": crate::trace::TRACE_MESSAGE,
            "protobuf_size": self.document.raw_protobuf().len(),
            "descriptor_files": self.document.descriptor_set().file.iter().filter_map(|file| file.name.as_deref()).collect::<Vec<_>>(),
            "unknown_wire_fields": self.document.unknown_field_count(),
            "apis": self.api_names,
            "info_tables": info_tables(self.document.message()).unwrap_or_default(),
            "calls": {
                "count": self.calls.len(),
                "actions": self.calls.iter().filter(|call| call.kind.is_action()).count(),
                "distinct_names": call_histogram.len(),
                "histogram": call_histogram,
                "kinds": call_kinds,
            },
            "timestamps": self.timestamps.len(),
            "timing_buckets": {
                "count": self.timing_buckets.len(),
                "longest": longest,
            },
            "frames": self.frames,
            "debug_group_count": self.debug_groups.len(),
            "nvtx_range_count": self.nvtx_ranges.len(),
            "main_indices": {
                "device": optional_u64(self.document.message(), "mainDeviceIndex"),
                "swapchain": optional_u64(self.document.message(), "mainSwapChainIndex"),
            },
        })
    }

    pub fn capture_scope(&self) -> Scope {
        Scope {
            kind: ScopeKind::Capture,
            id: "capture".into(),
            label: self
                .document
                .container()
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            start_ns: None,
            end_ns: None,
            call_start: None,
            call_stop: None,
            sample_start: None,
            sample_stop: None,
            precision: "periodic_samples".into(),
            warnings: Vec::new(),
        }
    }

    pub fn scope_for_time(
        &self,
        start_ns: u64,
        end_ns: u64,
        id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<Scope> {
        if start_ns > end_ns {
            return Err(Error::TracePath(format!(
                "invalid time range [{start_ns}, {end_ns})"
            )));
        }
        Ok(Scope {
            kind: ScopeKind::TimeRange,
            id: id.into(),
            label: label.into(),
            start_ns: Some(start_ns),
            end_ns: Some(end_ns),
            call_start: None,
            call_stop: None,
            sample_start: None,
            sample_stop: None,
            precision: "explicit".into(),
            warnings: Vec::new(),
        })
    }

    pub fn scope_for_samples(
        &mut self,
        start: usize,
        stop: usize,
        id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<Scope> {
        let samples = &self.ensure_counters()?.sample_info;
        if start > stop || stop > samples.len() {
            return Err(Error::TracePath(format!(
                "invalid sample range [{start}, {stop}); capture has {} samples",
                samples.len()
            )));
        }
        let selected = &samples[start..stop];
        let valid: Vec<_> = selected
            .iter()
            .filter(|sample| sample.timestamp_valid)
            .collect();
        let mut warnings = Vec::new();
        if valid.len() != selected.len() {
            warnings.push(format!(
                "{} of {} selected samples have valid timestamps.",
                valid.len(),
                selected.len()
            ));
        }
        Ok(Scope {
            kind: ScopeKind::SampleRange,
            id: id.into(),
            label: label.into(),
            start_ns: valid.first().map(|sample| sample.timestamp_start_ns),
            end_ns: valid.last().map(|sample| sample.timestamp_end_ns),
            call_start: None,
            call_stop: None,
            sample_start: Some(start),
            sample_stop: Some(stop),
            precision: "explicit_samples".into(),
            warnings,
        })
    }

    /// Resolve a stable scope ID returned by [`Self::scopes`].
    pub fn scope_by_id(&self, id: &str) -> Result<Scope> {
        if id == "capture" {
            return Ok(self.capture_scope());
        }
        for kind in [
            ScopeKind::DebugGroup,
            ScopeKind::Frame,
            ScopeKind::Action,
            ScopeKind::TimingBucket,
            ScopeKind::NvtxRange,
        ] {
            if let Some(scope) = self.scopes(kind)?.into_iter().find(|scope| scope.id == id) {
                return Ok(scope);
            }
        }
        Err(Error::TracePath(format!("unknown scope ID {id:?}")))
    }

    /// Parse the scope syntax accepted by the CLI and MCP server.
    pub fn parse_scope(&mut self, value: &str) -> Result<Scope> {
        if value == "capture"
            || value.starts_with("debug:")
            || value.starts_with("frame:")
            || value.starts_with("action:")
            || value.starts_with("bucket:")
            || value.starts_with("nvtx:")
        {
            return self.scope_by_id(value);
        }
        if let Some(range) = value.strip_prefix("calls:") {
            let (start, stop) = parse_range::<usize>(range)?;
            return self.scope_for_calls(
                start,
                stop,
                ScopeKind::CallRange,
                value,
                format!("global calls [{start}, {stop})"),
            );
        }
        if let Some(range) = value.strip_prefix("samples:") {
            let (start, stop) = parse_range::<usize>(range)?;
            return self.scope_for_samples(
                start,
                stop,
                value,
                format!("counter samples [{start}, {stop})"),
            );
        }
        if let Some(range) = value.strip_prefix("time:") {
            let (start, stop) = parse_range::<u64>(range)?;
            return self.scope_for_time(start, stop, value, format!("PTIMER [{start}, {stop})"));
        }
        if let Some(range) = value.strip_prefix("relative-time:") {
            let (start, stop) = parse_range::<u64>(range)?;
            let origin = self
                .counter_samples()?
                .iter()
                .find(|sample| sample.timestamp_valid)
                .map(|sample| sample.timestamp_start_ns)
                .ok_or_else(|| {
                    Error::TracePath("capture has no timestamped counter sample".into())
                })?;
            let absolute_start = origin
                .checked_add(start)
                .ok_or_else(|| Error::TracePath("relative time start overflow".into()))?;
            let absolute_stop = origin
                .checked_add(stop)
                .ok_or_else(|| Error::TracePath("relative time stop overflow".into()))?;
            return self.scope_for_time(
                absolute_start,
                absolute_stop,
                value,
                format!("relative PTIMER [{start}, {stop})"),
            );
        }
        Err(Error::TracePath(format!(
            "invalid scope {value:?}; use capture, a listed scope ID, calls:A..B, samples:A..B, time:A..B, or relative-time:A..B"
        )))
    }

    pub fn scope_for_calls(
        &self,
        start: usize,
        stop: usize,
        kind: ScopeKind,
        id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<Scope> {
        if start > stop || stop > self.calls.len() {
            return Err(Error::TracePath(format!(
                "invalid global call range [{start}, {stop}); capture has {} calls",
                self.calls.len()
            )));
        }
        if start == stop {
            return Ok(Scope {
                kind,
                id: id.into(),
                label: label.into(),
                start_ns: None,
                end_ns: None,
                call_start: Some(start),
                call_stop: Some(stop),
                sample_start: None,
                sample_stop: None,
                precision: "unavailable".into(),
                warnings: vec!["Scope contains no captured API calls.".into()],
            });
        }
        let buckets: Vec<_> = self
            .timing_buckets
            .iter()
            .filter(|bucket| {
                bucket.first_global_call_index < stop
                    && bucket.next_global_call_index > start
                    && bucket.interval().is_some()
            })
            .collect();
        if buckets.is_empty() {
            return Ok(Scope {
                kind,
                id: id.into(),
                label: label.into(),
                start_ns: None,
                end_ns: None,
                call_start: Some(start),
                call_stop: Some(stop),
                sample_start: None,
                sample_stop: None,
                precision: "unavailable".into(),
                warnings: vec!["No timestamp boundary covers this call range.".into()],
            });
        }
        let intervals: Vec<_> = buckets
            .iter()
            .filter_map(|bucket| bucket.interval())
            .collect();
        let shared = buckets.iter().any(|bucket| {
            bucket.first_global_call_index < start || bucket.next_global_call_index > stop
        });
        let mut covered = vec![false; stop - start];
        for bucket in &buckets {
            let overlap_start = start.max(bucket.first_global_call_index);
            let overlap_stop = stop.min(bucket.next_global_call_index);
            for item in &mut covered[overlap_start - start..overlap_stop - start] {
                *item = true;
            }
        }
        let partial = covered.iter().any(|covered| !covered);
        let streams: BTreeSet<_> = self.calls[start..stop]
            .iter()
            .map(|call| (call.device_index, call.queue_index, call.stream_index))
            .collect();
        let mut precision = "timestamp_bounded";
        let mut warnings = Vec::new();
        if shared {
            precision = "bucket_shared";
            warnings.push("Edge timing buckets include calls outside this scope; time and metrics cannot be attributed more narrowly.".into());
        }
        if partial {
            if !shared {
                precision = "partially_timestamped";
            }
            warnings.push(format!(
                "Only {} of {} calls have timestamp-bucket coverage.",
                covered.iter().filter(|value| **value).count(),
                covered.len()
            ));
        }
        if streams.len() > 1 {
            precision = "multi_stream_envelope";
            warnings.push(
                "Timestamp bounds are an envelope across command streams, not a serial duration."
                    .into(),
            );
        }
        Ok(Scope {
            kind,
            id: id.into(),
            label: label.into(),
            start_ns: intervals.iter().map(|item| item.0).min(),
            end_ns: intervals.iter().map(|item| item.1).max(),
            call_start: Some(start),
            call_stop: Some(stop),
            sample_start: None,
            sample_stop: None,
            precision: precision.into(),
            warnings,
        })
    }

    pub fn scopes(&self, kind: ScopeKind) -> Result<Vec<Scope>> {
        match kind {
            ScopeKind::Capture => Ok(vec![self.capture_scope()]),
            ScopeKind::DebugGroup => self
                .debug_groups
                .iter()
                .map(|group| {
                    let mut scope = self.scope_for_calls(
                        group.call_start,
                        group.call_stop,
                        kind,
                        group.id.clone(),
                        group.name.clone(),
                    )?;
                    if !group.closed {
                        scope
                            .warnings
                            .push("Debug group is not closed in the capture.".into());
                    }
                    Ok(scope)
                })
                .collect(),
            ScopeKind::Action => self
                .calls
                .iter()
                .filter(|call| call.kind.is_action())
                .enumerate()
                .map(|(index, call)| {
                    self.scope_for_calls(
                        call.global_index,
                        call.global_index + 1,
                        kind,
                        format!("action:{index}"),
                        format!("{} (global call {})", call.name, call.global_index),
                    )
                })
                .collect(),
            ScopeKind::TimingBucket => self
                .timing_buckets
                .iter()
                .map(|bucket| {
                    self.scope_for_calls(
                        bucket.first_global_call_index,
                        bucket.next_global_call_index,
                        kind,
                        format!("bucket:{}", bucket.index),
                        format!("timing bucket {}", bucket.index),
                    )
                })
                .collect(),
            ScopeKind::Frame => Ok(self
                .frames
                .iter()
                .map(|frame| Scope {
                    kind,
                    id: frame.id.clone(),
                    label: format!("{} frame {}", frame.kind, frame.index),
                    start_ns: Some(frame.start_ns),
                    end_ns: Some(frame.end_ns),
                    call_start: None,
                    call_stop: None,
                    sample_start: None,
                    sample_stop: None,
                    precision: "frame_timestamps".into(),
                    warnings: Vec::new(),
                })
                .collect()),
            ScopeKind::NvtxRange => Ok(self
                .nvtx_ranges
                .iter()
                .map(|range| Scope {
                    kind,
                    id: range.id.clone(),
                    label: range.name.clone(),
                    start_ns: Some(range.start),
                    end_ns: Some(range.end),
                    call_start: None,
                    call_stop: None,
                    sample_start: None,
                    sample_stop: None,
                    precision: "nvtx_clock_unvalidated".into(),
                    warnings: vec!["Legacy NVTX clock is not assumed to match GPU PTIMER.".into()],
                })
                .collect()),
            ScopeKind::SampleRange | ScopeKind::TimeRange | ScopeKind::CallRange => Err(
                Error::TracePath(format!("{kind:?} requires explicit bounds")),
            ),
        }
    }

    /// Return bounded calls or timing buckets supporting one exact scope.
    pub fn inspect_scope(
        &self,
        scope: &Scope,
        include_arguments: bool,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        let limit = limit.clamp(1, 200);
        let mut result = serde_json::json!({ "scope": scope });
        let object = result.as_object_mut().unwrap();
        if let Some((start, stop)) = scope.call_start.zip(scope.call_stop) {
            if start > stop || stop > self.calls.len() {
                return Err(Error::TracePath(format!(
                    "scope {} has invalid call bounds [{start}, {stop})",
                    scope.id
                )));
            }
            let calls = &self.calls[start..stop];
            let page_start = offset.min(calls.len());
            let page_stop = calls.len().min(page_start.saturating_add(limit));
            let selected = if include_arguments {
                serde_json::to_value(&calls[page_start..page_stop])?
            } else {
                serde_json::Value::Array(
                    calls[page_start..page_stop]
                        .iter()
                        .map(|call| {
                            serde_json::json!({
                                "global_index": call.global_index,
                                "device_index": call.device_index,
                                "queue_index": call.queue_index,
                                "stream_index": call.stream_index,
                                "call_index": call.call_index,
                                "name": call.name,
                                "kind": call.kind,
                                "interface": call.interface,
                            })
                        })
                        .collect(),
                )
            };
            object.insert("calls".into(), selected);
            object.insert(
                "calls_page".into(),
                page(page_start, page_stop, calls.len()),
            );
            object.insert(
                "call_histogram".into(),
                serde_json::to_value(histogram(calls.iter().map(|call| call.name.as_str())))?,
            );
            object.insert(
                "call_kinds".into(),
                serde_json::to_value(histogram(calls.iter().map(|call| call.kind)))?,
            );
            object.insert(
                "child_debug_groups".into(),
                serde_json::to_value(
                    self.debug_groups
                        .iter()
                        .filter(|group| group.parent_id.as_deref() == Some(scope.id.as_str()))
                        .collect::<Vec<_>>(),
                )?,
            );
        } else if let Some((start, end)) = scope.start_ns.zip(scope.end_ns) {
            let overlapping: Vec<_> = self
                .timing_buckets
                .iter()
                .filter(|bucket| {
                    bucket.interval().is_some_and(|(bucket_start, bucket_end)| {
                        bucket_start < end && bucket_end > start
                    })
                })
                .collect();
            let page_start = offset.min(overlapping.len());
            let page_stop = overlapping.len().min(page_start.saturating_add(limit));
            object.insert(
                "timing_buckets".into(),
                serde_json::to_value(&overlapping[page_start..page_stop])?,
            );
            object.insert(
                "timing_buckets_page".into(),
                page(page_start, page_stop, overlapping.len()),
            );
        }
        object.insert(
            "attribution_rule".into(),
            serde_json::json!(
                "bucket_shared timing and metrics apply to the whole bucket, not each enclosed call"
            ),
        );
        Ok(result)
    }

    pub fn counter_info(&mut self) -> Result<&CounterImageInfo> {
        Ok(&self.ensure_counters()?.info)
    }

    pub fn counter_samples(&mut self) -> Result<&[SampleInfo]> {
        Ok(&self.ensure_counters()?.sample_info)
    }

    pub fn metric_catalog(&mut self) -> Result<MetricCatalog> {
        let api = self.metrics_api()?;
        let state = self.ensure_counters()?;
        state.perfworks.metric_catalog(api, &state.info.chip_name)
    }

    pub fn describe_metric(&mut self, metric_name: &str) -> Result<MetricDescriptor> {
        let api = self.metrics_api()?;
        let state = self.ensure_counters()?;
        state
            .perfworks
            .describe_metric(api, &state.info.chip_name, metric_name)
    }

    /// Scan selected metric bases over a sample interval. Pass a catalog's
    /// complete `metrics` vector to discover everything collected by a trace.
    pub fn scan_metrics(
        &mut self,
        metric_bases: &[MetricBase],
        start: usize,
        stop: Option<usize>,
    ) -> Result<MetricScan> {
        let api = self.metrics_api()?;
        let state = self.ensure_counters()?;
        state
            .perfworks
            .scan(api, &state.image, metric_bases, start, stop)
    }

    pub fn scan_all_metrics(&mut self) -> Result<MetricScan> {
        let catalog = self.metric_catalog()?;
        self.scan_metrics(&catalog.metrics, 0, None)
    }

    pub fn evaluate_scope(&mut self, scope: &Scope, metrics: &[String]) -> Result<ScopedMetrics> {
        let api = self.metrics_api()?;
        let resolved = self.attach_samples(scope)?;
        let start = resolved.sample_start.unwrap_or(0);
        let stop = resolved.sample_stop.unwrap_or(start);
        let evaluation = if start < stop {
            let state = self.ensure_counters()?;
            state
                .perfworks
                .evaluate(api, &state.image, metrics, start, Some(stop))?
        } else {
            MetricEvaluation {
                metrics: metrics.to_vec(),
                samples: Vec::new(),
            }
        };
        let (scope_start, scope_end) = resolved.start_ns.zip(resolved.end_ns).unwrap_or((0, 0));
        let summary = metrics
            .iter()
            .map(|metric| {
                (
                    metric.clone(),
                    metric_statistics(&evaluation.samples, metric, scope_start, scope_end),
                )
            })
            .collect();
        Ok(ScopedMetrics {
            scope: resolved,
            metrics: evaluation.metrics,
            summary,
            samples: evaluation.samples,
        })
    }

    /// Summarize several metrics for every scope with one PerfWorks evaluation
    /// over the scopes' shared sample envelope.
    pub fn aggregate_scope_metrics(
        &mut self,
        scopes: &[Scope],
        metrics: &[String],
    ) -> Result<ScopeMetricAggregation> {
        if metrics.is_empty() {
            return Ok(ScopeMetricAggregation {
                metrics: Vec::new(),
                scope_count: scopes.len(),
                evaluated_scope_count: 0,
                sample_start: None,
                sample_stop: None,
                scopes: scopes
                    .iter()
                    .cloned()
                    .map(|scope| ScopeMetricSummary {
                        scope,
                        summary: BTreeMap::new(),
                    })
                    .collect(),
            });
        }

        let mut resolved = Vec::with_capacity(scopes.len());
        for scope in scopes {
            match self.attach_samples(scope) {
                Ok(scope) => resolved.push(scope),
                Err(Error::TracePath(message)) => {
                    let mut scope = scope.clone();
                    scope
                        .warnings
                        .push(format!("Metric attribution unavailable: {message}"));
                    resolved.push(scope);
                }
                Err(error) => return Err(error),
            }
        }
        let evaluated_scope_count = resolved
            .iter()
            .filter(|scope| metric_scope_bounds(scope).is_some())
            .count();
        let sample_start = resolved
            .iter()
            .filter_map(metric_scope_bounds)
            .map(|(start, _)| start)
            .min();
        let sample_stop = resolved
            .iter()
            .filter_map(metric_scope_bounds)
            .map(|(_, stop)| stop)
            .max();
        let rows = match sample_start.zip(sample_stop) {
            Some((start, stop)) if start < stop => {
                let envelope = self.scope_for_samples(
                    start,
                    stop,
                    format!("samples:{start}..{stop}"),
                    "multi-scope metric envelope",
                )?;
                self.evaluate_scope(&envelope, metrics)?.samples
            }
            _ => Vec::new(),
        };

        Ok(ScopeMetricAggregation {
            metrics: metrics.to_vec(),
            scope_count: scopes.len(),
            evaluated_scope_count,
            sample_start,
            sample_stop,
            scopes: aggregate_metric_rows(&resolved, metrics, &rows, sample_start),
        })
    }

    /// Rank scopes with one PerfWorks evaluation over their shared sample envelope.
    pub fn rank_scopes(
        &mut self,
        scopes: &[Scope],
        metric: &str,
        statistic: MetricStatistic,
        descending: bool,
        top: usize,
    ) -> Result<ScopeRanking> {
        let candidate_count = scopes.len();
        let rankable = scopes
            .iter()
            .filter_map(|scope| self.attach_samples(scope).ok())
            .filter(|scope| {
                scope.start_ns.is_some()
                    && scope.end_ns.is_some()
                    && scope
                        .sample_start
                        .zip(scope.sample_stop)
                        .is_some_and(|(start, stop)| start < stop)
            })
            .collect::<Vec<_>>();
        if rankable.is_empty() {
            return Ok(ScopeRanking {
                metric: metric.into(),
                statistic,
                descending,
                candidate_count,
                rankable_count: 0,
                metric_value_count: 0,
                evidence_group_count: 0,
                unavailable_count: candidate_count,
                ranked_scopes: Vec::new(),
            });
        }

        let sample_start = rankable
            .iter()
            .filter_map(|scope| scope.sample_start)
            .min()
            .unwrap();
        let sample_stop = rankable
            .iter()
            .filter_map(|scope| scope.sample_stop)
            .max()
            .unwrap();
        let envelope = self.scope_for_samples(
            sample_start,
            sample_stop,
            format!("samples:{sample_start}..{sample_stop}"),
            "scope ranking envelope",
        )?;
        let requested = vec![metric.to_owned()];
        let rows = self.evaluate_scope(&envelope, &requested)?.samples;
        let mut ranked: Vec<RankedScope> = Vec::new();
        let mut evidence_groups: BTreeMap<(usize, usize, u64, u64), usize> = BTreeMap::new();
        let mut metric_value_count = 0;
        for scope in &rankable {
            let first = scope.sample_start.unwrap().saturating_sub(sample_start);
            let stop = scope
                .sample_stop
                .unwrap()
                .saturating_sub(sample_start)
                .min(rows.len());
            let (start_ns, end_ns) = scope.start_ns.zip(scope.end_ns).unwrap();
            let statistics =
                metric_statistics(&rows[first.min(stop)..stop], metric, start_ns, end_ns);
            let Some(value) = statistic.value(&statistics) else {
                continue;
            };
            metric_value_count += 1;
            let key = (
                scope.sample_start.unwrap(),
                scope.sample_stop.unwrap(),
                start_ns,
                end_ns,
            );
            if scope.kind == ScopeKind::Action
                && let Some(index) = evidence_groups.get(&key).copied()
            {
                let entry = &mut ranked[index];
                entry.equivalent_scope_count += 1;
                if entry.equivalent_scopes.len() < 20 {
                    entry
                        .equivalent_scopes
                        .push((scope.id.clone(), scope.label.clone()));
                }
                continue;
            }
            let index = ranked.len();
            ranked.push(RankedScope {
                scope: scope.clone(),
                value,
                statistics,
                equivalent_scope_count: 1,
                equivalent_scopes: vec![(scope.id.clone(), scope.label.clone())],
            });
            if scope.kind == ScopeKind::Action {
                evidence_groups.insert(key, index);
            }
        }
        ranked.sort_by(|left, right| {
            let ordering = left.value.total_cmp(&right.value);
            if descending {
                ordering.reverse()
            } else {
                ordering
            }
        });
        let evidence_group_count = ranked.len();
        ranked.truncate(top.clamp(1, 100));
        Ok(ScopeRanking {
            metric: metric.into(),
            statistic,
            descending,
            candidate_count,
            rankable_count: rankable.len(),
            metric_value_count,
            evidence_group_count,
            unavailable_count: candidate_count.saturating_sub(metric_value_count),
            ranked_scopes: ranked,
        })
    }

    fn attach_samples(&mut self, scope: &Scope) -> Result<Scope> {
        let samples = self.ensure_counters()?.sample_info.clone();
        let valid: Vec<_> = samples
            .iter()
            .filter(|sample| sample.timestamp_valid)
            .collect();
        if valid.is_empty() {
            return Err(Error::PerfWorks(
                "capture has no timestamped metric samples".into(),
            ));
        }
        let mut scope = scope.clone();
        if scope.kind == ScopeKind::SampleRange {
            let start = scope.sample_start.ok_or_else(|| {
                Error::TracePath(format!("sample scope {} has no start index", scope.id))
            })?;
            let stop = scope.sample_stop.ok_or_else(|| {
                Error::TracePath(format!("sample scope {} has no stop index", scope.id))
            })?;
            if start > stop || stop > samples.len() {
                return Err(Error::TracePath(format!(
                    "invalid sample range [{start}, {stop}); capture has {} samples",
                    samples.len()
                )));
            }
            return Ok(scope);
        }
        if scope.kind == ScopeKind::Capture {
            scope.start_ns = Some(valid[0].timestamp_start_ns);
            scope.end_ns = Some(valid.last().unwrap().timestamp_end_ns);
            scope.sample_start = Some(valid[0].range_index);
            scope.sample_stop = Some(valid.last().unwrap().range_index + 1);
            return Ok(scope);
        }
        if scope.precision == "nvtx_clock_unvalidated" {
            scope.sample_start = Some(valid[0].range_index);
            scope.sample_stop = Some(valid[0].range_index);
            return Ok(scope);
        }
        let (start, end) = scope.start_ns.zip(scope.end_ns).ok_or_else(|| {
            Error::TracePath(format!("scope {} has no usable GPU timestamps", scope.id))
        })?;
        let overlaps: Vec<_> = valid
            .iter()
            .filter(|sample| sample.timestamp_start_ns < end && sample.timestamp_end_ns > start)
            .collect();
        if overlaps.is_empty() {
            let boundary = if end <= valid[0].timestamp_start_ns {
                valid[0].range_index
            } else {
                valid.last().unwrap().range_index + 1
            };
            scope.sample_start = Some(boundary);
            scope.sample_stop = Some(boundary);
            scope
                .warnings
                .push("Scope does not overlap the recorded periodic metric window.".into());
        } else {
            scope.sample_start = Some(overlaps[0].range_index);
            scope.sample_stop = Some(overlaps.last().unwrap().range_index + 1);
        }
        Ok(scope)
    }

    fn ensure_counters(&mut self) -> Result<&mut CounterState> {
        if self.counters.is_none() {
            let perfworks = PerfWorks::load(self.nvperf_library.as_deref())?;
            let image = CounterImage::from_container(self.document.container())?;
            let info = perfworks.inspect(&image)?;
            let mut sample_info = Vec::with_capacity(info.periodic_sampler.populated_ranges);
            for index in 0..info.periodic_sampler.populated_ranges {
                sample_info.push(perfworks.sample_info(&image, index)?);
            }
            self.counters = Some(CounterState {
                perfworks,
                image,
                info,
                sample_info,
            });
        }
        Ok(self.counters.as_mut().unwrap())
    }

    fn metrics_api(&self) -> Result<MetricsApi> {
        let apis: BTreeSet<_> = self
            .api_names
            .iter()
            .filter_map(|name| MetricsApi::from_trace_name(name))
            .collect();
        if apis.len() != 1 {
            return Err(Error::PerfWorks(format!(
                "capture must contain one supported metrics API; found {}",
                self.api_names.join(", ")
            )));
        }
        Ok(*apis.first().unwrap())
    }
}

fn metric_scope_bounds(scope: &Scope) -> Option<(usize, usize)> {
    scope
        .sample_start
        .zip(scope.sample_stop)
        .filter(|(start, stop)| start < stop)
        .filter(|_| scope.start_ns.zip(scope.end_ns).is_some())
}

fn aggregate_metric_rows(
    scopes: &[Scope],
    metrics: &[String],
    rows: &[MetricSample],
    envelope_start: Option<usize>,
) -> Vec<ScopeMetricSummary> {
    scopes
        .iter()
        .map(|scope| {
            let selected = metric_scope_bounds(scope)
                .zip(envelope_start)
                .and_then(|((start, stop), envelope_start)| {
                    let first = start.saturating_sub(envelope_start).min(rows.len());
                    let stop = stop.saturating_sub(envelope_start).min(rows.len());
                    (first < stop).then_some(&rows[first..stop])
                })
                .unwrap_or_default();
            let (start_ns, end_ns) = scope.start_ns.zip(scope.end_ns).unwrap_or((0, 0));
            ScopeMetricSummary {
                scope: scope.clone(),
                summary: metrics
                    .iter()
                    .map(|metric| {
                        (
                            metric.clone(),
                            metric_statistics(selected, metric, start_ns, end_ns),
                        )
                    })
                    .collect(),
            }
        })
        .collect()
}

pub fn metric_statistics(
    rows: &[MetricSample],
    metric: &str,
    start_ns: u64,
    end_ns: u64,
) -> MetricStatistics {
    let mut values = Vec::new();
    for row in rows {
        let Some(Some(value)) = row.values.get(metric) else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        let overlap = end_ns
            .min(row.timestamp_end_ns)
            .saturating_sub(start_ns.max(row.timestamp_start_ns));
        if overlap > 0 {
            values.push((*value, overlap, row.range_index));
        }
    }
    if values.is_empty() {
        return MetricStatistics {
            valid_samples: 0,
            selected_samples: rows.len(),
            coverage_pct: 0.0,
            mean: None,
            min: None,
            min_range_index: None,
            max: None,
            max_range_index: None,
            p50: None,
            p95: None,
            sum: None,
        };
    }
    let selected_duration = end_ns.saturating_sub(start_ns);
    let covered_duration: u64 = values.iter().map(|item| item.1).sum();
    let weighted_sum: f64 = values
        .iter()
        .map(|(value, duration, _)| value * *duration as f64)
        .sum();
    let min = values
        .iter()
        .min_by(|left, right| left.0.total_cmp(&right.0))
        .unwrap();
    let max = values
        .iter()
        .max_by(|left, right| left.0.total_cmp(&right.0))
        .unwrap();
    let mut sorted: Vec<_> = values.iter().map(|item| item.0).collect();
    sorted.sort_by(f64::total_cmp);
    MetricStatistics {
        valid_samples: values.len(),
        selected_samples: rows.len(),
        coverage_pct: if selected_duration == 0 {
            0.0
        } else {
            100.0 * covered_duration as f64 / selected_duration as f64
        },
        mean: Some(weighted_sum / covered_duration as f64),
        min: Some(min.0),
        min_range_index: Some(min.2),
        max: Some(max.0),
        max_range_index: Some(max.2),
        p50: Some(percentile(&sorted, 0.50)),
        p95: Some(percentile(&sorted, 0.95)),
        sum: Some(sorted.iter().sum()),
    }
}

fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0];
    }
    let position = (sorted.len() - 1) as f64 * fraction;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower as f64)
    }
}

fn parse_range<T>(value: &str) -> Result<(T, T)>
where
    T: std::str::FromStr,
{
    let (start, stop) = value
        .split_once("..")
        .ok_or_else(|| Error::TracePath(format!("range {value:?} must use A..B syntax")))?;
    if start.is_empty() || stop.is_empty() || stop.contains("..") {
        return Err(Error::TracePath(format!(
            "range {value:?} must contain exactly two bounds"
        )));
    }
    let start = start
        .parse()
        .map_err(|_| Error::TracePath(format!("invalid range start {start:?}")))?;
    let stop = stop
        .parse()
        .map_err(|_| Error::TracePath(format!("invalid range stop {stop:?}")))?;
    Ok((start, stop))
}

fn page(offset: usize, stop: usize, total: usize) -> serde_json::Value {
    serde_json::json!({
        "offset": offset,
        "returned": stop - offset,
        "total": total,
        "next_offset": (stop < total).then_some(stop),
    })
}

type StreamIndex = (
    Vec<String>,
    Vec<ApiCall>,
    Vec<TimestampBoundary>,
    Vec<TimingBucket>,
);

fn index_streams(trace: &DynamicMessage) -> Result<StreamIndex> {
    let mut api_names = Vec::new();
    let mut calls = Vec::new();
    let mut timestamps = Vec::new();
    let mut timing_buckets = Vec::new();
    let mut global_base = 0usize;
    for (device_index, device) in message_items(trace, "devices")?.enumerate() {
        api_names.push(enum_name(device, "API")?.unwrap_or_else(|| "unknown".into()));
        for (queue_index, queue) in message_items(device, "CommandQueues")?.enumerate() {
            for (stream_index, stream) in message_items(queue, "CommandStreams")?.enumerate() {
                let stream_calls: Vec<_> = message_items(stream, "Calls")?.collect();
                let metadata: Vec<_> = message_items(stream, "CallMetadata")?.collect();
                for (call_index, call) in stream_calls.iter().enumerate() {
                    let name = required_string(call, "functionName")?;
                    let arguments = message_items(call, "arguments")?
                        .map(message_json)
                        .collect::<Result<_>>()?;
                    let return_value = optional_message(call, "returnArgument")?
                        .map(message_json)
                        .transpose()?;
                    calls.push(ApiCall {
                        global_index: global_base + call_index,
                        device_index,
                        queue_index,
                        stream_index,
                        call_index,
                        kind: CallKind::classify(&name),
                        name,
                        interface: optional_string(call, "interfaceName"),
                        arguments,
                        return_value,
                        metadata: metadata
                            .get(call_index)
                            .map(|item| message_json(item))
                            .transpose()?,
                    });
                }
                let boundaries = index_timestamps(stream, device_index, queue_index, stream_index)?;
                let buckets = build_timing_buckets(
                    timing_buckets.len(),
                    &boundaries,
                    &stream_calls,
                    global_base,
                )?;
                timestamps.extend(boundaries);
                timing_buckets.extend(buckets);
                global_base += stream_calls.len();
            }
        }
    }
    api_names.sort();
    api_names.dedup();
    Ok((api_names, calls, timestamps, timing_buckets))
}

fn index_timestamps(
    stream: &DynamicMessage,
    device_index: usize,
    queue_index: usize,
    stream_index: usize,
) -> Result<Vec<TimestampBoundary>> {
    message_items(stream, "Timestamps")?
        .enumerate()
        .map(|(timestamp_index, timestamp)| {
            let values = message_items(timestamp, "Values")?
                .map(|value| {
                    Ok(TimestampValue {
                        stage: enum_name(value, "Stage")?.unwrap_or_else(|| "unknown".into()),
                        ptimer: required_u64(value, "PtimerValue")?,
                        raw: message_json(value)?,
                    })
                })
                .collect::<Result<_>>()?;
            Ok(TimestampBoundary {
                device_index,
                queue_index,
                stream_index,
                timestamp_index,
                next_call_index: required_u64(timestamp, "NextCallIndex")? as usize,
                values,
            })
        })
        .collect()
}

fn build_timing_buckets(
    base_index: usize,
    boundaries: &[TimestampBoundary],
    calls: &[&DynamicMessage],
    global_base: usize,
) -> Result<Vec<TimingBucket>> {
    let mut result = Vec::new();
    for pair in boundaries.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let first = previous.next_call_index;
        let stop = current.next_call_index;
        if first > stop || stop > calls.len() {
            return Err(Error::InvalidCapture(format!(
                "invalid timestamp call range [{first}, {stop}) in stream {}",
                previous.stream_index
            )));
        }
        let names: Vec<_> = calls[first..stop]
            .iter()
            .map(|call| required_string(call, "functionName"))
            .collect::<Result<_>>()?;
        let previous_values: BTreeMap<_, _> = previous
            .values
            .iter()
            .map(|value| (value.stage.clone(), value.ptimer))
            .collect();
        let current_values: BTreeMap<_, _> = current
            .values
            .iter()
            .map(|value| (value.stage.clone(), value.ptimer))
            .collect();
        let stages: Vec<_> = previous_values
            .iter()
            .filter_map(|(stage, start)| {
                current_values.get(stage).and_then(|end| {
                    end.checked_sub(*start).map(|duration_ns| TimingStage {
                        stage: stage.clone(),
                        start_ptimer: *start,
                        end_ptimer: *end,
                        duration_ns,
                    })
                })
            })
            .collect();
        result.push(TimingBucket {
            index: base_index + result.len(),
            device_index: previous.device_index,
            queue_index: previous.queue_index,
            stream_index: previous.stream_index,
            start_timestamp_index: previous.timestamp_index,
            end_timestamp_index: current.timestamp_index,
            first_call_index: first,
            next_call_index: stop,
            first_global_call_index: global_base + first,
            next_global_call_index: global_base + stop,
            call_count: stop - first,
            call_histogram: histogram(names.iter().cloned()),
            call_kinds: histogram(names.iter().map(|name| CallKind::classify(name))),
            max_duration_ns: stages.iter().map(|stage| stage.duration_ns).max(),
            stages,
        });
    }
    Ok(result)
}

fn index_frames(trace: &DynamicMessage) -> Result<Vec<Frame>> {
    let mut result = Vec::new();
    for (device_index, device) in message_items(trace, "devices")?.enumerate() {
        for (swapchain_index, swapchain) in message_items(device, "swapchains")?.enumerate() {
            for (kind, field) in [
                ("presented", "PresentedFrames"),
                ("application", "ApplicationFrames"),
            ] {
                for (index, frame) in message_items(swapchain, field)?.enumerate() {
                    let start_ns = required_u64(frame, "Start")?;
                    let end_ns = required_u64(frame, "End")?;
                    result.push(Frame {
                        id: format!("frame:{kind}:{device_index}:{swapchain_index}:{index}"),
                        device_index,
                        swapchain_index,
                        kind: kind.into(),
                        index,
                        start_ns,
                        end_ns,
                        duration_ns: end_ns.saturating_sub(start_ns),
                        application_frame_index: optional_u64(frame, "applicationFrameIndex"),
                    });
                }
            }
        }
    }
    Ok(result)
}

fn index_debug_groups(calls: &[ApiCall]) -> Vec<DebugGroup> {
    let mut streams: BTreeMap<(usize, usize, usize), Vec<&ApiCall>> = BTreeMap::new();
    for call in calls {
        streams
            .entry((call.device_index, call.queue_index, call.stream_index))
            .or_default()
            .push(call);
    }
    let mut groups: Vec<DebugGroup> = Vec::new();
    for (key, stream_calls) in streams {
        let mut stack: Vec<usize> = Vec::new();
        let mut sequence = 0usize;
        for call in &stream_calls {
            match marker_direction(&call.name) {
                Some(true) => {
                    let index = groups.len();
                    groups.push(DebugGroup {
                        id: format!("debug:{}:{}:{}:{sequence}", key.0, key.1, key.2),
                        name: marker_label(call).unwrap_or_else(|| call.name.clone()),
                        device_index: key.0,
                        queue_index: key.1,
                        stream_index: key.2,
                        depth: stack.len(),
                        parent_id: stack.last().map(|index| groups[*index].id.clone()),
                        open_call_index: call.global_index,
                        close_call_index: None,
                        call_start: call.global_index + 1,
                        call_stop: call.global_index + 1,
                        closed: false,
                    });
                    sequence += 1;
                    stack.push(index);
                }
                Some(false) => {
                    if let Some(index) = stack.pop() {
                        groups[index].close_call_index = Some(call.global_index);
                        groups[index].call_stop = call.global_index;
                        groups[index].closed = true;
                    }
                }
                None => {}
            }
        }
        let stream_stop = stream_calls
            .last()
            .map(|call| call.global_index + 1)
            .unwrap_or(0);
        for index in stack {
            groups[index].call_stop = stream_stop;
        }
    }
    groups
}

fn index_nvtx(trace: &DynamicMessage) -> Result<Vec<NvtxRange>> {
    let Some(data) = optional_message(trace, "NvtxData")? else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for (range_kind, field) in [
        ("push_pop", "LegacyNvtxPushPopRanges"),
        ("start_end", "LegacyNvtxStartEndRanges"),
    ] {
        for (index, range) in message_items(data, field)?.enumerate() {
            result.push(NvtxRange {
                id: format!("nvtx:{range_kind}:{index}"),
                range_kind: range_kind.into(),
                index,
                name: optional_string(range, "Name").unwrap_or_default(),
                domain: optional_string(range, "DomainName").unwrap_or_default(),
                start: optional_u64(range, "Start").unwrap_or(0),
                end: optional_u64(range, "End").unwrap_or(0),
                thread_id: optional_u64(range, "ThreadId"),
                start_thread_id: optional_u64(range, "StartThreadId"),
                end_thread_id: optional_u64(range, "EndThreadId"),
            });
        }
    }
    Ok(result)
}

fn info_tables(trace: &DynamicMessage) -> Result<Vec<serde_json::Value>> {
    message_items(trace, "InfoTables")?
        .map(|table| {
            let entries = message_items(table, "TableEntries")?
                .map(|entry| {
                    serde_json::json!({
                        "name": optional_string(entry, "Name"),
                        "value": optional_string(entry, "Value"),
                    })
                })
                .collect::<Vec<_>>();
            Ok(serde_json::json!({
                "name": optional_string(table, "TableName"),
                "entries": entries,
            }))
        })
        .collect()
}

fn marker_direction(name: &str) -> Option<bool> {
    let name = name.to_ascii_lowercase();
    if [
        "pushdebuggroup",
        "begindebug",
        "beginevent",
        "beginlabel",
        "debugmarkerbegin",
    ]
    .iter()
    .any(|token| name.contains(token))
    {
        Some(true)
    } else if [
        "popdebuggroup",
        "enddebug",
        "endevent",
        "endlabel",
        "debugmarkerend",
    ]
    .iter()
    .any(|token| name.contains(token))
    {
        Some(false)
    } else {
        None
    }
}

fn marker_label(call: &ApiCall) -> Option<String> {
    let mut fallback = None;
    for argument in &call.arguments {
        let mut strings = Vec::new();
        collect_argument_strings(argument, &mut strings);
        for (name, value) in strings {
            fallback.get_or_insert_with(|| value.clone());
            if ["message", "label", "name", "pmarkername", "plabelname"]
                .contains(&name.to_ascii_lowercase().as_str())
            {
                return Some(value);
            }
        }
    }
    fallback
}

fn collect_argument_strings(value: &serde_json::Value, output: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(items) => {
            if let Some((name, value)) = items.get("name").and_then(serde_json::Value::as_str).zip(
                items
                    .get("stringValue")
                    .and_then(|value| value.get("value"))
                    .and_then(serde_json::Value::as_str),
            ) {
                output.push((name.to_owned(), value.to_owned()));
            }
            for value in items.values() {
                collect_argument_strings(value, output);
            }
        }
        serde_json::Value::Array(items) => {
            for value in items {
                collect_argument_strings(value, output);
            }
        }
        _ => {}
    }
}

fn histogram<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeMap<T, usize> {
    let mut result = BTreeMap::new();
    for value in values {
        *result.entry(value).or_default() += 1;
    }
    result
}

fn message_items<'a>(
    message: &'a DynamicMessage,
    name: &str,
) -> Result<impl Iterator<Item = &'a DynamicMessage>> {
    let descriptor = message.descriptor();
    let field = descriptor.get_field_by_name(name).ok_or_else(|| {
        Error::Protobuf(format!("{} has no field {name}", descriptor.full_name()))
    })?;
    if !field.is_list() {
        return Err(Error::Protobuf(format!(
            "{}.{} is not a repeated field",
            descriptor.full_name(),
            name
        )));
    }
    let values = message
        .fields()
        .find(|(item, _)| item.number() == field.number())
        .map(|(_, value)| value);
    let values = match values {
        Some(Value::List(values)) => values.as_slice(),
        Some(_) => {
            return Err(Error::Protobuf(format!(
                "{}.{} has an unexpected runtime type",
                descriptor.full_name(),
                name
            )));
        }
        None => &[],
    };
    Ok(values.iter().filter_map(|value| match value {
        Value::Message(message) => Some(message),
        _ => None,
    }))
}

fn optional_message<'a>(
    message: &'a DynamicMessage,
    name: &str,
) -> Result<Option<&'a DynamicMessage>> {
    let descriptor = message.descriptor();
    let field = descriptor.get_field_by_name(name).ok_or_else(|| {
        Error::Protobuf(format!("{} has no field {name}", descriptor.full_name()))
    })?;
    Ok(message
        .fields()
        .find(|(item, _)| item.number() == field.number())
        .and_then(|(_, value)| match value {
            Value::Message(message) => Some(message),
            _ => None,
        }))
}

fn field_value<'a>(message: &'a DynamicMessage, name: &str) -> Option<&'a Value> {
    message
        .fields()
        .find(|(field, _)| field.name() == name)
        .map(|(_, value)| value)
}

fn required_string(message: &DynamicMessage, name: &str) -> Result<String> {
    optional_string(message, name).ok_or_else(|| {
        Error::Protobuf(format!(
            "{}.{} is missing",
            message.descriptor().full_name(),
            name
        ))
    })
}

fn optional_string(message: &DynamicMessage, name: &str) -> Option<String> {
    match field_value(message, name) {
        Some(Value::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn required_u64(message: &DynamicMessage, name: &str) -> Result<u64> {
    optional_u64(message, name).ok_or_else(|| {
        Error::Protobuf(format!(
            "{}.{} is missing",
            message.descriptor().full_name(),
            name
        ))
    })
}

fn optional_u64(message: &DynamicMessage, name: &str) -> Option<u64> {
    match field_value(message, name) {
        Some(Value::U64(value)) => Some(*value),
        Some(Value::U32(value)) => Some(u64::from(*value)),
        Some(Value::I64(value)) => u64::try_from(*value).ok(),
        Some(Value::I32(value)) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn enum_name(message: &DynamicMessage, name: &str) -> Result<Option<String>> {
    let descriptor = message.descriptor();
    let field = descriptor.get_field_by_name(name).ok_or_else(|| {
        Error::Protobuf(format!("{} has no field {name}", descriptor.full_name()))
    })?;
    let Some(Value::EnumNumber(number)) = field_value(message, name) else {
        return Ok(None);
    };
    let Kind::Enum(enumeration) = field.kind() else {
        return Err(Error::Protobuf(format!(
            "{}.{} is not an enum",
            descriptor.full_name(),
            name
        )));
    };
    Ok(Some(
        enumeration
            .get_value(*number)
            .map(|value| value.name().to_owned())
            .unwrap_or_else(|| number.to_string()),
    ))
}

fn message_json(message: &DynamicMessage) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(message)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_call(arguments: Vec<serde_json::Value>) -> ApiCall {
        ApiCall {
            global_index: 0,
            device_index: 0,
            queue_index: 0,
            stream_index: 0,
            call_index: 0,
            name: "marker".into(),
            kind: CallKind::Marker,
            interface: None,
            arguments,
            return_value: None,
            metadata: None,
        }
    }

    fn metric_scope(
        id: &str,
        start_ns: u64,
        end_ns: u64,
        sample_start: usize,
        sample_stop: usize,
        precision: &str,
    ) -> Scope {
        Scope {
            kind: ScopeKind::DebugGroup,
            id: id.into(),
            label: id.into(),
            start_ns: Some(start_ns),
            end_ns: Some(end_ns),
            call_start: None,
            call_stop: None,
            sample_start: Some(sample_start),
            sample_stop: Some(sample_stop),
            precision: precision.into(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn weighted_metric_statistics_use_overlap_duration() {
        let rows = vec![
            MetricSample {
                range_index: 0,
                timestamp_start_ns: 0,
                timestamp_end_ns: 10,
                time_ns: Some(0),
                duration_ns: Some(10),
                complete: true,
                values: BTreeMap::from([("m".into(), Some(10.0))]),
            },
            MetricSample {
                range_index: 1,
                timestamp_start_ns: 10,
                timestamp_end_ns: 20,
                time_ns: Some(10),
                duration_ns: Some(10),
                complete: true,
                values: BTreeMap::from([("m".into(), Some(30.0))]),
            },
        ];
        let statistics = metric_statistics(&rows, "m", 5, 15);
        assert_eq!(statistics.mean, Some(20.0));
        assert_eq!(statistics.coverage_pct, 100.0);
        assert_eq!(statistics.p50, Some(20.0));
    }

    #[test]
    fn marker_labels_use_string_values_instead_of_argument_metadata() {
        let gl = marker_call(vec![
            serde_json::json!({ "name": "source", "type": "UInt32" }),
            serde_json::json!({
                "name": "message",
                "type": "String",
                "stringValue": { "value": "composite19" },
            }),
        ]);
        let vk = marker_call(vec![serde_json::json!({
            "name": "pLabelInfo",
            "type": "Structure",
            "structureValue": {
                "arguments": [{
                    "name": "pLabelName",
                    "type": "String",
                    "stringValue": { "value": "BetterSDF composite" },
                }],
            },
        })]);

        assert_eq!(marker_label(&gl).as_deref(), Some("composite19"));
        assert_eq!(marker_label(&vk).as_deref(), Some("BetterSDF composite"));
    }

    #[test]
    fn multi_metric_aggregation_preserves_overlapping_scope_evidence_and_nulls() {
        let rows = vec![
            MetricSample {
                range_index: 0,
                timestamp_start_ns: 0,
                timestamp_end_ns: 10,
                time_ns: Some(0),
                duration_ns: Some(10),
                complete: true,
                values: BTreeMap::from([("m".into(), Some(10.0)), ("null".into(), None)]),
            },
            MetricSample {
                range_index: 1,
                timestamp_start_ns: 10,
                timestamp_end_ns: 20,
                time_ns: Some(10),
                duration_ns: Some(10),
                complete: true,
                values: BTreeMap::from([("m".into(), Some(30.0)), ("null".into(), None)]),
            },
        ];
        let scopes = vec![
            metric_scope("outer", 0, 20, 0, 2, "timestamp_bounded"),
            metric_scope("nested", 0, 10, 0, 1, "timestamp_bounded"),
            metric_scope("shared", 5, 15, 0, 2, "bucket_shared"),
            metric_scope("streams", 0, 20, 0, 2, "multi_stream_envelope"),
        ];
        let summaries =
            aggregate_metric_rows(&scopes, &["m".into(), "null".into()], &rows, Some(0));

        assert_eq!(summaries.len(), 4);
        assert_eq!(summaries[0].summary["m"].mean, Some(20.0));
        assert_eq!(summaries[1].summary["m"].mean, Some(10.0));
        assert_eq!(summaries[2].summary["m"].mean, Some(20.0));
        assert_eq!(summaries[2].scope.precision, "bucket_shared");
        assert_eq!(summaries[3].scope.precision, "multi_stream_envelope");
        assert_eq!(summaries[0].summary["null"].mean, None);
        assert_eq!(summaries[0].summary["null"].coverage_pct, 0.0);
    }
}
