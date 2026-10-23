use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use nsight_gpu_trace::{
    Analysis, AnalysisOptions, ByteField, CallKind, CompareOptions, Container, Error, McpServer,
    MetricKind, QueryOptions, Result, ScopeKind, SectionRole, ShaderCatalog, TimelineOptions,
    TraceDocument, compare_captures, disassemble, load_keystream, recover_keystream,
    top_down_report,
};
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "ngfx-trace",
    version,
    about = "Inspect and analyze NVIDIA Nsight Graphics GPU Trace captures",
    long_about = "A JSON-first, read-only toolkit for WRPV containers, dynamic protobuf trace data, API/timing scopes, artifacts, and arbitrary PerfWorks metrics."
)]
struct Cli {
    /// Explicit Nsight WarpViz plugin binary used to recover the trace schema.
    #[arg(long, global = true)]
    schema_binary: Option<PathBuf>,

    /// Explicit NVIDIA PerfWorks host library used to evaluate metrics.
    #[arg(long, global = true)]
    nvperf_library: Option<PathBuf>,

    /// Emit compact JSON instead of indented JSON.
    #[arg(long, global = true)]
    compact: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve stateless, bounded analysis tools over MCP stdio.
    Mcp,

    /// Validate the WRPV container and list every section/chunk.
    Info { trace: PathBuf },

    /// Summarize devices, APIs, calls, frames, markers, and timing buckets.
    Summary {
        trace: PathBuf,
        /// Also materialize and inspect the PerfWorks counter image.
        #[arg(long)]
        with_counters: bool,
    },

    /// Report measurement coverage, environment identity, and capture settings.
    Quality { trace: PathBuf },

    /// Report queue lanes, gaps, overlap, and frame pacing.
    Timeline {
        trace: PathBuf,
        /// Omit gaps shorter than this many nanoseconds.
        #[arg(long, default_value_t = 1000)]
        min_gap_ns: u64,
    },

    /// Compare two captures without deciding whether a change is good.
    Compare {
        baseline: PathBuf,
        candidate: PathBuf,
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Scope family used for per-region deltas.
        #[arg(long, value_enum)]
        scope_kind: Option<CliScopeKind>,
        /// Case-insensitive regex matched against scope IDs and labels.
        #[arg(long)]
        filter: Option<String>,
        /// Exact metrics used for per-scope deltas. Repeatable.
        #[arg(long = "metric")]
        metrics: Vec<String>,
        /// Skip Shader Profiler/cubin comparison.
        #[arg(long)]
        no_shaders: bool,
    },

    /// Show observed bindings and barrier counts for draw/dispatch actions.
    Actions {
        trace: PathBuf,
        #[arg(long, value_enum)]
        kind: Option<CliCallKind>,
        /// Case-insensitive regex matched against action names.
        #[arg(long)]
        filter: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Describe all protobuf fields at a dynamic trace path.
    Schema {
        trace: PathBuf,
        #[arg(default_value = "")]
        path: String,
    },

    /// Query a bounded dynamic protobuf subtree.
    Query {
        trace: PathBuf,
        #[arg(default_value = "")]
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = 6)]
        depth: usize,
    },

    /// Emit the complete standard ProtoJSON trace, including base64 byte fields.
    #[command(name = "json")]
    Json { trace: PathBuf },

    /// List decoded API calls and arguments.
    Calls {
        trace: PathBuf,
        #[arg(long, value_enum)]
        kind: Option<CliCallKind>,
        /// Case-insensitive regular expression matched against function names.
        #[arg(long)]
        filter: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Rank timestamp-bounded call buckets by duration.
    Timings {
        trace: PathBuf,
        #[arg(long, value_enum)]
        kind: Option<CliCallKind>,
        /// Case-insensitive regular expression matched against calls in a bucket.
        #[arg(long)]
        filter: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// List stable metric-attribution scopes.
    Scopes {
        trace: PathBuf,
        #[arg(value_enum)]
        kind: CliScopeKind,
        /// Case-insensitive regular expression matched against scope ID or label.
        #[arg(long)]
        filter: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Inspect periodic counter-image metadata and sample ranges.
    Counters {
        trace: PathBuf,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Enumerate, describe, evaluate, or scan arbitrary PerfWorks metrics.
    Metrics {
        #[command(subcommand)]
        command: MetricsCommand,
    },

    /// Build a compact, heuristic-labeled top-down report from every metric base.
    Report {
        trace: PathBuf,
        #[arg(long, default_value_t = 15)]
        top: usize,
    },

    /// List Shader Profiler shaders, blobs, and attached cubins.
    Shaders {
        trace: PathBuf,
        /// Case-insensitive regular expression matched against shader names and stages.
        #[arg(long)]
        filter: Option<String>,
        /// Restrict output to one trace device index.
        #[arg(long)]
        device: Option<usize>,
        /// Include the complete blob table metadata for each device.
        #[arg(long)]
        blobs: bool,
        /// Explicit XOR stream file.
        #[arg(long)]
        keystream: Option<PathBuf>,
        /// Recover the XOR stream from a known plaintext shader/SPIR-V file.
        #[arg(long)]
        known_plaintext: Option<PathBuf>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Extract one shader's cubin and disassemble it with nvdisasm.
    Sass {
        trace: PathBuf,
        /// Shader index from `shaders`, or a case-insensitive name/entry-point regex.
        selector: Option<String>,
        /// Restrict selection to one trace device index.
        #[arg(long)]
        device: Option<usize>,
        /// Write SASS text to this file instead of embedding it in JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Write the decoded ELF/cubin to this file.
        #[arg(long = "cubin")]
        cubin_output: Option<PathBuf>,
        /// Extract the cubin without invoking nvdisasm.
        #[arg(long)]
        no_disassemble: bool,
        /// Explicit nvdisasm executable.
        #[arg(long)]
        nvdisasm: Option<PathBuf>,
        /// Explicit XOR stream file.
        #[arg(long)]
        keystream: Option<PathBuf>,
        /// Recover the XOR stream from a known plaintext shader/SPIR-V file.
        #[arg(long)]
        known_plaintext: Option<PathBuf>,
    },

    /// Inventory every populated protobuf byte field.
    Artifacts {
        trace: PathBuf,
        /// Case-insensitive regular expression matched against path or message type.
        #[arg(long)]
        filter: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Extract one protobuf byte field by dynamic path.
    Extract {
        trace: PathBuf,
        path: String,
        output: PathBuf,
    },

    /// Stream-decompress one outer WRPV section.
    Section {
        trace: PathBuf,
        index: usize,
        output: PathBuf,
    },

    /// Export lossless trace data and normalized indices to a new/empty directory.
    Unpack {
        trace: PathBuf,
        directory: PathBuf,
        /// Do not write individual protobuf byte payloads (they remain in trace.json/trace.pb).
        #[arg(long)]
        skip_bytes: bool,
        /// Also materialize the potentially multi-gigabyte LOPDATA section.
        #[arg(long)]
        counter_data: bool,
        /// Additionally materialize an outer section by numeric index. Repeatable.
        #[arg(long = "section")]
        sections: Vec<usize>,
    },
}

#[derive(Debug, Subcommand)]
enum MetricsCommand {
    /// List all evaluator metric bases and supported suffixes.
    List {
        trace: PathBuf,
        #[arg(long, value_enum)]
        kind: Option<CliMetricKind>,
        #[arg(long)]
        filter: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },

    /// Describe one fully qualified metric name and its dependencies.
    Describe { trace: PathBuf, metric: String },

    /// Evaluate arbitrary metric names over one exact scope.
    Query {
        trace: PathBuf,
        #[arg(long = "metric", required = true, num_args = 1..)]
        metrics: Vec<String>,
        /// capture, a stable scope ID, calls:A..B, samples:A..B, time:A..B, or relative-time:A..B.
        #[arg(long, default_value = "capture")]
        scope: String,
        /// Shift a selected NVTX scope by this many nanoseconds before metric attribution.
        #[arg(long)]
        nvtx_offset_ns: Option<i64>,
        /// Caller-reported residual for the NVTX clock shift.
        #[arg(long)]
        nvtx_residual_ns: Option<u64>,
        /// Include the complete selected sample series as well as aggregates.
        #[arg(long)]
        sample_series: bool,
    },

    /// Evaluate canonical forms to discover which metric bases were collected.
    Scan {
        trace: PathBuf,
        #[arg(long, value_enum)]
        kind: Option<CliMetricKind>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long)]
        stop: Option<usize>,
        /// Include metric bases whose values are unavailable in every selected sample.
        #[arg(long)]
        include_unavailable: bool,
        #[command(flatten)]
        page: PageArgs,
    },
}

#[derive(Debug, Clone, Args)]
struct PageArgs {
    #[arg(long, default_value_t = 0)]
    offset: usize,
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCallKind {
    Draw,
    Dispatch,
    Copy,
    Clear,
    Sync,
    Marker,
    Present,
    Other,
}

impl From<CliCallKind> for CallKind {
    fn from(value: CliCallKind) -> Self {
        match value {
            CliCallKind::Draw => Self::Draw,
            CliCallKind::Dispatch => Self::Dispatch,
            CliCallKind::Copy => Self::Copy,
            CliCallKind::Clear => Self::Clear,
            CliCallKind::Sync => Self::Sync,
            CliCallKind::Marker => Self::Marker,
            CliCallKind::Present => Self::Present,
            CliCallKind::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliScopeKind {
    Capture,
    Action,
    DebugGroup,
    NvtxRange,
    Frame,
    TimingBucket,
}

impl From<CliScopeKind> for ScopeKind {
    fn from(value: CliScopeKind) -> Self {
        match value {
            CliScopeKind::Capture => Self::Capture,
            CliScopeKind::Action => Self::Action,
            CliScopeKind::DebugGroup => Self::DebugGroup,
            CliScopeKind::NvtxRange => Self::NvtxRange,
            CliScopeKind::Frame => Self::Frame,
            CliScopeKind::TimingBucket => Self::TimingBucket,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMetricKind {
    Counter,
    Ratio,
    Throughput,
}

impl From<CliMetricKind> for MetricKind {
    fn from(value: CliMetricKind) -> Self {
        match value {
            CliMetricKind::Counter => Self::Counter,
            CliMetricKind::Ratio => Self::Ratio,
            CliMetricKind::Throughput => Self::Throughput,
        }
    }
}

#[derive(Debug, Serialize)]
struct ExtractedByte {
    #[serde(flatten)]
    metadata: ByteField,
    file: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let options = AnalysisOptions {
        schema_binary: cli.schema_binary.clone(),
        nvperf_library: cli.nvperf_library.clone(),
    };
    let output = match cli.command {
        Command::Mcp => {
            McpServer::new(options).serve()?;
            return Ok(());
        }
        Command::Info { trace } => container_info(Container::open(trace)?),
        Command::Summary {
            trace,
            with_counters,
        } => {
            let mut analysis = Analysis::open(trace, options)?;
            let mut overview = analysis.overview();
            if let Value::Object(object) = &mut overview {
                let byte_fields = analysis.document().byte_fields();
                object.insert(
                    "byte_fields".into(),
                    json!({
                        "count": byte_fields.len(),
                        "total_bytes": byte_fields.iter().map(|field| field.size).sum::<usize>(),
                    }),
                );
                if with_counters {
                    object.insert(
                        "counters".into(),
                        serde_json::to_value(analysis.counter_info()?)?,
                    );
                }
            }
            overview
        }
        Command::Quality { trace } => {
            let mut analysis = Analysis::open(trace, options)?;
            serde_json::to_value(analysis.quality()?)?
        }
        Command::Timeline { trace, min_gap_ns } => {
            let analysis = Analysis::open(trace, options)?;
            serde_json::to_value(analysis.timeline(TimelineOptions { min_gap_ns }))?
        }
        Command::Compare {
            baseline,
            candidate,
            top,
            scope_kind,
            filter,
            metrics,
            no_shaders,
        } => {
            let mut baseline = Analysis::open(baseline, options.clone())?;
            let mut candidate = Analysis::open(candidate, options)?;
            let options = CompareOptions {
                top,
                scope_kind: scope_kind.map(ScopeKind::from),
                scope_pattern: filter
                    .as_deref()
                    .map(|pattern| RegexBuilder::new(pattern).case_insensitive(true).build())
                    .transpose()?,
                include_shaders: !no_shaders,
                scope_metrics: metrics,
            };
            serde_json::to_value(compare_captures(&mut baseline, &mut candidate, &options)?)?
        }
        Command::Actions {
            trace,
            kind,
            filter,
            page,
        } => {
            let analysis = Analysis::open(trace, options)?;
            let regex = compile_filter(filter.as_deref())?;
            let kind = kind.map(CallKind::from);
            let states: Vec<_> = analysis
                .action_states()
                .into_iter()
                .filter(|state| kind.is_none_or(|kind| state.kind == kind))
                .filter(|state| {
                    regex
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&state.name))
                })
                .collect();
            page_value(&states, &page)?
        }
        Command::Schema { trace, path } => {
            let document = open_document(trace, &options)?;
            json!({ "path": path, "fields": document.schema(&path)? })
        }
        Command::Query {
            trace,
            path,
            offset,
            limit,
            depth,
        } => open_document(trace, &options)?.query(
            &path,
            QueryOptions {
                offset,
                limit,
                max_depth: depth,
            },
        )?,
        Command::Json { trace } => open_document(trace, &options)?.full_json()?,
        Command::Calls {
            trace,
            kind,
            filter,
            page,
        } => {
            let analysis = Analysis::open(trace, options)?;
            let regex = compile_filter(filter.as_deref())?;
            let kind = kind.map(CallKind::from);
            let calls: Vec<_> = analysis
                .calls()
                .iter()
                .filter(|call| kind.is_none_or(|kind| call.kind == kind))
                .filter(|call| {
                    regex
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&call.name))
                })
                .collect();
            page_value(&calls, &page)?
        }
        Command::Timings {
            trace,
            kind,
            filter,
            page,
        } => {
            let analysis = Analysis::open(trace, options)?;
            let regex = compile_filter(filter.as_deref())?;
            let kind = kind.map(CallKind::from);
            let mut buckets: Vec<_> = analysis
                .timing_buckets()
                .iter()
                .filter(|bucket| {
                    kind.is_none_or(|kind| bucket.call_kinds.get(&kind).copied().unwrap_or(0) > 0)
                })
                .filter(|bucket| {
                    regex.as_ref().is_none_or(|regex| {
                        bucket
                            .call_histogram
                            .keys()
                            .any(|name| regex.is_match(name))
                    })
                })
                .collect();
            buckets.sort_by_key(|bucket| std::cmp::Reverse(bucket.max_duration_ns));
            page_value(&buckets, &page)?
        }
        Command::Scopes {
            trace,
            kind,
            filter,
            page,
        } => {
            let analysis = Analysis::open(trace, options)?;
            let regex = compile_filter(filter.as_deref())?;
            let scopes: Vec<_> = analysis
                .scopes(kind.into())?
                .into_iter()
                .filter(|scope| {
                    regex.as_ref().is_none_or(|regex| {
                        regex.is_match(&scope.id) || regex.is_match(&scope.label)
                    })
                })
                .collect();
            page_value(&scopes, &page)?
        }
        Command::Counters { trace, page } => {
            let mut analysis = Analysis::open(trace, options)?;
            let info = analysis.counter_info()?.clone();
            let samples = analysis.counter_samples()?;
            json!({
                "counter_image": info,
                "samples": page_value(samples, &page)?,
            })
        }
        Command::Metrics { command } => metrics_command(command, options)?,
        Command::Report { trace, top } => {
            let mut analysis = Analysis::open(trace, options)?;
            let quality = analysis.quality()?;
            let overview = analysis.overview();
            let timeline = analysis.timeline(TimelineOptions { min_gap_ns: 1000 });
            let counter_info = analysis.counter_info()?.clone();
            let catalog = analysis.metric_catalog()?;
            let scan = analysis.scan_metrics(&catalog.metrics, 0, None)?;
            json!({
                "capture": overview,
                "quality": quality,
                "timeline": timeline,
                "counter_image": counter_info,
                "diagnostics": top_down_report(&scan, top),
            })
        }
        Command::Shaders {
            trace,
            filter,
            device,
            blobs,
            keystream,
            known_plaintext,
            page,
        } => shader_inventory(
            trace,
            &options,
            filter.as_deref(),
            device,
            blobs,
            keystream.as_deref(),
            known_plaintext.as_deref(),
            &page,
        )?,
        Command::Sass {
            trace,
            selector,
            device,
            output,
            cubin_output,
            no_disassemble,
            nvdisasm,
            keystream,
            known_plaintext,
        } => sass(
            trace,
            &options,
            selector.as_deref(),
            device,
            output.as_deref(),
            cubin_output.as_deref(),
            no_disassemble,
            nvdisasm.as_deref(),
            keystream.as_deref(),
            known_plaintext.as_deref(),
        )?,
        Command::Artifacts {
            trace,
            filter,
            page,
        } => {
            let document = open_document(trace, &options)?;
            let regex = compile_filter(filter.as_deref())?;
            let fields: Vec<_> = document
                .byte_fields()
                .into_iter()
                .filter(|field| {
                    regex.as_ref().is_none_or(|regex| {
                        regex.is_match(&field.path) || regex.is_match(&field.message_type)
                    })
                })
                .collect();
            page_value(&fields, &page)?
        }
        Command::Extract {
            trace,
            path,
            output,
        } => {
            let document = open_document(trace, &options)?;
            let data = document.extract_bytes(&path)?;
            write_bytes_file(&output, &data)?;
            json!({ "path": path, "output": output, "size": data.len() })
        }
        Command::Section {
            trace,
            index,
            output,
        } => {
            let container = Container::open(trace)?;
            let section = container.sections.get(index).ok_or_else(|| {
                Error::TracePath(format!(
                    "section index {index} out of range (count {})",
                    container.sections.len()
                ))
            })?;
            write_section_file(&container, section, &output)?;
            json!({
                "section": section,
                "role": section.role(),
                "output": output,
            })
        }
        Command::Unpack {
            trace,
            directory,
            skip_bytes,
            counter_data,
            sections,
        } => unpack(
            trace,
            &directory,
            skip_bytes,
            counter_data,
            &sections,
            options,
        )?,
    };
    write_json_stdout(&output, !cli.compact)
}

fn metrics_command(command: MetricsCommand, options: AnalysisOptions) -> Result<Value> {
    match command {
        MetricsCommand::List {
            trace,
            kind,
            filter,
            page,
        } => {
            let mut analysis = Analysis::open(trace, options)?;
            let catalog = analysis.metric_catalog()?;
            let regex = compile_filter(filter.as_deref())?;
            let kind = kind.map(MetricKind::from);
            let metrics: Vec<_> = catalog
                .metrics
                .iter()
                .filter(|metric| kind.is_none_or(|kind| metric.kind == kind))
                .filter(|metric| {
                    regex
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&metric.name))
                })
                .collect();
            Ok(json!({
                "chip_name": catalog.chip_name,
                "supported_submetrics": catalog.supported_submetrics,
                "metrics": page_value(&metrics, &page)?,
            }))
        }
        MetricsCommand::Describe { trace, metric } => {
            let mut analysis = Analysis::open(trace, options)?;
            Ok(serde_json::to_value(analysis.describe_metric(&metric)?)?)
        }
        MetricsCommand::Query {
            trace,
            metrics,
            scope,
            nvtx_offset_ns,
            nvtx_residual_ns,
            sample_series,
        } => {
            let mut analysis = Analysis::open(trace, options)?;
            let scope = if let Some(offset) = nvtx_offset_ns
                && scope.starts_with("nvtx:")
            {
                analysis.scope_for_nvtx(&scope, offset, nvtx_residual_ns)?
            } else {
                analysis.parse_scope(&scope)?
            };
            let report = analysis.evaluate_scope(&scope, &metrics)?;
            if sample_series {
                Ok(serde_json::to_value(report)?)
            } else {
                Ok(json!({
                    "scope": report.scope,
                    "metrics": report.metrics,
                    "summary": report.summary,
                    "sample_count": report.samples.len(),
                    "null_semantics": "Unavailable/not collected is null, never zero.",
                }))
            }
        }
        MetricsCommand::Scan {
            trace,
            kind,
            filter,
            start,
            stop,
            include_unavailable,
            page,
        } => {
            let mut analysis = Analysis::open(trace, options)?;
            let catalog = analysis.metric_catalog()?;
            let regex = compile_filter(filter.as_deref())?;
            let kind = kind.map(MetricKind::from);
            let selected: Vec<_> = catalog
                .metrics
                .iter()
                .filter(|metric| kind.is_none_or(|kind| metric.kind == kind))
                .filter(|metric| {
                    regex
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&metric.name))
                })
                .cloned()
                .collect();
            let scan = analysis.scan_metrics(&selected, start, stop)?;
            let available = scan
                .metrics
                .iter()
                .filter(|metric| metric.valid_samples > 0)
                .count();
            let metrics: Vec<_> = scan
                .metrics
                .iter()
                .filter(|metric| include_unavailable || metric.valid_samples > 0)
                .collect();
            Ok(json!({
                "chip_name": scan.chip_name,
                "sample_start": scan.sample_start,
                "sample_stop": scan.sample_stop,
                "selected_samples": scan.selected_samples,
                "selected_metric_bases": selected.len(),
                "available_metric_bases": available,
                "unavailable_metric_bases": selected.len() - available,
                "metrics": page_value(&metrics, &page)?,
                "null_semantics": "Unavailable/not collected is omitted by default; use --include-unavailable to show it.",
            }))
        }
    }
}

fn open_document(path: PathBuf, options: &AnalysisOptions) -> Result<TraceDocument> {
    TraceDocument::open(path, options.schema_binary.as_deref())
}

fn shader_catalog(
    document: &TraceDocument,
    keystream: Option<&Path>,
    known_plaintext: Option<&Path>,
) -> Result<ShaderCatalog> {
    let (key, source) = if let Some(known) = known_plaintext {
        recover_keystream(document, known)?
    } else {
        load_keystream(keystream)?
    };
    ShaderCatalog::open(document, &key, &source)
}

#[allow(clippy::too_many_arguments)]
fn shader_inventory(
    trace: PathBuf,
    options: &AnalysisOptions,
    filter: Option<&str>,
    device: Option<usize>,
    include_blobs: bool,
    keystream: Option<&Path>,
    known_plaintext: Option<&Path>,
    page: &PageArgs,
) -> Result<Value> {
    let document = open_document(trace, options)?;
    let catalog = shader_catalog(&document, keystream, known_plaintext)?;
    let regex = compile_filter(filter)?;
    let shaders: Vec<_> = catalog
        .shaders()
        .filter(|shader| device.is_none_or(|value| shader.device_index == value))
        .filter(|shader| {
            regex.as_ref().is_none_or(|regex| {
                [
                    shader.name.as_str(),
                    shader.entry_point.as_deref().unwrap_or(""),
                    shader.source_file.as_deref().unwrap_or(""),
                    shader.stage.as_str(),
                    shader.shader_type.as_str(),
                    shader.origin.as_str(),
                    shader.pipeline.as_deref().unwrap_or(""),
                ]
                .iter()
                .any(|value| regex.is_match(value))
            })
        })
        .cloned()
        .collect();
    let devices = catalog
        .devices
        .iter()
        .filter(|entry| device.is_none_or(|value| entry.device_index == value))
        .map(|entry| {
            let mut kinds = BTreeMap::new();
            for blob in &entry.blobs {
                *kinds.entry(format!("{:?}", blob.kind)).or_insert(0usize) += 1;
            }
            json!({
                "device_index": entry.device_index,
                "blob_count": entry.blobs.len(),
                "blob_kinds": kinds,
                "module_count": entry.modules.len(),
                "shader_count": entry.shaders.len(),
                "pc_sampling": entry.pc_sampling,
                "modules": entry.modules,
                "blobs": include_blobs.then_some(&entry.blobs),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "capture": document.container().path,
        "keystream": {
            "bytes": catalog.keystream_bytes,
            "source": catalog.keystream_source,
        },
        "devices": devices,
        "shaders": page_value(&shaders, page)?,
        "sass_hint": "Run `ngfx-trace sass <capture> <index>` to decode the attached cubin and disassemble it.",
    }))
}

#[allow(clippy::too_many_arguments)]
fn sass(
    trace: PathBuf,
    options: &AnalysisOptions,
    selector: Option<&str>,
    device: Option<usize>,
    output: Option<&Path>,
    cubin_output: Option<&Path>,
    no_disassemble: bool,
    nvdisasm: Option<&Path>,
    keystream: Option<&Path>,
    known_plaintext: Option<&Path>,
) -> Result<Value> {
    let document = open_document(trace, options)?;
    let catalog = shader_catalog(&document, keystream, known_plaintext)?;
    let candidates: Vec<_> = catalog
        .shaders()
        .filter(|shader| device.is_none_or(|value| shader.device_index == value))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Err(Error::Shader(
            "capture has no Shader Profiler shader records for the selected device".into(),
        ));
    }
    let selected = select_shader(&candidates, selector)?;
    let cubin = catalog.cubin(selected.device_index, selected.index)?;
    if !cubin.starts_with(b"\x7fELF") {
        return Err(Error::Shader(format!(
            "shader {} ({}) does not reference an ELF/cubin blob",
            selected.index, selected.name
        )));
    }
    let cubin_sha256 = selected.cubin_sha256.clone();
    if let Some(path) = cubin_output {
        write_bytes_file(path, &cubin)?;
    }

    let mut result = json!({
        "capture": document.container().path,
        "keystream": {
            "bytes": catalog.keystream_bytes,
            "source": catalog.keystream_source,
        },
        "shader": selected,
        "cubin": {
            "size": cubin.len(),
            "sha256": cubin_sha256,
            "path": cubin_output,
        },
    });

    if !no_disassemble {
        let disassembly = disassemble(&cubin, nvdisasm)?;
        if let Some(path) = output {
            write_bytes_file(path, disassembly.text.as_bytes())?;
            result["sass"] = json!({
                "tool": disassembly.tool,
                "args": disassembly.args,
                "path": path,
                "bytes": disassembly.text.len(),
                "registers": disassembly.registers,
                "registers_hint": disassembly.registers_hint,
                "stats": disassembly.stats,
                "stats_source": disassembly.stats_source,
                "warnings": disassembly.warnings,
            });
        } else {
            result["sass"] = json!({
                "tool": disassembly.tool,
                "args": disassembly.args,
                "text": disassembly.text,
                "registers": disassembly.registers,
                "registers_hint": disassembly.registers_hint,
                "stats": disassembly.stats,
                "stats_source": disassembly.stats_source,
                "warnings": disassembly.warnings,
            });
        }
    }
    Ok(result)
}

fn select_shader<'a>(
    candidates: &'a [nsight_gpu_trace::ShaderInfo],
    selector: Option<&str>,
) -> Result<&'a nsight_gpu_trace::ShaderInfo> {
    let Some(selector) = selector else {
        if candidates.len() == 1 {
            return Ok(&candidates[0]);
        }
        return Err(Error::Shader(format!(
            "capture has {} shaders; pass a shader index or name pattern (for example: {})",
            candidates.len(),
            candidates
                .iter()
                .take(5)
                .map(|shader| format!("{}={}", shader.index, shader.name))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    if let Ok(index) = selector.parse::<usize>() {
        return candidates
            .iter()
            .find(|shader| shader.index == index)
            .ok_or_else(|| {
                Error::Shader(format!(
                    "shader index {index} is out of range for the selected device"
                ))
            });
    }
    let regex = RegexBuilder::new(selector)
        .case_insensitive(true)
        .build()
        .map_err(Error::from)?;
    let matches: Vec<_> = candidates
        .iter()
        .filter(|shader| {
            regex.is_match(&shader.name)
                || shader
                    .entry_point
                    .as_deref()
                    .is_some_and(|value| regex.is_match(value))
                || regex.is_match(&shader.stage)
                || regex.is_match(&shader.shader_type)
                || shader
                    .pipeline
                    .as_deref()
                    .is_some_and(|value| regex.is_match(value))
        })
        .collect();
    match matches.as_slice() {
        [shader] => Ok(*shader),
        [] => Err(Error::Shader(format!(
            "no shader matched {selector:?}; available: {}",
            candidates
                .iter()
                .map(|shader| format!("{}={}", shader.index, shader.name))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        _ => Err(Error::Shader(format!(
            "{selector:?} matched {} shaders; use an index or a narrower pattern: {}",
            matches.len(),
            matches
                .iter()
                .map(|shader| format!("{}={}", shader.index, shader.name))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn container_info(container: Container) -> Value {
    let sections: Vec<_> = container
        .sections
        .iter()
        .map(|section| {
            let chunks: Vec<_> = section
                .chunks
                .iter()
                .map(|chunk| {
                    json!({
                        "index": chunk.index,
                        "header_offset": chunk.header_offset,
                        "payload_offset": chunk.payload_offset,
                        "compression": chunk.compression,
                        "compression_name": chunk.compression_name(),
                        "reserved": chunk.reserved,
                        "stored_size": chunk.stored_size,
                        "unpacked_size": chunk.unpacked_size,
                    })
                })
                .collect();
            json!({
                "index": section.index,
                "role": section.role(),
                "header_offset": section.header_offset,
                "flags": [section.flag_a, section.flag_b],
                "reserved_06": section.reserved_06,
                "reserved_0c": section.reserved_0c,
                "stored_size": section.stored_size(),
                "unpacked_size": section.unpacked_size,
                "chunks": chunks,
            })
        })
        .collect();
    json!({
        "path": container.path,
        "version": container.version,
        "file_size": container.file_size,
        "sections": sections,
    })
}

fn compile_filter(pattern: Option<&str>) -> Result<Option<Regex>> {
    pattern
        .map(|pattern| RegexBuilder::new(pattern).case_insensitive(true).build())
        .transpose()
        .map_err(Error::from)
}

fn page_value<T: Serialize>(items: &[T], page: &PageArgs) -> Result<Value> {
    let offset = page.offset.min(items.len());
    let stop = items.len().min(offset.saturating_add(page.limit));
    Ok(json!({
        "items": serde_json::to_value(&items[offset..stop])?,
        "page": {
            "offset": offset,
            "returned": stop - offset,
            "total": items.len(),
            "next_offset": (stop < items.len()).then_some(stop),
        }
    }))
}

fn unpack(
    trace: PathBuf,
    directory: &Path,
    skip_bytes: bool,
    counter_data: bool,
    sections: &[usize],
    options: AnalysisOptions,
) -> Result<Value> {
    prepare_empty_directory(directory)?;
    let document = open_document(trace, &options)?;
    write_json_file(
        &directory.join("container.json"),
        &container_info(document.container().clone()),
    )?;
    write_bytes_file(&directory.join("trace.pb"), document.raw_protobuf())?;
    write_bytes_file(
        &directory.join("descriptor-set.pb"),
        &document.descriptor_set_bytes(),
    )?;
    write_json_file(&directory.join("trace.json"), &document.full_json()?)?;
    let byte_fields = document.byte_fields();
    write_json_file(&directory.join("byte-fields.json"), &byte_fields)?;

    let mut extracted = Vec::new();
    if !skip_bytes {
        fs::create_dir(directory.join("bytes"))?;
        let mut index = 0usize;
        document.visit_bytes(|metadata, data| {
            let filename = format!(
                "{index:05}_{}.{}",
                sanitize_filename(&metadata.path),
                content_extension(data)
            );
            let relative = PathBuf::from("bytes").join(filename);
            write_bytes_file(&directory.join(&relative), data)?;
            extracted.push(ExtractedByte {
                metadata: metadata.clone(),
                file: relative,
            });
            index += 1;
            Ok(())
        })?;
        write_json_file(&directory.join("byte-files.json"), &extracted)?;
    }

    let mut materialized_sections = BTreeSet::new();
    if counter_data {
        let section = document.container().section(SectionRole::CounterData)?;
        write_section_file(
            document.container(),
            section,
            &directory.join("counter-data.bin"),
        )?;
        materialized_sections.insert(section.index);
    }
    for index in sections.iter().copied().collect::<BTreeSet<_>>() {
        let section = document.container().sections.get(index).ok_or_else(|| {
            Error::TracePath(format!(
                "section index {index} out of range (count {})",
                document.container().sections.len()
            ))
        })?;
        let filename = format!("section-{index}-{:?}.bin", section.role()).to_ascii_lowercase();
        write_section_file(document.container(), section, &directory.join(filename))?;
        materialized_sections.insert(index);
    }

    let analysis = Analysis::from_document(document, options.nvperf_library)?;
    write_json_file(&directory.join("overview.json"), &analysis.overview())?;
    write_json_file(&directory.join("calls.json"), analysis.calls())?;
    write_json_file(&directory.join("timestamps.json"), analysis.timestamps())?;
    write_json_file(
        &directory.join("timing-buckets.json"),
        analysis.timing_buckets(),
    )?;
    write_json_file(&directory.join("frames.json"), analysis.frames())?;
    write_json_file(
        &directory.join("debug-groups.json"),
        analysis.debug_groups(),
    )?;
    write_json_file(&directory.join("nvtx-ranges.json"), analysis.nvtx_ranges())?;

    let result = json!({
        "directory": directory,
        "protobuf_size": analysis.document().raw_protobuf().len(),
        "byte_field_count": byte_fields.len(),
        "extracted_byte_count": extracted.len(),
        "materialized_sections": materialized_sections,
        "counter_data_materialized": counter_data,
        "unknown_wire_fields_preserved_in": "trace.pb",
    });
    write_json_file(&directory.join("unpack.json"), &result)?;
    Ok(result)
}

fn prepare_empty_directory(path: &Path) -> Result<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a directory", path.display()),
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} is not empty", path.display()),
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn write_section_file(
    container: &Container,
    section: &nsight_gpu_trace::Section,
    path: &Path,
) -> Result<()> {
    let file = create_new_file(path)?;
    let mut writer = BufWriter::new(file);
    container.write_section(section, &mut writer)?;
    writer.flush()?;
    Ok(())
}

fn write_bytes_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut writer = BufWriter::new(create_new_file(path)?);
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

fn write_json_file(path: &Path, value: &(impl Serialize + ?Sized)) -> Result<()> {
    let mut writer = BufWriter::new(create_new_file(path)?);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn create_new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
}

fn write_json_stdout(value: &impl Serialize, pretty: bool) -> Result<()> {
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value)?;
    } else {
        serde_json::to_writer(&mut writer, value)?;
    }
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn sanitize_filename(path: &str) -> String {
    let mut name: String = path
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(140)
        .collect();
    if name.is_empty() {
        name.push_str("field");
    }
    name
}

fn content_extension(data: &[u8]) -> &'static str {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else if data.starts_with(&[0xff, 0xd8, 0xff]) {
        "jpg"
    } else if data.starts_with(b"\x7fELF") {
        "elf"
    } else if data.starts_with(&[0x03, 0x02, 0x23, 0x07]) {
        "spv"
    } else if !data.is_empty()
        && std::str::from_utf8(data).is_ok()
        && data
            .iter()
            .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
            .count()
            * 100
            / data.len()
            >= 90
    {
        "txt"
    } else {
        "bin"
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_line_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn artifact_extension_detection_is_content_based() {
        assert_eq!(content_extension(b"\x89PNG\r\n\x1a\nrest"), "png");
        assert_eq!(content_extension(b"#version 450\nvoid main() {}\n"), "txt");
        assert_eq!(content_extension(&[0, 1, 2]), "bin");
    }
}
