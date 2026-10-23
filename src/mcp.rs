//! Capture-independent MCP requests with bounded views over immutable results.

mod output;

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, Write},
    path::PathBuf,
    sync::Mutex,
};

use regex::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    ActionState, Analysis, AnalysisOptions, ApiCall, CallKind, CompareOptions, Container,
    MetricAvailability, MetricKind, MetricScan, MetricStatistic, MetricStatistics, QueryOptions,
    Result, Scope, ScopeKind, ScopeMetricSummary, ShaderCatalog, TimelineOptions, TimingBucket,
    TopDownReport, compare_captures, diagnostics::metric_category, disassemble, load_keystream,
    recover_keystream, top_down_report,
};

const PROTOCOL_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];
const FALLBACK_PROTOCOL: &str = "2025-06-18";
const INSTRUCTIONS: &str = "Use analyze_capture once for triage; compare_captures for baseline/candidate evidence; query_capture for new evidence; query_result to filter, sort, project or page saved evidence without reopening the capture. Check quality before claims. Regions are ranked by duration, metric pressure, and anomaly; scope_evidence joins one scope's evidence; frame_series evaluates metrics per frame. Replies default to 12 KiB total. result_id identifies immutable JSON cached in memory and on disk (16 in-memory results / 64 MiB). $ref is a JSON Pointer into that JSON before table formatting. columns/rows factor repeated fields; keys identifies object-map rows. Query pages bound computation; view pages bound presentation. Null means unavailable, never zero. bucket_shared applies to the whole bucket; multi_stream_envelope is elapsed overlap. Weighted p50/p95 and burst ratios are evidence; thresholds and comparisons are not causality. The tool reports evidence; it does not accept or reject changes.";
const DEFAULT_TOP: usize = 8;
const MAX_TOP: usize = 25;
const MAX_QUERIES: usize = 16;
const MAX_SCOPES: usize = 1024;
const MAX_PAGE: usize = 100;
const MAX_EXACT_METRICS: usize = 16;
const MAX_METRIC_PATTERNS: usize = 16;
const MAX_SELECTED_METRICS: usize = 48;
const MAX_EVALUATED_METRICS: usize = 64;
const MAX_ARTIFACT_READ: usize = 16 * 1024;

/// A sequential stdio MCP server with no mutable current capture.
/// Only serialized, immutable results survive a call; capture objects are dropped.
pub struct McpServer {
    options: AnalysisOptions,
    results: Mutex<output::ResultStore>,
}

impl McpServer {
    pub fn new(options: AnalysisOptions) -> Self {
        Self {
            options,
            results: Mutex::new(output::ResultStore::default()),
        }
    }

    /// Handle one JSON-RPC request. Notifications intentionally return no response.
    pub fn handle(&self, request: &Value) -> Option<Value> {
        let Some(object) = request.as_object() else {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "JSON-RPC request must be an object",
            ));
        };
        let id = object.get("id")?.clone();
        if !(id.is_null() || id.is_string() || id.is_number()) || serialized_len(&id) > 256 {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "JSON-RPC id must be a scalar of at most 256 serialized bytes",
            ));
        }
        let method = object.get("method").and_then(Value::as_str);
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || method.is_none() {
            return Some(rpc_error(id, -32600, "invalid JSON-RPC request"));
        }
        let method = method.unwrap();
        let params = match object.get("params") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(value)) => value.clone(),
            Some(_) => return Some(rpc_error(id, -32602, "JSON-RPC params must be an object")),
        };
        let modern = params
            .get("_meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(Value::as_str)
            == Some(PROTOCOL_VERSIONS[0]);

        let result = match method {
            "server/discover" => json!({
                "resultType": "complete",
                "supportedVersions": PROTOCOL_VERSIONS,
                "capabilities": { "tools": {} },
                "serverInfo": server_info(),
                "instructions": INSTRUCTIONS,
            }),
            "initialize" => {
                let requested = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(FALLBACK_PROTOCOL);
                let version = if PROTOCOL_VERSIONS.contains(&requested) {
                    requested
                } else {
                    FALLBACK_PROTOCOL
                };
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": server_info(),
                    "instructions": INSTRUCTIONS,
                })
            }
            "ping" => json!({}),
            "tools/list" => {
                let mut result = json!({ "tools": tool_catalog() });
                if modern {
                    result["ttlMs"] = json!(3_600_000);
                    result["cacheScope"] = json!("public");
                    result["resultType"] = json!("complete");
                }
                result
            }
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = match params.get("arguments") {
                    None | Some(Value::Null) => Map::new(),
                    Some(Value::Object(value)) => value.clone(),
                    Some(_) => {
                        return Some(tool_error(id, "tool arguments must be an object", modern));
                    }
                };
                return Some(match self.respond(id.clone(), name, &arguments, modern) {
                    Ok(response) => response,
                    Err(error) => {
                        let budget = integer(&arguments, "max_bytes", output::DEFAULT_BYTES)
                            .unwrap_or(output::DEFAULT_BYTES)
                            .clamp(1024, 64 * 1024);
                        bounded_tool_error(id, &error, modern, budget)
                    }
                });
            }
            _ => {
                return Some(rpc_error(
                    id,
                    -32601,
                    &format!("method not found: {method}"),
                ));
            }
        };
        let mut response = json!({ "jsonrpc": "2.0", "id": id, "result": result });
        if modern && method != "initialize" && method != "tools/list" {
            response["result"]["resultType"] = json!("complete");
        }
        Some(response)
    }

    pub fn serve(self) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut output = stdout.lock();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(Value::Array(requests)) => {
                    let responses = requests
                        .iter()
                        .filter_map(|request| self.handle(request))
                        .collect::<Vec<_>>();
                    (!responses.is_empty()).then_some(Value::Array(responses))
                }
                Ok(request) => self.handle(&request),
                Err(error) => Some(rpc_error(Value::Null, -32700, &error.to_string())),
            };
            if let Some(response) = response {
                serde_json::to_writer(&mut output, &response)?;
                writeln!(output)?;
                output.flush()?;
            }
        }
        Ok(())
    }

    fn respond(
        &self,
        id: Value,
        name: &str,
        arguments: &Map<String, Value>,
        modern: bool,
    ) -> std::result::Result<Value, String> {
        let (mut view, budget) = output::View::parse(arguments)?;
        let preset = if name == "analyze_capture" {
            let preset = if arguments.contains_key("preset") {
                required_string(arguments, "preset")?
            } else {
                "triage"
            };
            if !matches!(preset, "triage" | "metrics" | "full") {
                return Err("preset must be triage, metrics or full".into());
            }
            preset
        } else {
            "full"
        };
        let (result_id, value) = if name == "query_result" {
            let result_id = required_string(arguments, "result_id")?;
            let value = self
                .results
                .lock()
                .map_err(|error| error.to_string())?
                .get(result_id)?;
            (result_id.to_owned(), value)
        } else {
            let value = self.call_tool(name, arguments)?;
            let result_id = self
                .results
                .lock()
                .map_err(|error| error.to_string())?
                .insert(&value)?;
            (result_id, value)
        };
        if !arguments.contains_key("view") {
            if name == "query_capture" {
                view.path = "/results".into();
            }
            if name == "compare_captures" {
                view.select = vec![
                    "/comparability",
                    "/metric_summary",
                    "/metrics",
                    "/scope_kind",
                    "/scopes",
                    "/shaders",
                    "/limitations",
                ]
                .into_iter()
                .filter(|path| value.pointer(path).is_some())
                .map(str::to_owned)
                .collect();
                return output::response(id, &result_id, &value, &view, budget, modern).map_err(
                    |error| {
                        format!(
                            "Saved result_id={result_id}; retry query_result with a corrected view. {error}"
                        )
                    },
                );
            }
            view.select = match preset {
                "triage" => vec![
                    "/capture",
                    "/workload",
                    "/quality",
                    "/timeline/frame_summary",
                    "/timeline/longest_global_gap",
                    "/timeline/parallelism",
                    "/timing",
                    "/counter_coverage",
                    "/diagnostics/findings",
                    "/representative_metrics/capture_summary",
                    "/regions",
                    "/manifest/unavailable_evidence",
                ],
                "metrics" => vec![
                    "/representative_metrics",
                    "/regions",
                    "/region_metrics",
                    "/manifest/unavailable_evidence",
                ],
                _ => Vec::new(),
            }
            .into_iter()
            .filter(|path| value.pointer(path).is_some())
            .map(str::to_owned)
            .collect();
        }
        output::response(id, &result_id, &value, &view, budget, modern).map_err(|error| {
            format!(
                "Saved result_id={result_id}; retry query_result with a corrected view. {error}"
            )
        })
    }

    fn call_tool(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        match name {
            "analyze_capture" => {
                let capture = PathBuf::from(required_string(arguments, "capture")?);
                let scope_pattern = regex(arguments, "scope_pattern")?;
                let metric_patterns = optional_string_array(arguments, "metric_patterns")?;
                let metrics = optional_string_array(arguments, "metrics")?;
                if metric_patterns.len() > MAX_METRIC_PATTERNS {
                    return Err(format!(
                        "metric_patterns accepts at most {MAX_METRIC_PATTERNS} values"
                    ));
                }
                if metrics.len() > MAX_EXACT_METRICS {
                    return Err(format!(
                        "metrics accepts at most {MAX_EXACT_METRICS} exact names"
                    ));
                }
                let top = integer(arguments, "top", DEFAULT_TOP)?.clamp(1, MAX_TOP);
                let mut analysis = Analysis::open(capture, self.options.clone())
                    .map_err(|error| error.to_string())?;
                analyze_capture(
                    &mut analysis,
                    scope_pattern.as_ref(),
                    &metric_patterns,
                    &metrics,
                    top,
                )
            }
            "query_capture" => self.query_capture(arguments),
            "compare_captures" => {
                let baseline = PathBuf::from(required_string(arguments, "baseline")?);
                let candidate = PathBuf::from(required_string(arguments, "candidate")?);
                let top = integer(arguments, "top", DEFAULT_TOP)?.clamp(1, MAX_TOP);
                let scope_kind = arguments
                    .get("scope_kind")
                    .and_then(Value::as_str)
                    .map(scope_kind)
                    .transpose()?;
                let scope_pattern = regex(arguments, "scope_pattern")?;
                let scope_metrics = optional_string_array(arguments, "metrics")?;
                if scope_metrics.len() > MAX_EVALUATED_METRICS {
                    return Err(format!(
                        "metrics accepts at most {MAX_EVALUATED_METRICS} exact names"
                    ));
                }
                let include_shaders = boolean(arguments, "include_shaders", true)?;
                let mut baseline = Analysis::open(baseline, self.options.clone())
                    .map_err(|error| error.to_string())?;
                let mut candidate = Analysis::open(candidate, self.options.clone())
                    .map_err(|error| error.to_string())?;
                let options = CompareOptions {
                    top,
                    scope_kind,
                    scope_pattern,
                    include_shaders,
                    scope_metrics,
                };
                let comparison = compare_captures(&mut baseline, &mut candidate, &options)
                    .map_err(|error| error.to_string())?;
                serde_json::to_value(comparison).map_err(|error| error.to_string())
            }
            _ => Err(format!("unknown analysis tool: {name}")),
        }
    }

    fn query_capture(&self, arguments: &Map<String, Value>) -> std::result::Result<Value, String> {
        let capture = PathBuf::from(required_string(arguments, "capture")?);
        let queries = arguments
            .get("queries")
            .and_then(Value::as_array)
            .ok_or_else(|| "queries must be an array".to_owned())?;
        if queries.is_empty() || queries.len() > MAX_QUERIES {
            return Err(format!(
                "query_capture requires between 1 and {MAX_QUERIES} queries"
            ));
        }
        let queries = queries
            .iter()
            .enumerate()
            .map(|(index, query)| {
                let query = query
                    .as_object()
                    .ok_or_else(|| format!("queries[{index}] must be an object"))?;
                let kind = required_string(query, "type")?;
                if !QUERY_TYPES.contains(&kind) {
                    return Err(format!("queries[{index}] has unsupported type {kind:?}"));
                }
                Ok((kind, query))
            })
            .collect::<std::result::Result<Vec<_>, String>>()?;

        if queries.iter().all(|(kind, _)| *kind == "container_info") {
            let container = Container::open(&capture).map_err(|error| error.to_string())?;
            let results = queries
                .iter()
                .enumerate()
                .map(|(index, (kind, query))| {
                    container_query(&container, query)
                        .map(|data| json!({ "index": index, "type": kind, "data": data }))
                        .map_err(|error| format!("queries[{index}] ({kind}): {error}"))
                })
                .collect::<std::result::Result<Vec<_>, String>>()?;
            return Ok(json!({
                "capture": container.path,
                "results": results,
            }));
        }

        let mut analysis =
            Analysis::open(&capture, self.options.clone()).map_err(|error| error.to_string())?;
        let mut results = Vec::with_capacity(queries.len());
        for (index, (kind, query)) in queries.into_iter().enumerate() {
            let data = execute_query(&mut analysis, kind, query)
                .map_err(|error| format!("queries[{index}] ({kind}): {error}"))?;
            results.push(json!({ "index": index, "type": kind, "data": data }));
        }
        Ok(json!({
            "capture": analysis.document().container().path,
            "results": results,
        }))
    }
}

struct RegionSelection {
    kind: &'static str,
    available: usize,
    matching: usize,
    precision: BTreeMap<String, usize>,
    scopes: Vec<Scope>,
}

#[derive(Debug, Clone, Serialize)]
struct RegionScore {
    candidate_index: usize,
    scope_id: String,
    label: String,
    duration_ns: Option<u64>,
    duration_score: f64,
    metric_pressure: Option<f64>,
    metric_anomaly: Option<f64>,
    combined_score: f64,
    reason: String,
}

struct MetricPipeline {
    counter_coverage: Value,
    metric_scan: Value,
    diagnostics: Value,
    selected_metrics: Vec<String>,
    selection: Value,
    capture_summary: BTreeMap<String, MetricStatistics>,
    region_summaries: Vec<ScopeMetricSummary>,
    metric_references: BTreeMap<String, MetricAvailability>,
}

fn analyze_capture(
    analysis: &mut Analysis,
    scope_pattern: Option<&Regex>,
    metric_patterns: &[String],
    exact_metrics: &[String],
    top: usize,
) -> std::result::Result<Value, String> {
    let candidate_limit = top.clamp(128, 256);
    let regions = select_regions(analysis, scope_pattern, candidate_limit)?;
    let byte_fields = analysis.document().byte_fields();
    let root_fields = analysis
        .document()
        .schema("")
        .map_err(|error| error.to_string())?;
    let scope_counts = scope_counts(analysis)?;
    let mut unavailable_evidence = Vec::new();
    if analysis.debug_groups().is_empty() {
        unavailable_evidence.push(format!(
            "debug-label regions are absent; region analysis fell back to {}",
            regions.kind
        ));
    }
    if regions.kind == "nvtx_range" {
        unavailable_evidence.push(
            "NVTX timestamps use an unvalidated legacy clock, so metric attribution is null".into(),
        );
    }
    if regions.kind == "none" {
        unavailable_evidence.push(
            "no debug groups, NVTX ranges, frames, or timestamp buckets are available".into(),
        );
    }

    let metric_pipeline = build_metric_pipeline(
        analysis,
        &regions.scopes,
        metric_patterns,
        exact_metrics,
        top,
    );
    let (
        counter_coverage,
        metric_scan,
        diagnostics,
        selected_metrics,
        metric_selection,
        capture_metric_summary,
        region_summaries,
        metric_references,
    ) = match metric_pipeline {
        Ok(pipeline) => (
            pipeline.counter_coverage,
            pipeline.metric_scan,
            pipeline.diagnostics,
            pipeline.selected_metrics,
            pipeline.selection,
            json!(compact_summary(&pipeline.capture_summary)),
            pipeline.region_summaries,
            pipeline.metric_references,
        ),
        Err(error) => {
            unavailable_evidence.push(format!("counter/metric evidence unavailable: {error}"));
            (
                Value::Null,
                json!({ "complete": false, "unavailable": error }),
                Value::Null,
                Vec::new(),
                json!({ "selected": 0 }),
                Value::Null,
                Vec::new(),
                BTreeMap::new(),
            )
        }
    };

    let ranked_regions = rank_regions(&regions.scopes, &region_summaries, &metric_references, top);
    let region_values = ranked_regions
        .iter()
        .map(|(index, score)| {
            let mut value = region_report(
                analysis,
                region_summaries.get(*index).map(|summary| &summary.scope),
                &regions.scopes[*index],
                region_summaries.get(*index).map(|summary| &summary.summary),
            );
            if let Value::Object(object) = &mut value {
                object.insert(
                    "selection".into(),
                    serde_json::to_value(score).unwrap_or(Value::Null),
                );
            }
            value
        })
        .collect::<Vec<_>>();
    let region_ranking: Vec<_> = ranked_regions
        .iter()
        .map(|(_, score)| score.clone())
        .collect();
    let quality = analysis.quality().map_err(|error| error.to_string())?;
    let timeline = analysis.timeline(TimelineOptions { min_gap_ns: 1000 });
    let container = analysis.document().container();
    let timing = timing_summary(analysis, &regions.precision);
    let workload = workload_summary(analysis);
    let largest_artifacts = {
        let mut fields = byte_fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|field| std::cmp::Reverse(field.size));
        fields
            .into_iter()
            .take(5)
            .map(|field| {
                json!({
                    "path": field.path,
                    "size": field.size,
                    "sha256": field.sha256,
                })
            })
            .collect::<Vec<_>>()
    };
    let present_root_fields = root_fields.iter().filter(|field| field.present).count();
    let root_field_manifest = root_fields
        .iter()
        .map(|field| {
            json!({
                "name": field.name,
                "kind": field.kind,
                "present": field.present,
                "item_count": field.item_count,
            })
        })
        .collect::<Vec<_>>();
    let section_manifest = container
        .sections
        .iter()
        .map(|section| {
            json!({
                "index": section.index,
                "role": section.role(),
                "stored_size": section.stored_size(),
                "unpacked_size": section.unpacked_size,
                "chunk_count": section.chunks.len(),
            })
        })
        .collect::<Vec<_>>();

    let result = json!({
        "capture": {
            "path": container.path,
            "wrpv_version": container.version,
            "compressed_bytes": container.file_size,
            "protobuf_type": crate::trace::TRACE_MESSAGE,
            "protobuf_bytes": analysis.document().raw_protobuf().len(),
        },
        "workload": workload,
        "quality": quality,
        "timeline": timeline,
        "counter_coverage": counter_coverage,
        "timing": timing,
        "metric_scan": metric_scan,
        "diagnostics": diagnostics,
        "representative_metrics": {
            "names": selected_metrics,
            "selection": metric_selection,
            "capture_summary": capture_metric_summary,
        },
        "regions": {
            "kind": regions.kind,
            "scope_pattern": scope_pattern.map(Regex::as_str),
            "available": regions.available,
            "matching": regions.matching,
            "candidates": regions.scopes.len(),
            "truncated_candidates": regions.matching > regions.scopes.len(),
            "returned": region_values.len(),
            "next_offset": Value::Null,
            "note": "Triage returns the top ranked candidates. Use scopes or scope_ranking for exhaustive region queries, or increase top.",
            "ranking": {
                "method": "0.45*duration + 0.35*metric_pressure + 0.20*metric_anomaly; metric terms are omitted when no matching reference metrics exist",
                "items": region_ranking,
            },
            "items": region_values,
        },
        "region_metrics": region_summaries.iter().map(|summary| {
            (summary.scope.id.clone(), compact_summary(&summary.summary))
        }).collect::<Map<_, _>>(),
        "manifest": {
            "sections": section_manifest,
            "protobuf": {
                "raw_bytes": analysis.document().raw_protobuf().len(),
                "unknown_wire_fields": analysis.document().unknown_field_count(),
                "root_fields": {
                    "total": root_fields.len(),
                    "present": present_root_fields,
                    "items": root_field_manifest,
                },
                "authoritative_cli_access": ["json", "schema", "query", "unpack"],
            },
            "artifacts": {
                "count": byte_fields.len(),
                "total_bytes": byte_fields.iter().map(|field| field.size).sum::<usize>(),
                "largest": largest_artifacts,
                "authoritative_cli_access": ["artifacts", "extract", "unpack"],
            },
            "calls": {
                "count": analysis.calls().len(),
                "arguments_in_default_response": false,
                "query_type": "calls",
            },
            "scopes": {
                "counts": scope_counts,
                "selected_region_kind": regions.kind,
                "query_type": "scopes",
            },
            "unavailable_evidence": unavailable_evidence,
            "omitted_from_default": [
                "metric sample series",
                "call arguments and return values",
                "artifact payloads",
                "complete raw protobuf values",
            ],
            "follow_up": {
                "tool": "query_capture",
                "offsets_are_stateless": true,
            },
        },
    });
    Ok(result)
}

fn select_regions(
    analysis: &Analysis,
    pattern: Option<&Regex>,
    top: usize,
) -> std::result::Result<RegionSelection, String> {
    let (kind, scope_kind) = if !analysis.debug_groups().is_empty() {
        ("debug_group", Some(ScopeKind::DebugGroup))
    } else if !analysis.nvtx_ranges().is_empty() {
        ("nvtx_range", Some(ScopeKind::NvtxRange))
    } else if !analysis.frames().is_empty() {
        ("frame", Some(ScopeKind::Frame))
    } else if !analysis.timing_buckets().is_empty() {
        ("timing_bucket", Some(ScopeKind::TimingBucket))
    } else {
        ("none", None)
    };
    let mut scopes = match scope_kind {
        Some(kind) => analysis.scopes(kind).map_err(|error| error.to_string())?,
        None => Vec::new(),
    };
    let available = scopes.len();
    scopes.retain(|scope| {
        pattern.is_none_or(|pattern| pattern.is_match(&scope.id) || pattern.is_match(&scope.label))
    });
    scopes.sort_by(|left, right| {
        right
            .duration_ns()
            .cmp(&left.duration_ns())
            .then_with(|| left.id.cmp(&right.id))
    });
    let matching = scopes.len();
    let precision = histogram(scopes.iter().map(|scope| scope.precision.clone()));
    scopes.truncate(top);
    Ok(RegionSelection {
        kind,
        available,
        matching,
        precision,
        scopes,
    })
}

fn rank_regions(
    scopes: &[Scope],
    summaries: &[ScopeMetricSummary],
    references: &BTreeMap<String, MetricAvailability>,
    top: usize,
) -> Vec<(usize, RegionScore)> {
    let max_duration = scopes
        .iter()
        .filter_map(Scope::duration_ns)
        .max()
        .unwrap_or(0);
    let mut ranked = scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| {
            let duration_ns = scope.duration_ns();
            let duration_score = duration_ns
                .filter(|_| max_duration > 0)
                .map(|duration| duration as f64 / max_duration as f64)
                .unwrap_or(0.0);
            let summary = summaries.get(index).map(|summary| &summary.summary);
            let mut pressure: Option<f64> = None;
            let mut anomaly: Option<f64> = None;
            if let Some(summary) = summary {
                for (metric, statistics) in summary {
                    let Some(reference) = references.get(metric) else {
                        continue;
                    };
                    let Some(value) = statistics.mean else {
                        continue;
                    };
                    if let Some(level) = reference.p95.or(reference.max)
                        && level > 0.0
                        && value.is_finite()
                    {
                        let ratio = value / level;
                        pressure = Some(pressure.map_or(ratio, |current| current.max(ratio)));
                    }
                    if let (Some(mean), Some(stddev)) = (
                        reference.time_weighted_mean.or(reference.sample_mean),
                        reference.stddev,
                    ) && stddev > 0.0
                        && value.is_finite()
                    {
                        let z = ((value - mean) / stddev).abs().min(10.0);
                        anomaly = Some(anomaly.map_or(z, |current| current.max(z)));
                    }
                }
            }
            let pressure_score = pressure.unwrap_or(0.0).clamp(0.0, 1.0);
            let anomaly_score = (anomaly.unwrap_or(0.0) / 5.0).clamp(0.0, 1.0);
            let combined_score =
                0.45 * duration_score + 0.35 * pressure_score + 0.20 * anomaly_score;
            let reason = if pressure.is_none() && anomaly.is_none() {
                "duration"
            } else if pressure_score >= duration_score && pressure_score >= anomaly_score {
                "metric_pressure"
            } else if anomaly_score > duration_score {
                "metric_anomaly"
            } else {
                "duration"
            };
            (
                index,
                RegionScore {
                    candidate_index: index,
                    scope_id: scope.id.clone(),
                    label: scope.label.clone(),
                    duration_ns,
                    duration_score,
                    metric_pressure: pressure,
                    metric_anomaly: anomaly,
                    combined_score,
                    reason: reason.into(),
                },
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .1
            .combined_score
            .total_cmp(&left.1.combined_score)
            .then_with(|| right.1.duration_ns.cmp(&left.1.duration_ns))
            .then_with(|| left.1.scope_id.cmp(&right.1.scope_id))
    });
    ranked.truncate(top.max(1));
    ranked
}

fn build_metric_pipeline(
    analysis: &mut Analysis,
    regions: &[Scope],
    metric_patterns: &[String],
    exact_metrics: &[String],
    top: usize,
) -> std::result::Result<MetricPipeline, String> {
    let info = analysis
        .counter_info()
        .map_err(|error| error.to_string())?
        .clone();
    let samples = analysis
        .counter_samples()
        .map_err(|error| error.to_string())?
        .to_vec();
    let scan = analysis
        .scan_all_metrics()
        .map_err(|error| error.to_string())?;
    let report = top_down_report(&scan, top);
    let (selected_metrics, selection) =
        select_metrics(&scan, &report, metric_patterns, exact_metrics, top)?;
    let metric_references = selected_metrics
        .iter()
        .filter_map(|name| {
            scan.metrics
                .iter()
                .find(|metric| &metric.metric_name == name)
                .cloned()
                .map(|metric| (name.clone(), metric))
        })
        .collect();
    let mut scopes = Vec::with_capacity(regions.len() + 1);
    scopes.push(analysis.capture_scope());
    scopes.extend_from_slice(regions);
    let aggregation = analysis
        .aggregate_scope_metrics(&scopes, &selected_metrics)
        .map_err(|error| error.to_string())?;
    let mut summaries = aggregation.scopes.into_iter();
    let capture_summary = summaries
        .next()
        .map(|summary| summary.summary)
        .unwrap_or_default();
    let timestamped = samples
        .iter()
        .filter(|sample| sample.timestamp_valid)
        .count();
    let complete = samples.iter().filter(|sample| sample.complete).count();
    let first_timestamp = samples
        .iter()
        .find(|sample| sample.timestamp_valid)
        .map(|sample| sample.timestamp_start_ns);
    let last_timestamp = samples
        .iter()
        .rev()
        .find(|sample| sample.timestamp_valid)
        .map(|sample| sample.timestamp_end_ns);

    Ok(MetricPipeline {
        counter_coverage: json!({
            "available": true,
            "chip_name": info.chip_name,
            "image_bytes": info.image_size,
            "ranges": info.num_ranges,
            "samples": {
                "total": info.periodic_sampler.total_ranges,
                "populated": info.periodic_sampler.populated_ranges,
                "completed": info.periodic_sampler.completed_ranges,
                "timestamped": timestamped,
                "complete": complete,
            },
            "window": {
                "start_ns": first_timestamp,
                "end_ns": last_timestamp,
                "span_ns": info.periodic_sampler.timestamp_span_ns,
            },
        }),
        metric_scan: compact_scan(&scan),
        diagnostics: compact_diagnostics(&report),
        selected_metrics,
        selection,
        capture_summary,
        region_summaries: summaries.collect(),
        metric_references,
    })
}

fn select_metrics(
    scan: &MetricScan,
    report: &TopDownReport,
    patterns: &[String],
    exact: &[String],
    top: usize,
) -> std::result::Result<(Vec<String>, Value), String> {
    let compiled = patterns
        .iter()
        .map(|pattern| {
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|error| error.to_string())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    let mut add = |name: &str| {
        if selected.len() < MAX_SELECTED_METRICS && seen.insert(name.to_owned()) {
            selected.push(name.to_owned());
        }
    };

    for metric in exact {
        add(metric);
    }
    for finding in &report.findings {
        add(&finding.metric_name);
    }
    for category in &report.categories {
        if let Some(metric) = category.top_percent_of_peak.first() {
            add(&metric.metric_name);
        } else if let Some(metric) = scan.metrics.iter().find(|metric| {
            metric.valid_samples > 0 && metric_category(&metric.base_name) == category.category
        }) {
            add(&metric.metric_name);
        }
    }
    let mut pattern_matches = scan
        .metrics
        .iter()
        .filter(|metric| metric.valid_samples > 0)
        .filter(|metric| {
            compiled.iter().any(|pattern| {
                pattern.is_match(&metric.base_name) || pattern.is_match(&metric.metric_name)
            })
        })
        .collect::<Vec<_>>();
    pattern_matches.sort_by(|left, right| {
        right
            .sample_mean
            .unwrap_or(f64::NEG_INFINITY)
            .total_cmp(&left.sample_mean.unwrap_or(f64::NEG_INFINITY))
            .then_with(|| left.metric_name.cmp(&right.metric_name))
    });
    let pattern_match_count = pattern_matches.len();
    for metric in pattern_matches.into_iter().take(top) {
        add(&metric.metric_name);
    }
    let selected_count = selected.len();
    Ok((
        selected,
        json!({
            "finding_metrics": report.findings.len(),
            "subsystem_categories": report.categories.len(),
            "exact_requested": exact.len(),
            "pattern_count": patterns.len(),
            "collected_pattern_matches": pattern_match_count,
            "pattern_matches_considered": pattern_match_count.min(top),
            "selected": selected_count,
            "maximum": MAX_SELECTED_METRICS,
        }),
    ))
}

fn compact_scan(scan: &MetricScan) -> Value {
    let available = scan
        .metrics
        .iter()
        .filter(|metric| metric.valid_samples > 0)
        .count();
    let mut kinds: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for metric in &scan.metrics {
        let counts = kinds.entry(metric_kind_name(metric.kind)).or_default();
        counts.0 += 1;
        counts.1 += usize::from(metric.valid_samples > 0);
    }
    let kinds = kinds
        .into_iter()
        .map(|(kind, (scanned, available))| {
            (
                kind.to_owned(),
                json!({ "scanned": scanned, "available": available }),
            )
        })
        .collect::<Map<_, _>>();
    json!({
        "complete": true,
        "chip_name": scan.chip_name,
        "sample_start": scan.sample_start,
        "sample_stop": scan.sample_stop,
        "selected_samples": scan.selected_samples,
        "timestamped_samples": scan.timestamped_samples,
        "complete_samples": scan.complete_samples,
        "sample_duration_ns": scan.sample_duration_ns,
        "scanned_metric_bases": scan.metrics.len(),
        "available_metric_bases": available,
        "unavailable_metric_bases": scan.metrics.len() - available,
        "by_kind": kinds,
        "values_omitted": "Use query_capture metric_discovery or metric_evaluation for bounded metric rows.",
    })
}

fn compact_diagnostics(report: &TopDownReport) -> Value {
    let categories = report
        .categories
        .iter()
        .map(|category| {
            json!({
                "category": category.category,
                "available_metrics": category.available_metrics,
                "nonzero_metrics": category.nonzero_metrics,
                "leading_metric": category.top_percent_of_peak.first(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "methodology": report.methodology,
        "sampling": report.sampling,
        "activity": report.activity,
        "categories": categories,
        "top_percent_of_peak": report.top_percent_of_peak,
        "throughput_cluster": report.throughput_cluster,
        "throughput_cluster_spread_pct_points": report.throughput_cluster_spread_pct_points,
        "findings": report.findings,
        "limitations": report.limitations,
    })
}

fn compact_summary(summary: &BTreeMap<String, MetricStatistics>) -> Value {
    Value::Object(
        summary
            .iter()
            .map(|(metric, statistics)| (metric.clone(), compact_statistics(statistics)))
            .collect(),
    )
}

fn compact_statistics(statistics: &MetricStatistics) -> Value {
    json!({
        "valid_samples": statistics.valid_samples,
        "selected_samples": statistics.selected_samples,
        "coverage_pct": statistics.coverage_pct,
        "mean": statistics.mean,
        "stddev": statistics.stddev,
        "min": statistics.min,
        "max": statistics.max,
        "p50": statistics.p50,
        "p95": statistics.p95,
    })
}

fn region_report(
    analysis: &Analysis,
    resolved: Option<&Scope>,
    original: &Scope,
    summary: Option<&BTreeMap<String, MetricStatistics>>,
) -> Value {
    let scope = resolved.unwrap_or(original);
    let coverage = summary.map(|summary| {
        let values = summary.values().map(|statistics| statistics.coverage_pct);
        let min = values.clone().min_by(f64::total_cmp);
        let max = values.max_by(f64::total_cmp);
        json!({
            "sample_start": scope.sample_start,
            "sample_stop": scope.sample_stop,
            "minimum_metric_pct": min,
            "maximum_metric_pct": max,
        })
    });
    json!({
        "scope_id": scope.id,
        "label": scope.label,
        "calls": call_evidence(analysis, scope),
        "timing": {
            "start_ns": scope.start_ns,
            "end_ns": scope.end_ns,
            "duration_ns": scope.duration_ns(),
            "precision": scope.precision,
            "warnings": scope.warnings,
        },
        "counter_coverage": coverage,
    })
}

fn call_evidence(analysis: &Analysis, scope: &Scope) -> Value {
    let calls: Vec<&ApiCall> = if let Some((start, stop)) = scope.call_start.zip(scope.call_stop) {
        analysis
            .calls()
            .get(start..stop)
            .unwrap_or_default()
            .iter()
            .collect()
    } else if scope.precision != "nvtx_clock_unvalidated" {
        let mut indices = BTreeSet::new();
        if let Some((start, end)) = scope.start_ns.zip(scope.end_ns) {
            for bucket in analysis.timing_buckets().iter().filter(|bucket| {
                bucket.interval().is_some_and(|(bucket_start, bucket_end)| {
                    bucket_start < end && bucket_end > start
                })
            }) {
                indices.extend(bucket.first_global_call_index..bucket.next_global_call_index);
            }
        }
        indices
            .into_iter()
            .filter_map(|index| analysis.calls().get(index))
            .collect()
    } else {
        Vec::new()
    };
    let mut names = histogram(calls.iter().map(|call| call.name.as_str()))
        .into_iter()
        .collect::<Vec<_>>();
    names.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    let distinct_names = names.len();
    names.truncate(20);
    json!({
        "count": calls.len(),
        "distinct_names": distinct_names,
        "histogram": names.into_iter().map(|(name, count)| json!({ "name": name, "count": count })).collect::<Vec<_>>(),
        "kinds": histogram(calls.iter().map(|call| call.kind)),
    })
}

fn workload_summary(analysis: &Analysis) -> Value {
    let mut names = histogram(analysis.calls().iter().map(|call| call.name.as_str()))
        .into_iter()
        .collect::<Vec<_>>();
    names.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    let distinct_names = names.len();
    names.truncate(20);
    let mut devices: BTreeMap<usize, (usize, usize, usize, usize)> = BTreeMap::new();
    for call in analysis.calls() {
        let entry = devices.entry(call.device_index).or_default();
        entry.0 += 1;
        entry.1 += usize::from(call.kind.is_action());
    }
    for bucket in analysis.timing_buckets() {
        devices.entry(bucket.device_index).or_default().2 += 1;
    }
    for frame in analysis.frames() {
        devices.entry(frame.device_index).or_default().3 += 1;
    }
    let devices = devices
        .into_iter()
        .map(|(device_index, (calls, actions, timing_buckets, frames))| {
            json!({
                "device_index": device_index,
                "calls": calls,
                "actions": actions,
                "timing_buckets": timing_buckets,
                "frames": frames,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "apis": analysis.api_names(),
        "calls": analysis.calls().len(),
        "actions": analysis.calls().iter().filter(|call| call.kind.is_action()).count(),
        "call_kinds": histogram(analysis.calls().iter().map(|call| call.kind)),
        "leading_calls": names.into_iter().map(|(name, count)| json!({ "name": name, "count": count })).collect::<Vec<_>>(),
        "distinct_call_names": distinct_names,
        "devices": devices,
        "frames": analysis.frames().len(),
        "debug_groups": analysis.debug_groups().len(),
        "nvtx_ranges": analysis.nvtx_ranges().len(),
        "timing_buckets": analysis.timing_buckets().len(),
    })
}

fn timing_summary(analysis: &Analysis, region_precision: &BTreeMap<String, usize>) -> Value {
    let covered_calls = analysis
        .timing_buckets()
        .iter()
        .flat_map(|bucket| bucket.first_global_call_index..bucket.next_global_call_index)
        .collect::<BTreeSet<_>>()
        .len();
    let shared_buckets = analysis
        .timing_buckets()
        .iter()
        .filter(|bucket| bucket.call_count > 1)
        .count();
    json!({
        "bucket_count": analysis.timing_buckets().len(),
        "timestamped_calls": covered_calls,
        "call_coverage_pct": if analysis.calls().is_empty() { 0.0 } else { 100.0 * covered_calls as f64 / analysis.calls().len() as f64 },
        "single_call_buckets": analysis.timing_buckets().len() - shared_buckets,
        "shared_call_buckets": shared_buckets,
        "longest_bucket_ns": analysis.timing_buckets().iter().filter_map(|bucket| bucket.max_duration_ns).max(),
        "region_precision": region_precision,
        "attribution_rule": "bucket_shared timing and metrics apply to the whole bucket, not each enclosed call",
    })
}

fn scope_counts(analysis: &Analysis) -> std::result::Result<BTreeMap<&'static str, usize>, String> {
    Ok(BTreeMap::from([
        ("debug_group", analysis.debug_groups().len()),
        ("nvtx_range", analysis.nvtx_ranges().len()),
        ("frame", analysis.frames().len()),
        (
            "action",
            analysis
                .calls()
                .iter()
                .filter(|call| call.kind.is_action())
                .count(),
        ),
        ("timing_bucket", analysis.timing_buckets().len()),
    ]))
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

const QUERY_TYPES: &[&str] = &[
    "container_info",
    "calls",
    "timings",
    "scopes",
    "counter_samples",
    "capture_quality",
    "timeline",
    "action_state",
    "metric_discovery",
    "metric_evaluation",
    "scope_evidence",
    "frame_series",
    "scope_ranking",
    "trace_schema",
    "trace_query",
    "artifact_inventory",
    "artifact_read",
    "shader_inventory",
    "shader_sass",
];

fn execute_query(
    analysis: &mut Analysis,
    kind: &str,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    match kind {
        "container_info" => container_query(analysis.document().container(), query),
        "calls" => calls_query(analysis, query),
        "timings" => timings_query(analysis, query),
        "scopes" => scopes_query(analysis, query),
        "counter_samples" => counter_samples_query(analysis, query),
        "capture_quality" => {
            serde_json::to_value(analysis.quality().map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())
        }
        "timeline" => timeline_query(analysis, query),
        "action_state" => action_state_query(analysis, query),
        "metric_discovery" => metric_discovery_query(analysis, query),
        "metric_evaluation" => metric_evaluation_query(analysis, query),
        "scope_evidence" => scope_evidence_query(analysis, query),
        "frame_series" => frame_series_query(analysis, query),
        "scope_ranking" => scope_ranking_query(analysis, query),
        "trace_schema" => trace_schema_query(analysis, query),
        "trace_query" => trace_query(analysis, query),
        "artifact_inventory" => artifact_inventory_query(analysis, query),
        "artifact_read" => artifact_read_query(analysis, query),
        "shader_inventory" => shader_inventory_query(analysis, query),
        "shader_sass" => shader_sass_query(analysis, query),
        _ => Err(format!("unsupported query type {kind:?}")),
    }
}

fn container_query(
    container: &Container,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    if let Some(index) = optional_integer(query, "section_index")? {
        let section = container.sections.get(index).ok_or_else(|| {
            format!(
                "section_index {index} is out of range for {} sections",
                container.sections.len()
            )
        })?;
        let offset = integer(query, "offset", 0)?;
        let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
        let chunks = section
            .chunks
            .iter()
            .map(|chunk| {
                json!({
                    "index": chunk.index,
                    "header_offset": chunk.header_offset,
                    "payload_offset": chunk.payload_offset,
                    "compression": chunk.compression,
                    "compression_name": chunk.compression_name(),
                    "stored_size": chunk.stored_size,
                    "unpacked_size": chunk.unpacked_size,
                })
            })
            .collect::<Vec<_>>();
        return Ok(json!({
            "path": container.path,
            "version": container.version,
            "file_size": container.file_size,
            "section": {
                "index": section.index,
                "role": section.role(),
                "flags": [section.flag_a, section.flag_b],
                "stored_size": section.stored_size(),
                "unpacked_size": section.unpacked_size,
                "chunks": paged(&chunks, offset, limit)?,
            },
        }));
    }
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let sections = container
        .sections
        .iter()
        .map(|section| {
            json!({
                "index": section.index,
                "role": section.role(),
                "flags": [section.flag_a, section.flag_b],
                "stored_size": section.stored_size(),
                "unpacked_size": section.unpacked_size,
                "chunk_count": section.chunks.len(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "path": container.path,
        "version": container.version,
        "file_size": container.file_size,
        "sections": paged(&sections, offset, limit)?,
    }))
}

fn calls_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let pattern = regex(query, "pattern")?;
    let kind = call_kind(query.get("kind").and_then(Value::as_str))?;
    let include_arguments = boolean(query, "include_arguments", false)?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let calls = analysis
        .calls()
        .iter()
        .filter(|call| kind.is_none_or(|kind| call.kind == kind))
        .filter(|call| {
            pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(&call.name))
        })
        .map(|call| call_value(call, include_arguments))
        .collect::<Vec<_>>();
    paged(&calls, offset, limit)
}

fn call_value(call: &ApiCall, include_arguments: bool) -> Value {
    if include_arguments {
        serde_json::to_value(call).unwrap_or(Value::Null)
    } else {
        json!({
            "global_index": call.global_index,
            "device_index": call.device_index,
            "queue_index": call.queue_index,
            "stream_index": call.stream_index,
            "call_index": call.call_index,
            "name": call.name,
            "kind": call.kind,
            "interface": call.interface,
        })
    }
}

fn timings_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let pattern = regex(query, "pattern")?;
    let kind = call_kind(query.get("kind").and_then(Value::as_str))?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let mut buckets = analysis
        .timing_buckets()
        .iter()
        .filter(|bucket| timing_matches(analysis, bucket, pattern.as_ref(), kind))
        .collect::<Vec<_>>();
    buckets.sort_by_key(|bucket| std::cmp::Reverse(bucket.max_duration_ns));
    paged(&buckets, offset, limit)
}

fn timing_matches(
    analysis: &Analysis,
    bucket: &TimingBucket,
    pattern: Option<&Regex>,
    kind: Option<CallKind>,
) -> bool {
    if kind.is_none() && pattern.is_none() {
        return true;
    }
    analysis.calls()[bucket.first_global_call_index..bucket.next_global_call_index]
        .iter()
        .any(|call| {
            kind.is_none_or(|kind| call.kind == kind)
                && pattern.is_none_or(|pattern| pattern.is_match(&call.name))
        })
}

fn scopes_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let kind_name = required_string(query, "kind")?;
    let kind = scope_kind(kind_name)?;
    let pattern = regex(query, "pattern")?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let scopes = analysis
        .scopes(kind)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|scope| {
            pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(&scope.id) || pattern.is_match(&scope.label))
        })
        .collect::<Vec<_>>();
    Ok(json!({ "kind": kind_name, "scopes": paged(&scopes, offset, limit)? }))
}

fn counter_samples_query(
    analysis: &mut Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let info = analysis
        .counter_info()
        .map_err(|error| error.to_string())?
        .clone();
    let samples = analysis
        .counter_samples()
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "counter_image": info,
        "samples": paged(samples, offset, limit)?,
    }))
}

fn timeline_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let min_gap_ns = integer(query, "min_gap_ns", 1000)? as u64;
    let max_gaps = integer(query, "max_gaps", 20)?.clamp(1, MAX_PAGE);
    let mut timeline = analysis.timeline(TimelineOptions { min_gap_ns });
    for lane in &mut timeline.lanes {
        lane.gaps
            .sort_by_key(|gap| std::cmp::Reverse(gap.duration_ns));
        lane.gaps.truncate(max_gaps);
    }
    timeline
        .global_gaps
        .sort_by_key(|gap| std::cmp::Reverse(gap.duration_ns));
    timeline.global_gaps.truncate(max_gaps);
    serde_json::to_value(timeline).map_err(|error| error.to_string())
}

fn action_state_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let pattern = regex(query, "pattern")?;
    let kind = call_kind(query.get("kind").and_then(Value::as_str))?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let states = analysis
        .action_states()
        .into_iter()
        .filter(|state| kind.is_none_or(|kind| state.kind == kind))
        .filter(|state| {
            pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(&state.name))
        })
        .collect::<Vec<_>>();
    paged(&states, offset, limit)
}

fn metric_discovery_query(
    analysis: &mut Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    if let Some(metric) = string(query, "metric") {
        return analysis
            .describe_metric(metric)
            .map(|descriptor| json!({ "metric": descriptor }))
            .map_err(|error| error.to_string());
    }
    let pattern = regex(query, "pattern")?;
    let kind = metric_kind(query.get("kind").and_then(Value::as_str))?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let catalog = analysis
        .metric_catalog()
        .map_err(|error| error.to_string())?;
    let metrics = catalog
        .metrics
        .into_iter()
        .filter(|metric| kind.is_none_or(|kind| metric.kind == kind))
        .filter(|metric| {
            pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(&metric.name))
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "chip_name": catalog.chip_name,
        "supported_submetrics": catalog.supported_submetrics,
        "metrics": paged(&metrics, offset, limit)?,
    }))
}

fn metric_evaluation_query(
    analysis: &mut Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let scopes = optional_string_array(query, "scopes")?;
    let include_samples = boolean(query, "include_samples", false)?;
    if query.contains_key("scopes") && (scopes.is_empty() || scopes.len() > MAX_SCOPES) {
        return Err(format!(
            "scopes requires between 1 and {MAX_SCOPES} scope IDs"
        ));
    }
    if !scopes.is_empty() && (query.contains_key("scope") || include_samples) {
        return Err("scopes cannot be combined with scope or include_samples; request samples for one scope".into());
    }
    let exact = optional_string_array(query, "metrics")?;
    let patterns = optional_string_array(query, "patterns")?;
    if exact.is_empty() && patterns.is_empty() {
        return Err("metric_evaluation requires metrics, patterns, or both".into());
    }
    if exact.len() > MAX_EVALUATED_METRICS || patterns.len() > MAX_METRIC_PATTERNS {
        return Err(format!(
            "metric_evaluation accepts at most {MAX_EVALUATED_METRICS} metrics and {MAX_METRIC_PATTERNS} patterns"
        ));
    }
    let compiled = patterns
        .iter()
        .map(|pattern| {
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|error| error.to_string())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    let mut names = exact
        .into_iter()
        .filter(|name| seen.insert(name.clone()))
        .collect::<Vec<_>>();
    let mut matching_bases = 0;
    let mut collected_matches = 0;
    if !compiled.is_empty() {
        let catalog = analysis
            .metric_catalog()
            .map_err(|error| error.to_string())?;
        let bases = catalog
            .metrics
            .into_iter()
            .filter(|metric| {
                compiled
                    .iter()
                    .any(|pattern| pattern.is_match(&metric.name))
            })
            .collect::<Vec<_>>();
        matching_bases = bases.len();
        let scan = analysis
            .scan_metrics(&bases, 0, None)
            .map_err(|error| error.to_string())?;
        for metric in scan
            .metrics
            .into_iter()
            .filter(|metric| metric.valid_samples > 0)
        {
            collected_matches += 1;
            if seen.insert(metric.metric_name.clone()) {
                names.push(metric.metric_name);
            }
        }
    }
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 32)?.clamp(1, MAX_EVALUATED_METRICS);
    let page_start = offset.min(names.len());
    let page_stop = names.len().min(page_start.saturating_add(limit));
    let selected = names[page_start..page_stop].to_vec();
    let nvtx_offset_ns = query.get("nvtx_offset_ns").and_then(Value::as_i64);
    let nvtx_residual_ns = query.get("nvtx_residual_ns").and_then(Value::as_u64);
    if !scopes.is_empty() {
        let mut resolved = Vec::with_capacity(scopes.len());
        for name in &scopes {
            let scope = if let Some(offset) = nvtx_offset_ns
                && name.starts_with("nvtx:")
            {
                analysis.scope_for_nvtx(name, offset, nvtx_residual_ns)
            } else {
                analysis.parse_scope(name)
            }
            .map_err(|error| error.to_string())?;
            resolved.push(scope);
        }
        let report = analysis
            .aggregate_scope_metrics(&resolved, &selected)
            .map_err(|error| error.to_string())?;
        return Ok(json!({
            "selector": { "matching_bases": matching_bases, "collected_matches": collected_matches },
            "aggregation": report,
            "page": page(page_start, page_stop, names.len()),
        }));
    }
    if selected.is_empty() {
        return Ok(json!({
            "selector": {
                "matching_bases": matching_bases,
                "collected_matches": collected_matches,
            },
            "metrics": [],
            "summary": {},
            "page": page(page_start, page_stop, names.len()),
        }));
    }
    let scope_name = string(query, "scope").unwrap_or("capture");
    let scope = if let Some(offset) = nvtx_offset_ns
        && scope_name.starts_with("nvtx:")
    {
        analysis.scope_for_nvtx(scope_name, offset, nvtx_residual_ns)
    } else {
        analysis.parse_scope(scope_name)
    }
    .map_err(|error| error.to_string())?;
    let report = analysis
        .evaluate_scope(&scope, &selected)
        .map_err(|error| error.to_string())?;
    let sample_offset = integer(query, "sample_offset", 0)?;
    let sample_limit = integer(query, "sample_limit", 50)?.clamp(1, MAX_PAGE);
    let mut value = json!({
        "selector": {
            "matching_bases": matching_bases,
            "collected_matches": collected_matches,
        },
        "scope": report.scope,
        "metrics": report.metrics,
        "summary": report.summary,
        "sample_count": report.samples.len(),
        "page": page(page_start, page_stop, names.len()),
    });
    if include_samples {
        value["samples"] = paged(&report.samples, sample_offset, sample_limit)?;
    }
    Ok(value)
}

fn scope_evidence_query(
    analysis: &mut Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let scope_name = required_string(query, "scope")?;
    let nvtx_offset_ns = query.get("nvtx_offset_ns").and_then(Value::as_i64);
    let nvtx_residual_ns = query.get("nvtx_residual_ns").and_then(Value::as_u64);
    let scope = resolve_scope(analysis, scope_name, nvtx_offset_ns, nvtx_residual_ns)?;
    let action_limit = integer(query, "action_limit", 20)?.clamp(1, MAX_PAGE);
    let mut metric_query = query.clone();
    metric_query.insert("scope".into(), json!(scope_name));
    let metrics = metric_evaluation_query(analysis, &metric_query)?;
    let calls = analysis
        .inspect_scope(&scope, false, 0, action_limit)
        .map_err(|error| error.to_string())?;
    let actions = action_states_in_scope(analysis, &scope, action_limit);
    let resolved_scope: Scope =
        serde_json::from_value(metrics.get("scope").cloned().unwrap_or(Value::Null))
            .map_err(|error| format!("resolved scope: {error}"))?;
    let sample_start = resolved_scope.sample_start;
    let sample_stop = resolved_scope.sample_stop;
    let precision = resolved_scope.precision.clone();
    let warnings = resolved_scope.warnings.clone();
    Ok(json!({
        "scope": resolved_scope,
        "attribution": {
            "sample_start": sample_start,
            "sample_stop": sample_stop,
            "precision": precision,
            "warnings": warnings,
            "bucket_shared_rule": "bucket_shared timing and metrics apply to the whole bucket, not each enclosed call",
        },
        "metrics": metrics,
        "calls": calls,
        "actions": actions,
    }))
}

fn resolve_scope(
    analysis: &mut Analysis,
    name: &str,
    nvtx_offset_ns: Option<i64>,
    nvtx_residual_ns: Option<u64>,
) -> std::result::Result<Scope, String> {
    if let Some(offset) = nvtx_offset_ns
        && name.starts_with("nvtx:")
    {
        analysis
            .scope_for_nvtx(name, offset, nvtx_residual_ns)
            .map_err(|error| error.to_string())
    } else {
        analysis
            .parse_scope(name)
            .map_err(|error| error.to_string())
    }
}

fn action_states_in_scope(analysis: &Analysis, scope: &Scope, limit: usize) -> Vec<ActionState> {
    let indices: BTreeSet<usize> =
        if let Some((start, stop)) = scope.call_start.zip(scope.call_stop) {
            (start..stop).collect()
        } else if let Some((start, end)) = scope.start_ns.zip(scope.end_ns) {
            analysis
                .timing_buckets()
                .iter()
                .filter(|bucket| {
                    bucket.interval().is_some_and(|(bucket_start, bucket_end)| {
                        bucket_start < end && bucket_end > start
                    })
                })
                .flat_map(|bucket| bucket.first_global_call_index..bucket.next_global_call_index)
                .collect()
        } else {
            BTreeSet::new()
        };
    analysis
        .action_states()
        .into_iter()
        .filter(|state| indices.contains(&state.global_index))
        .take(limit)
        .collect()
}

fn frame_series_query(
    analysis: &mut Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let kind = string(query, "kind");
    let frames: Vec<_> = analysis
        .frames()
        .iter()
        .filter(|frame| kind.is_none_or(|kind| frame.kind == kind))
        .cloned()
        .collect();
    if frames.is_empty() {
        return Ok(json!({
            "frame_kind": kind,
            "frames": paged(&Vec::<Value>::new(), 0, 50)?,
            "unavailable": "no matching frames were captured",
        }));
    }
    let ids: Vec<_> = frames.iter().map(|frame| frame.id.clone()).collect();
    let mut metric_query = query.clone();
    metric_query.insert("scopes".into(), json!(ids));
    metric_query.insert("offset".into(), json!(0));
    metric_query.insert("limit".into(), json!(MAX_EVALUATED_METRICS));
    let metrics = metric_evaluation_query(analysis, &metric_query)?;
    let aggregation = metrics.get("aggregation").cloned().unwrap_or(Value::Null);
    let summaries = aggregation
        .get("scopes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let items = frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            let gap = index
                .checked_sub(1)
                .map(|previous| frame.start_ns.saturating_sub(frames[previous].end_ns));
            let summary = summaries
                .get(index)
                .and_then(|summary| summary.get("summary"))
                .cloned()
                .unwrap_or(Value::Null);
            json!({
                "index": index,
                "id": frame.id,
                "kind": frame.kind,
                "frame_index": frame.index,
                "start_ns": frame.start_ns,
                "end_ns": frame.end_ns,
                "duration_ns": frame.duration_ns,
                "gap_since_previous_ns": gap,
                "metrics": summary,
            })
        })
        .collect::<Vec<_>>();
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let timeline = analysis.timeline(TimelineOptions { min_gap_ns: 1000 });
    Ok(json!({
        "frame_kind": kind,
        "frames": paged(&items, offset, limit)?,
        "metric_names": aggregation.get("metrics"),
        "metric_page": metrics.get("page"),
        "scope_count": aggregation.get("scope_count"),
        "evaluated_scope_count": aggregation.get("evaluated_scope_count"),
        "sample_start": aggregation.get("sample_start"),
        "sample_stop": aggregation.get("sample_stop"),
        "frame_summary": timeline.frame_summary,
    }))
}

fn scope_ranking_query(
    analysis: &mut Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let kind = scope_kind(required_string(query, "kind")?)?;
    let pattern = regex(query, "pattern")?;
    let metric = required_string(query, "metric")?;
    let statistic = MetricStatistic::parse(string(query, "statistic").unwrap_or("mean"))
        .map_err(|error| error.to_string())?;
    let descending = boolean(query, "descending", true)?;
    let top = integer(query, "top", DEFAULT_TOP)?.clamp(1, MAX_PAGE);
    let nvtx_offset_ns = query.get("nvtx_offset_ns").and_then(Value::as_i64);
    let nvtx_residual_ns = query.get("nvtx_residual_ns").and_then(Value::as_u64);
    let scopes = if kind == ScopeKind::NvtxRange
        && let Some(offset) = nvtx_offset_ns
    {
        analysis
            .nvtx_ranges()
            .iter()
            .map(|range| {
                analysis
                    .scope_for_nvtx(&range.id, offset, nvtx_residual_ns)
                    .map_err(|error| error.to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
    } else {
        analysis.scopes(kind).map_err(|error| error.to_string())?
    };
    let scopes = scopes
        .into_iter()
        .filter(|scope| {
            pattern
                .as_ref()
                .is_none_or(|pattern| pattern.is_match(&scope.id) || pattern.is_match(&scope.label))
        })
        .collect::<Vec<_>>();
    analysis
        .rank_scopes(&scopes, metric, statistic, descending, top)
        .map_err(|error| error.to_string())
        .and_then(|report| serde_json::to_value(report).map_err(|error| error.to_string()))
}

fn trace_schema_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let path = string(query, "path").unwrap_or("");
    Ok(json!({
        "path": path,
        "fields": analysis.document().schema(path).map_err(|error| error.to_string())?,
    }))
}

fn trace_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let path = string(query, "path").unwrap_or("");
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let max_depth = integer(query, "max_depth", 5)?.clamp(1, 12);
    analysis
        .document()
        .query(
            path,
            QueryOptions {
                offset,
                limit,
                max_depth,
            },
        )
        .map_err(|error| error.to_string())
}

fn artifact_inventory_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let pattern = regex(query, "pattern")?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let fields = analysis
        .document()
        .byte_fields()
        .into_iter()
        .filter(|field| {
            pattern.as_ref().is_none_or(|pattern| {
                pattern.is_match(&field.path) || pattern.is_match(&field.message_type)
            })
        })
        .collect::<Vec<_>>();
    paged(&fields, offset, limit)
}

fn artifact_read_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let path = required_string(query, "path")?;
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 4096)?.clamp(1, MAX_ARTIFACT_READ);
    let data = analysis
        .document()
        .extract_bytes(path)
        .map_err(|error| error.to_string())?;
    let start = offset.min(data.len());
    let stop = data.len().min(start.saturating_add(limit));
    Ok(json!({
        "path": path,
        "encoding": "hex",
        "data": hex(&data[start..stop]),
        "page": page(start, stop, data.len()),
    }))
}

fn shader_catalog_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<ShaderCatalog, String> {
    let document = analysis.document();
    let keystream = query
        .get("keystream")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let known = query
        .get("known_plaintext")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let (key, source) = if let Some(path) = known {
        recover_keystream(document, &path).map_err(|error| error.to_string())?
    } else {
        load_keystream(keystream.as_deref()).map_err(|error| error.to_string())?
    };
    ShaderCatalog::open(document, &key, &source).map_err(|error| error.to_string())
}

fn shader_inventory_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let catalog = shader_catalog_query(analysis, query)?;
    let pattern = regex(query, "pattern")?;
    let device = integer(query, "device", usize::MAX)?;
    let device = (device != usize::MAX).then_some(device);
    let offset = integer(query, "offset", 0)?;
    let limit = integer(query, "limit", 50)?.clamp(1, MAX_PAGE);
    let shaders = catalog
        .shaders()
        .filter(|shader| device.is_none_or(|value| shader.device_index == value))
        .filter(|shader| {
            pattern.as_ref().is_none_or(|pattern| {
                [
                    shader.name.as_str(),
                    shader.entry_point.as_deref().unwrap_or(""),
                    shader.source_file.as_deref().unwrap_or(""),
                    shader.stage.as_str(),
                    shader.shader_type.as_str(),
                ]
                .iter()
                .any(|value| pattern.is_match(value))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    Ok(json!({
        "keystream": {
            "bytes": catalog.keystream_bytes,
            "source": catalog.keystream_source,
        },
        "devices": catalog.devices.iter().map(|device| json!({
            "device_index": device.device_index,
            "blob_count": device.blobs.len(),
            "module_count": device.modules.len(),
            "shader_count": device.shaders.len(),
        })).collect::<Vec<_>>(),
        "shaders": paged(&shaders, offset, limit)?,
    }))
}

fn shader_sass_query(
    analysis: &Analysis,
    query: &Map<String, Value>,
) -> std::result::Result<Value, String> {
    let catalog = shader_catalog_query(analysis, query)?;
    let selector = required_string(query, "shader")?;
    let device = integer(query, "device", usize::MAX)?;
    let device = (device != usize::MAX).then_some(device);
    let candidates = catalog
        .shaders()
        .filter(|shader| device.is_none_or(|value| shader.device_index == value))
        .cloned()
        .collect::<Vec<_>>();
    let selected = if let Ok(index) = selector.parse::<usize>() {
        candidates
            .iter()
            .find(|shader| shader.index == index)
            .cloned()
            .ok_or_else(|| format!("shader index {index} is out of range"))?
    } else {
        let pattern = RegexBuilder::new(selector)
            .case_insensitive(true)
            .build()
            .map_err(|error| error.to_string())?;
        let matches = candidates
            .iter()
            .filter(|shader| {
                pattern.is_match(&shader.name)
                    || shader
                        .entry_point
                        .as_deref()
                        .is_some_and(|value| pattern.is_match(value))
                    || pattern.is_match(&shader.stage)
                    || shader
                        .source_file
                        .as_deref()
                        .is_some_and(|value| pattern.is_match(value))
            })
            .cloned()
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [shader] => shader.clone(),
            [] => return Err(format!("no shader matched {selector:?}")),
            _ => {
                return Err(format!(
                    "{selector:?} matched {} shaders; use an index or narrower pattern",
                    matches.len()
                ));
            }
        }
    };
    let cubin = catalog
        .cubin(selected.device_index, selected.index)
        .map_err(|error| error.to_string())?;
    if !cubin.starts_with(b"\x7fELF") {
        return Err(format!(
            "shader {} ({}) has no ELF/cubin blob",
            selected.index, selected.name
        ));
    }
    let include_disassembly = query
        .get("include_disassembly")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let limit = integer(query, "limit", 4096)?.clamp(1, MAX_ARTIFACT_READ);
    let mut result = json!({
        "keystream": {
            "bytes": catalog.keystream_bytes,
            "source": catalog.keystream_source,
        },
        "shader": selected,
        "cubin": {
            "size": cubin.len(),
            "sha256": crate::shader::sha256_hex(&cubin),
        },
    });
    if include_disassembly {
        let disassembly = disassemble(&cubin, None).map_err(|error| error.to_string())?;
        let truncated = disassembly.text.len() > limit;
        let mut end = limit.min(disassembly.text.len());
        while !disassembly.text.is_char_boundary(end) {
            end -= 1;
        }
        result["sass"] = json!({
            "tool": disassembly.tool,
            "args": disassembly.args,
            "registers": disassembly.registers,
            "registers_hint": disassembly.registers_hint,
            "warnings": disassembly.warnings,
            "truncated": truncated,
            "text": &disassembly.text[..end],
        });
    }
    Ok(result)
}

fn server_info() -> Value {
    json!({ "name": "nsight-gpu-trace", "version": env!("CARGO_PKG_VERSION") })
}

fn tool_catalog() -> Vec<Value> {
    let annotations = json!({ "readOnlyHint": true, "idempotentHint": true });
    vec![
        tool(
            "analyze_capture",
            "Analyze a capture once. Returns a compact triage view and result_id for the complete report. Presets choose views; query_result retrieves omitted evidence without rescanning.",
            analyze_schema(),
            annotations.clone(),
        ),
        tool(
            "compare_captures",
            "Compare baseline and candidate captures: environment comparability, metric deltas with bootstrap intervals, scope deltas, and shader/cubin deltas. Returns evidence only; it does not accept or reject a change.",
            compare_schema(),
            annotations.clone(),
        ),
        tool(
            "query_capture",
            "Compute new evidence in one capture: batch typed queries, aggregate metrics across scopes, or rank scopes server-side. Default view pages /results. Returns result_id; query_result reuses computed evidence.",
            query_capture_schema(),
            annotations.clone(),
        ),
        tool(
            "query_result",
            "Inspect immutable saved evidence without loading a capture or evaluating counters. Filter, sort, project and page before returning data. result_id expires after restart or eviction; rerun the original query if expired.",
            json!({
                "type": "object", "properties": { "result_id": { "type": "string" } },
                "required": ["result_id"], "additionalProperties": false
            }),
            annotations,
        ),
    ]
}

fn analyze_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "capture": { "type": "string", "description": "Path to a completed .ngfx-gputrace capture." },
            "preset": { "enum": ["triage", "metrics", "full"], "default": "triage", "description": "Output view only; complete evidence is always saved. An explicit view overrides the preset." },
            "scope_pattern": { "type": "string", "description": "Case-insensitive regex matched against fallback region IDs and labels." },
            "metric_patterns": {
                "type": "array",
                "items": { "type": "string" },
                "maxItems": MAX_METRIC_PATTERNS,
                "description": "Regex selectors evaluated directly for matching collected canonical metrics."
            },
            "metrics": {
                "type": "array",
                "items": { "type": "string" },
                "maxItems": MAX_EXACT_METRICS,
                "description": "Exact PerfWorks metric names to include with automatic representatives."
            },
            "top": { "type": "integer", "minimum": 1, "maximum": MAX_TOP, "default": DEFAULT_TOP }
        },
        "required": ["capture"],
        "additionalProperties": false,
    })
}

fn compare_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "baseline": { "type": "string", "description": "Path to the baseline .ngfx-gputrace capture." },
            "candidate": { "type": "string", "description": "Path to the candidate .ngfx-gputrace capture." },
            "top": { "type": "integer", "minimum": 1, "maximum": MAX_TOP, "default": DEFAULT_TOP },
            "scope_kind": scope_kind_schema(),
            "scope_pattern": { "type": "string", "description": "Case-insensitive regex matched against scope IDs and labels." },
            "metrics": {
                "type": "array", "items": { "type": "string" }, "maxItems": MAX_EVALUATED_METRICS,
                "description": "Exact metrics used for per-scope deltas."
            },
            "include_shaders": { "type": "boolean", "default": true }
        },
        "required": ["baseline", "candidate"],
        "additionalProperties": false,
    })
}

fn query_capture_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "capture": { "type": "string", "description": "Path to a completed .ngfx-gputrace capture." },
            "queries": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_QUERIES,
                "items": { "oneOf": query_schemas() }
            }
        },
        "required": ["capture", "queries"],
        "additionalProperties": false,
    })
}

fn query_schemas() -> Vec<Value> {
    vec![
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "container_info" },
                "section_index": { "type": "integer", "minimum": 0 },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "calls" },
                "kind": call_kind_schema(), "pattern": { "type": "string" },
                "include_arguments": { "type": "boolean", "default": false },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "timings" },
                "kind": call_kind_schema(), "pattern": { "type": "string" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "scopes" }, "kind": scope_kind_schema(),
                "pattern": { "type": "string" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type", "kind"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "counter_samples" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "capture_quality" }
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "timeline" },
                "min_gap_ns": { "type": "integer", "minimum": 0, "default": 1000 },
                "max_gaps": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": 20 }
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "action_state" },
                "kind": call_kind_schema(),
                "pattern": { "type": "string" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "metric_discovery" },
                "kind": { "type": "string", "enum": ["counter", "ratio", "throughput"] },
                "pattern": { "type": "string" }, "metric": { "type": "string" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "metric_evaluation" },
                "metrics": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_EVALUATED_METRICS },
                "patterns": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_METRIC_PATTERNS },
                "scope": { "type": "string", "default": "capture" },
                "scopes": { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": MAX_SCOPES, "description": "Aggregate several scope IDs in one evaluation. Replaces scope; excludes include_samples." },
                "nvtx_offset_ns": { "type": "integer", "description": "Caller-supplied NVTX clock shift for nvtx: scopes. The analyzer does not guess this offset." },
                "nvtx_residual_ns": { "type": "integer", "minimum": 0, "description": "Caller-reported residual for the NVTX clock shift." },
                "offset": page_offset_schema(), "limit": { "type": "integer", "minimum": 1, "maximum": MAX_EVALUATED_METRICS, "default": 32 },
                "include_samples": { "type": "boolean", "default": false },
                "sample_offset": page_offset_schema(), "sample_limit": page_limit_schema()
            },
            "required": ["type"],
            "anyOf": [{ "required": ["metrics"] }, { "required": ["patterns"] }],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "scope_evidence" },
                "scope": { "type": "string", "description": "Stable scope ID, capture, calls:A..B, samples:A..B, time:A..B, or relative-time:A..B." },
                "metrics": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_EVALUATED_METRICS },
                "patterns": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_METRIC_PATTERNS },
                "nvtx_offset_ns": { "type": "integer", "description": "Caller-supplied NVTX clock shift for nvtx: scopes." },
                "nvtx_residual_ns": { "type": "integer", "minimum": 0 },
                "include_samples": { "type": "boolean", "default": false },
                "action_limit": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": 20 },
                "sample_offset": page_offset_schema(), "sample_limit": page_limit_schema()
            },
            "required": ["type", "scope"],
            "anyOf": [{ "required": ["metrics"] }, { "required": ["patterns"] }],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "frame_series" },
                "kind": { "type": "string", "enum": ["presented", "application"], "description": "Optional frame kind filter." },
                "metrics": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_EVALUATED_METRICS },
                "patterns": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_METRIC_PATTERNS },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"],
            "anyOf": [{ "required": ["metrics"] }, { "required": ["patterns"] }],
            "additionalProperties": false
        }),
        json!({
            "type": "object", "properties": {
                "type": { "const": "scope_ranking" },
                "kind": scope_kind_schema(), "pattern": { "type": "string" },
                "metric": { "type": "string" },
                "statistic": { "enum": ["mean", "min", "max", "p50", "p95", "sum"], "default": "mean" },
                "descending": { "type": "boolean", "default": true },
                "nvtx_offset_ns": { "type": "integer", "description": "Caller-supplied NVTX clock shift for nvtx_range ranking." },
                "nvtx_residual_ns": { "type": "integer", "minimum": 0 },
                "top": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": DEFAULT_TOP }
            }, "required": ["type", "kind", "metric"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "trace_schema" }, "path": { "type": "string", "default": "" }
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "trace_query" }, "path": { "type": "string", "default": "" },
                "offset": page_offset_schema(), "limit": page_limit_schema(),
                "max_depth": { "type": "integer", "minimum": 1, "maximum": 12, "default": 5 }
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "artifact_inventory" }, "pattern": { "type": "string" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "artifact_read" }, "path": { "type": "string" },
                "offset": page_offset_schema(),
                "limit": { "type": "integer", "minimum": 1, "maximum": MAX_ARTIFACT_READ, "default": 4096 }
            },
            "required": ["type", "path"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "shader_inventory" },
                "pattern": { "type": "string" },
                "offset": page_offset_schema(), "limit": page_limit_schema()
            },
            "required": ["type"], "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "type": { "const": "shader_sass" },
                "shader": { "type": "string" },
                "device": { "type": "integer", "minimum": 0 },
                "include_disassembly": { "type": "boolean", "default": false },
                "limit": { "type": "integer", "minimum": 1, "maximum": MAX_ARTIFACT_READ, "default": 4096 }
            },
            "required": ["type", "shader"], "additionalProperties": false
        }),
    ]
}

fn page_offset_schema() -> Value {
    json!({ "type": "integer", "minimum": 0, "default": 0 })
}

fn page_limit_schema() -> Value {
    json!({ "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": 50 })
}

fn call_kind_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["draw", "dispatch", "copy", "clear", "sync", "marker", "present", "other"]
    })
}

fn scope_kind_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["debug_group", "nvtx_range", "frame", "action", "timing_bucket"]
    })
}

fn tool(name: &str, description: &str, mut input_schema: Value, annotations: Value) -> Value {
    output::add_schema(&mut input_schema, name == "query_result");
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": annotations,
    })
}

fn tool_success(id: Value, value: Value, modern: bool) -> Value {
    let mut result = if modern {
        json!({ "structuredContent": value, "isError": false })
    } else {
        let text = serde_json::to_string(&value).unwrap_or_else(|_| "null".into());
        json!({ "content": [{ "type": "text", "text": text }], "isError": false })
    };
    if modern {
        result["resultType"] = json!("complete");
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn tool_error(id: Value, message: &str, modern: bool) -> Value {
    let mut result = if modern {
        json!({ "structuredContent": { "error": message }, "isError": true })
    } else {
        json!({ "content": [{ "type": "text", "text": message }], "isError": true })
    };
    if modern {
        result["resultType"] = json!("complete");
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn bounded_tool_error(id: Value, message: &str, modern: bool, budget: usize) -> Value {
    let mut message = message.to_owned();
    let mut truncated = false;
    loop {
        let display = if truncated {
            format!("{message} [error truncated]")
        } else {
            message.clone()
        };
        let response = tool_error(id.clone(), &display, modern);
        if serialized_len(&response) <= budget || message.is_empty() {
            return response;
        }
        let stop = message
            .char_indices()
            .nth(message.chars().count() / 2)
            .map_or(0, |(index, _)| index);
        message.truncate(stop);
        truncated = true;
    }
}
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

fn required_string<'a>(
    arguments: &'a Map<String, Value>,
    name: &str,
) -> std::result::Result<&'a str, String> {
    string(arguments, name).ok_or_else(|| format!("{name} must be a string"))
}

fn string<'a>(arguments: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    arguments.get(name).and_then(Value::as_str)
}

fn boolean(
    arguments: &Map<String, Value>,
    name: &str,
    default: bool,
) -> std::result::Result<bool, String> {
    match arguments.get(name) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("{name} must be a boolean")),
    }
}

fn integer(
    arguments: &Map<String, Value>,
    name: &str,
    default: usize,
) -> std::result::Result<usize, String> {
    optional_integer(arguments, name).map(|value| value.unwrap_or(default))
}

fn optional_integer(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<Option<usize>, String> {
    match arguments.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| format!("{name} must be a non-negative integer")),
    }
}

fn optional_string_array(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<Vec<String>, String> {
    let Some(value) = arguments.get(name) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| format!("{name} must be an array of strings"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} must contain only strings"))
        })
        .collect()
}

fn regex(arguments: &Map<String, Value>, name: &str) -> std::result::Result<Option<Regex>, String> {
    string(arguments, name)
        .map(|pattern| RegexBuilder::new(pattern).case_insensitive(true).build())
        .transpose()
        .map_err(|error| error.to_string())
}

fn metric_kind(value: Option<&str>) -> std::result::Result<Option<MetricKind>, String> {
    value
        .map(|value| match value {
            "counter" => Ok(MetricKind::Counter),
            "ratio" => Ok(MetricKind::Ratio),
            "throughput" => Ok(MetricKind::Throughput),
            _ => Err(format!("unsupported metric kind {value:?}")),
        })
        .transpose()
}

fn metric_kind_name(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Counter => "counter",
        MetricKind::Ratio => "ratio",
        MetricKind::Throughput => "throughput",
    }
}

fn scope_kind(value: &str) -> std::result::Result<ScopeKind, String> {
    match value {
        "debug_group" => Ok(ScopeKind::DebugGroup),
        "nvtx_range" => Ok(ScopeKind::NvtxRange),
        "frame" => Ok(ScopeKind::Frame),
        "action" => Ok(ScopeKind::Action),
        "timing_bucket" => Ok(ScopeKind::TimingBucket),
        _ => Err(format!("unsupported scope kind {value:?}")),
    }
}

fn call_kind(value: Option<&str>) -> std::result::Result<Option<CallKind>, String> {
    value
        .map(|value| match value {
            "draw" => Ok(CallKind::Draw),
            "dispatch" => Ok(CallKind::Dispatch),
            "copy" => Ok(CallKind::Copy),
            "clear" => Ok(CallKind::Clear),
            "sync" => Ok(CallKind::Sync),
            "marker" => Ok(CallKind::Marker),
            "present" => Ok(CallKind::Present),
            "other" => Ok(CallKind::Other),
            _ => Err(format!("unsupported call kind {value:?}")),
        })
        .transpose()
}

fn histogram<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeMap<T, usize> {
    let mut result = BTreeMap::new();
    for value in values {
        *result.entry(value).or_default() += 1;
    }
    result
}

fn paged<T: Serialize>(
    items: &[T],
    offset: usize,
    limit: usize,
) -> std::result::Result<Value, String> {
    let offset = offset.min(items.len());
    let stop = items.len().min(offset.saturating_add(limit));
    Ok(json!({
        "items": serde_json::to_value(&items[offset..stop]).map_err(|error| error.to_string())?,
        "page": page(offset, stop, items.len()),
    }))
}

fn page(offset: usize, stop: usize, total: usize) -> Value {
    json!({
        "offset": offset,
        "returned": stop - offset,
        "total": total,
        "next_offset": (stop < total).then_some(stop),
    })
}

fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::container::{SUPPORTED_VERSION, WRPV_MAGIC};

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn container_only_query(path: &std::path::Path) -> Map<String, Value> {
        object(json!({
            "capture": path,
            "queries": [{ "type": "container_info" }],
        }))
    }

    fn empty_container() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&WRPV_MAGIC).unwrap();
        file.write_all(&SUPPORTED_VERSION.to_le_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn advertises_capture_queries_and_saved_result_views() {
        let tools = tool_catalog();
        assert!(serialized_len(&json!(tools)) < 14 * 1024);
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "analyze_capture",
                "compare_captures",
                "query_capture",
                "query_result"
            ]
        );
        for tool in tools {
            let required = match tool["name"].as_str().unwrap() {
                "query_result" => "result_id",
                "compare_captures" => "baseline",
                _ => "capture",
            };
            assert!(
                tool["inputSchema"]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == required)
            );
        }
    }

    #[test]
    fn missing_capture_is_a_tool_error() {
        let server = McpServer::new(AnalysisOptions::default());
        let response = server
            .handle(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "analyze_capture", "arguments": {} }
            }))
            .unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("capture")
        );
    }

    #[test]
    fn aba_interleaving_cannot_replace_a_capture() {
        let a = empty_container();
        let b = empty_container();
        let server = McpServer::new(AnalysisOptions::default());
        let first_a = server
            .call_tool("query_capture", &container_only_query(a.path()))
            .unwrap();
        let middle_b = server
            .call_tool("query_capture", &container_only_query(b.path()))
            .unwrap();
        let last_a = server
            .call_tool("query_capture", &container_only_query(a.path()))
            .unwrap();

        assert_eq!(first_a["capture"], last_a["capture"]);
        assert_ne!(first_a["capture"], middle_b["capture"]);
        assert_eq!(
            first_a["results"][0]["data"]["path"],
            last_a["results"][0]["data"]["path"]
        );
    }

    #[test]
    fn modern_and_legacy_results_each_encode_payload_once() {
        let payload = json!({ "report": "x".repeat(33_879) });
        let modern = tool_success(json!(1), payload.clone(), true);
        assert!(modern["result"].get("content").is_none());
        assert_eq!(modern["result"]["structuredContent"], payload);
        assert!(serde_json::to_vec(&modern).unwrap().len() < 35_000);

        let legacy = tool_success(json!(1), payload, false);
        assert!(legacy["result"].get("structuredContent").is_none());
        assert!(legacy["result"]["content"][0]["text"].is_string());
        assert!(serde_json::to_vec(&legacy).unwrap().len() < 35_000);
    }

    #[test]
    fn saved_results_survive_interleaving_and_capture_removal() {
        let a = empty_container();
        let b = empty_container();
        let server = McpServer::new(AnalysisOptions::default());
        let first = server
            .respond(
                json!(1),
                "query_capture",
                &container_only_query(a.path()),
                true,
            )
            .unwrap();
        let first = &first["result"]["structuredContent"];
        server
            .respond(
                json!(2),
                "query_capture",
                &container_only_query(b.path()),
                true,
            )
            .unwrap();
        let mut invalid_view = container_only_query(a.path());
        invalid_view.insert("view".into(), json!({ "path": "/absent" }));
        let error = server
            .respond(json!(2), "query_capture", &invalid_view, true)
            .unwrap_err();
        assert!(error.contains(first["result_id"].as_str().unwrap()));
        let expected = json!(a.path());
        a.close().unwrap();
        let saved = server
            .respond(
                json!(3),
                "query_result",
                &object(json!({
                    "result_id": first["result_id"], "view": { "path": "/capture" }
                })),
                true,
            )
            .unwrap();
        assert_eq!(saved["result"]["structuredContent"]["data"], expected);
        assert_eq!(
            saved["result"]["structuredContent"]["result_id"],
            first["result_id"]
        );
        let error = server
            .respond(
                json!(4),
                "query_result",
                &object(json!({ "result_id": "missing" })),
                true,
            )
            .unwrap_err();
        assert!(error.contains("expired"));
        for modern in [true, false] {
            let response = bounded_tool_error(json!(1), &"\"\n🦀".repeat(10_000), modern, 1024);
            assert!(serialized_len(&response) <= 1024);
            assert_eq!(response["result"]["isError"], true);
        }
        let response = server.handle(&json!({
            "jsonrpc": "2.0", "id": "x".repeat(2000), "method": "tools/call",
            "params": { "name": "query_result", "arguments": {"result_id": "missing", "max_bytes": 1024} }
        })).unwrap();
        assert!(serialized_len(&response) <= 1024);
        assert_eq!(response["error"]["code"], -32600);
    }

    #[test]
    fn triage_presets_and_query_dispatch_preserve_unavailable_evidence() {
        use prost::Message;
        use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};

        // A minimal synthetic schema and empty trace exercise the whole pipeline
        // without an Nsight installation, proprietary fixtures, or a GPU.
        let descriptor = FileDescriptorProto {
            name: Some("WarpViz.proto".into()),
            package: Some("NV.WarpViz".into()),
            syntax: Some("proto3".into()),
            message_type: vec![
                DescriptorProto {
                    name: Some("PbTraceData".into()),
                    field: [("devices", 1, 3), ("NvtxData", 2, 1)]
                        .into_iter()
                        .map(|(name, number, label)| FieldDescriptorProto {
                            name: Some(name.into()),
                            number: Some(number),
                            label: Some(label),
                            r#type: Some(11),
                            type_name: Some(".NV.WarpViz.Empty".into()),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("Empty".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut schema = NamedTempFile::new().unwrap();
        schema.write_all(&descriptor.encode_to_vec()).unwrap();
        let mut capture = empty_container();
        capture.write_all(&0x1234_u16.to_le_bytes()).unwrap();
        capture.write_all(&1_u16.to_le_bytes()).unwrap();
        capture.write_all(&[0; 20]).unwrap();
        capture.flush().unwrap();
        let server = McpServer::new(AnalysisOptions {
            schema_binary: Some(schema.path().into()),
            nvperf_library: Some(schema.path().with_extension("absent")),
        });
        for preset in ["triage", "metrics", "full"] {
            let response = server
                .respond(
                    json!(1),
                    "analyze_capture",
                    &object(json!({
                        "capture": capture.path(), "preset": preset
                    })),
                    true,
                )
                .unwrap();
            assert!(serialized_len(&response) <= output::DEFAULT_BYTES);
            let result = &response["result"]["structuredContent"];
            let original = server
                .results
                .lock()
                .unwrap()
                .get(result["result_id"].as_str().unwrap())
                .unwrap();
            assert!(original["counter_coverage"].is_null());
            assert!(original["representative_metrics"]["capture_summary"].is_null());
            assert!(
                !original["manifest"]["unavailable_evidence"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(original["regions"]["kind"], "none");
        }
        let response = server
            .respond(
                json!(2),
                "query_capture",
                &object(json!({
                    "capture": capture.path(), "queries": [
                        {"type": "scopes", "kind": "debug_group"},
                        {"type": "scope_ranking", "kind": "debug_group", "metric": "test"}
                    ]
                })),
                true,
            )
            .unwrap();
        assert_eq!(response["result"]["structuredContent"]["page"]["total"], 2);
        let error = server
            .respond(
                json!(3),
                "query_capture",
                &object(json!({
                    "capture": capture.path(), "queries": [{
                        "type": "metric_evaluation", "metrics": ["test"],
                        "scopes": ["capture"], "include_samples": true
                    }]
                })),
                true,
            )
            .unwrap_err();
        assert!(error.contains("include_samples"));
    }

    #[test]
    fn modern_discovery_marks_results_complete() {
        let server = McpServer::new(AnalysisOptions::default());
        let response = server
            .handle(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
            }))
            .unwrap();
        assert_eq!(response["result"]["resultType"], "complete");
    }
}
