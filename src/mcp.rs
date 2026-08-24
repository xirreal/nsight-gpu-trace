//! Stateless, bounded Model Context Protocol tools over the Rust analyzer.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, Write},
    path::PathBuf,
};

use regex::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    Analysis, AnalysisOptions, ApiCall, CallKind, Container, MetricKind, MetricScan,
    MetricStatistics, QueryOptions, Result, Scope, ScopeKind, ScopeMetricSummary, TimingBucket,
    TopDownReport, diagnostics::metric_category, top_down_report,
};

const PROTOCOL_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];
const FALLBACK_PROTOCOL: &str = "2025-06-18";
const INSTRUCTIONS: &str = "Pass a .ngfx-gputrace path to every tool call. Use analyze_capture for one-shot triage and query_capture for bounded follow-up queries. Null means unavailable, never zero. bucket_shared evidence belongs to the whole timing bucket. Treat thresholds as hypotheses and validate changes with a same-settings recapture.";
const DEFAULT_TOP: usize = 8;
const MAX_TOP: usize = 25;
const MAX_QUERIES: usize = 16;
const MAX_PAGE: usize = 100;
const MAX_EXACT_METRICS: usize = 16;
const MAX_METRIC_PATTERNS: usize = 16;
const MAX_SELECTED_METRICS: usize = 48;
const MAX_EVALUATED_METRICS: usize = 64;
const MAX_ARTIFACT_READ: usize = 16 * 1024;
const MAX_ANALYZE_RESULT_BYTES: usize = 52 * 1024;

/// A sequential stdio MCP server with immutable configuration and no capture state.
pub struct McpServer {
    options: AnalysisOptions,
}

impl McpServer {
    pub fn new(options: AnalysisOptions) -> Self {
        Self { options }
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
                return Some(match self.call_tool(name, &arguments) {
                    Ok(value) => tool_success(id, value, modern),
                    Err(error) => tool_error(id, &error, modern),
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
                "stateless": true,
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
            "stateless": true,
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

struct MetricPipeline {
    counter_coverage: Value,
    metric_scan: Value,
    diagnostics: Value,
    selected_metrics: Vec<String>,
    selection: Value,
    capture_summary: BTreeMap<String, MetricStatistics>,
    region_summaries: Vec<ScopeMetricSummary>,
}

fn analyze_capture(
    analysis: &mut Analysis,
    scope_pattern: Option<&Regex>,
    metric_patterns: &[String],
    exact_metrics: &[String],
    top: usize,
) -> std::result::Result<Value, String> {
    let regions = select_regions(analysis, scope_pattern, top)?;
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
    ) = match metric_pipeline {
        Ok(pipeline) => (
            pipeline.counter_coverage,
            pipeline.metric_scan,
            pipeline.diagnostics,
            pipeline.selected_metrics,
            pipeline.selection,
            json!(compact_summary(&pipeline.capture_summary)),
            pipeline.region_summaries,
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
            )
        }
    };

    let region_values = regions
        .scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| {
            region_report(
                analysis,
                region_summaries.get(index).map(|summary| &summary.scope),
                scope,
                region_summaries.get(index).map(|summary| &summary.summary),
            )
        })
        .collect::<Vec<_>>();
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

    let mut result = json!({
        "capture": {
            "path": container.path,
            "wrpv_version": container.version,
            "compressed_bytes": container.file_size,
            "protobuf_type": crate::trace::TRACE_MESSAGE,
            "protobuf_bytes": analysis.document().raw_protobuf().len(),
        },
        "workload": workload,
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
            "returned": region_values.len(),
            "next_offset": (region_values.len() < regions.matching).then_some(region_values.len()),
            "items": region_values,
        },
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
    bound_analyze_result(&mut result);
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
        "categories": categories,
        "top_percent_of_peak": report.top_percent_of_peak,
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
        "min": statistics.min,
        "max": statistics.max,
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
        "metrics": summary.map(compact_summary).unwrap_or_else(|| json!({})),
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
    json!({
        "apis": analysis.api_names(),
        "calls": analysis.calls().len(),
        "actions": analysis.calls().iter().filter(|call| call.kind.is_action()).count(),
        "call_kinds": histogram(analysis.calls().iter().map(|call| call.kind)),
        "leading_calls": names.into_iter().map(|(name, count)| json!({ "name": name, "count": count })).collect::<Vec<_>>(),
        "distinct_call_names": distinct_names,
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
    [
        ("debug_group", ScopeKind::DebugGroup),
        ("nvtx_range", ScopeKind::NvtxRange),
        ("frame", ScopeKind::Frame),
        ("action", ScopeKind::Action),
        ("timing_bucket", ScopeKind::TimingBucket),
    ]
    .into_iter()
    .map(|(name, kind)| {
        analysis
            .scopes(kind)
            .map(|scopes| (name, scopes.len()))
            .map_err(|error| error.to_string())
    })
    .collect()
}

fn bound_analyze_result(result: &mut Value) {
    let original_regions = result["regions"]["items"].as_array().map_or(0, Vec::len);
    while serialized_len(result) > MAX_ANALYZE_RESULT_BYTES {
        let Some(items) = result["regions"]["items"].as_array_mut() else {
            break;
        };
        if items.pop().is_none() {
            break;
        }
    }
    let returned = result["regions"]["items"].as_array().map_or(0, Vec::len);
    if returned < original_regions {
        result["regions"]["returned"] = json!(returned);
        result["regions"]["next_offset"] = json!(returned);
        result["regions"]["truncated_for_response_size"] = json!(true);
    }
    while serialized_len(result) > MAX_ANALYZE_RESULT_BYTES {
        let Some(items) = result["diagnostics"]["top_percent_of_peak"].as_array_mut() else {
            break;
        };
        if items.pop().is_none() {
            break;
        }
    }
    while serialized_len(result) > MAX_ANALYZE_RESULT_BYTES {
        let Some(items) = result["manifest"]["protobuf"]["root_fields"]["items"].as_array_mut()
        else {
            break;
        };
        if items.pop().is_none() {
            break;
        }
    }
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
    "metric_discovery",
    "metric_evaluation",
    "trace_schema",
    "trace_query",
    "artifact_inventory",
    "artifact_read",
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
        "metric_discovery" => metric_discovery_query(analysis, query),
        "metric_evaluation" => metric_evaluation_query(analysis, query),
        "trace_schema" => trace_schema_query(analysis, query),
        "trace_query" => trace_query(analysis, query),
        "artifact_inventory" => artifact_inventory_query(analysis, query),
        "artifact_read" => artifact_read_query(analysis, query),
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
    let mut names = exact;
    let mut seen = names.iter().cloned().collect::<BTreeSet<_>>();
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
    let scope = analysis
        .parse_scope(scope_name)
        .map_err(|error| error.to_string())?;
    let report = analysis
        .evaluate_scope(&scope, &selected)
        .map_err(|error| error.to_string())?;
    let include_samples = boolean(query, "include_samples", false)?;
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
        "null_semantics": "Unavailable/not collected is null, never zero.",
    });
    if include_samples {
        value["samples"] = paged(&report.samples, sample_offset, sample_limit)?;
    }
    Ok(value)
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

fn server_info() -> Value {
    json!({ "name": "nsight-gpu-trace", "version": env!("CARGO_PKG_VERSION") })
}

fn tool_catalog() -> Vec<Value> {
    let annotations = json!({ "readOnlyHint": true, "idempotentHint": true });
    vec![
        tool(
            "analyze_capture",
            "Open one capture for this call and return bounded identity, workload, timing, complete metric-scan diagnostics, representative metrics, fallback regions, and a data manifest.",
            analyze_schema(),
            annotations.clone(),
        ),
        tool(
            "query_capture",
            "Open one capture for this call and execute a bounded batch of typed container, trace, call, timing, scope, counter, metric, or artifact queries.",
            query_capture_schema(),
            annotations,
        ),
    ]
}

fn analyze_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "capture": { "type": "string", "description": "Path to a completed .ngfx-gputrace capture." },
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

fn tool(name: &str, description: &str, input_schema: Value, annotations: Value) -> Value {
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
    fn advertises_only_stateless_tools_and_requires_capture() {
        let tools = tool_catalog();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["analyze_capture", "query_capture"]
        );
        for tool in tools {
            assert!(
                tool["inputSchema"]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == "capture")
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
    fn analysis_result_limiter_keeps_protocol_responses_below_64_kib() {
        let mut report = json!({
            "regions": {
                "items": (0..8).map(|_| json!({ "metrics": "x".repeat(10_000) })).collect::<Vec<_>>(),
                "returned": 8,
                "matching": 8,
            },
            "diagnostics": { "top_percent_of_peak": [] },
            "manifest": { "protobuf": { "root_fields": { "items": [] } } },
        });
        bound_analyze_result(&mut report);

        assert!(serialized_len(&report) <= MAX_ANALYZE_RESULT_BYTES);
        assert_eq!(report["regions"]["truncated_for_response_size"], true);
        assert!(
            serde_json::to_vec(&tool_success(json!(1), report.clone(), true))
                .unwrap()
                .len()
                < 64 * 1024
        );
        assert!(
            serde_json::to_vec(&tool_success(json!(1), report, false))
                .unwrap()
                .len()
                < 64 * 1024
        );
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
