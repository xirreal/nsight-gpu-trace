//! Bounded Model Context Protocol tools over the Rust analyzer.

use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
    path::PathBuf,
};

use regex::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    Analysis, AnalysisOptions, CallKind, MetricKind, MetricStatistic, QueryOptions, Result,
    ScopeKind, top_down_report,
};

const PROTOCOL_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];
const FALLBACK_PROTOCOL: &str = "2025-06-18";
const INSTRUCTIONS: &str = "Open a .ngfx-gputrace with open_capture, then call capture_overview. Use top_down_report for triage, resolve stable IDs with list_scopes, and query exact metrics on exact scopes. Null means unavailable, never zero. bucket_shared evidence belongs to the whole timing bucket. Treat thresholds as hypotheses and validate changes with a same-settings recapture.";

/// A sequential stdio MCP server with one replaceable active capture.
pub struct McpServer {
    options: AnalysisOptions,
    analysis: Option<Analysis>,
}

impl McpServer {
    pub fn new(options: AnalysisOptions) -> Self {
        Self {
            options,
            analysis: None,
        }
    }

    pub fn with_capture(options: AnalysisOptions, trace: PathBuf) -> Result<Self> {
        let mut server = Self::new(options);
        server.open_capture(trace)?;
        Ok(server)
    }

    pub fn open_capture(&mut self, trace: PathBuf) -> Result<()> {
        self.analysis = Some(Analysis::open(trace, self.options.clone())?);
        Ok(())
    }

    /// Handle one JSON-RPC request. Notifications intentionally return no response.
    pub fn handle(&mut self, request: &Value) -> Option<Value> {
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

    pub fn serve(mut self) -> Result<()> {
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

    fn active(&mut self) -> std::result::Result<&mut Analysis, String> {
        self.analysis
            .as_mut()
            .ok_or_else(|| "no active capture; call open_capture first".into())
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        match name {
            "open_capture" => {
                let path = PathBuf::from(required_string(arguments, "path")?);
                self.open_capture(path).map_err(|error| error.to_string())?;
                let analysis = self.active()?;
                Ok(json!({
                    "active_capture": analysis.document().container().path,
                    "apis": analysis.api_names(),
                    "call_count": analysis.calls().len(),
                    "frame_count": analysis.frames().len(),
                    "debug_group_count": analysis.debug_groups().len(),
                    "nvtx_range_count": analysis.nvtx_ranges().len(),
                    "next": "Call capture_overview, optionally with with_counters=true.",
                }))
            }
            "capture_overview" => {
                let with_counters = boolean(arguments, "with_counters", false)?;
                let analysis = self.active()?;
                let mut overview = analysis.overview();
                let byte_fields = analysis.document().byte_fields();
                overview["byte_fields"] = json!({
                    "count": byte_fields.len(),
                    "total_bytes": byte_fields.iter().map(|field| field.size).sum::<usize>(),
                });
                overview["active_capture"] = json!(analysis.document().container().path);
                overview["attribution_rule"] = json!(
                    "bucket_shared timing and metrics apply to the whole bucket, not each enclosed call"
                );
                if with_counters {
                    overview["counter_data"] = serde_json::to_value(
                        analysis.counter_info().map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                }
                Ok(overview)
            }
            "list_metrics" => self.list_metrics(arguments),
            "describe_metric" => {
                let metric = required_string(arguments, "metric")?;
                let value = self
                    .active()?
                    .describe_metric(metric)
                    .map_err(|error| error.to_string())?;
                serde_json::to_value(value).map_err(|error| error.to_string())
            }
            "scan_metrics" => self.scan_metrics(arguments),
            "list_scopes" => self.list_scopes(arguments),
            "inspect_scope" => {
                let scope = string(arguments, "scope").unwrap_or("capture");
                let include_arguments = boolean(arguments, "include_arguments", true)?;
                let offset = integer(arguments, "offset", 0)?;
                let limit = integer(arguments, "limit", 50)?.clamp(1, 200);
                let analysis = self.active()?;
                let scope = analysis
                    .parse_scope(scope)
                    .map_err(|error| error.to_string())?;
                analysis
                    .inspect_scope(&scope, include_arguments, offset, limit)
                    .map_err(|error| error.to_string())
            }
            "query_metrics" => self.query_metrics(arguments),
            "rank_scopes" => self.rank_scopes(arguments),
            "top_down_report" => {
                let top = integer(arguments, "top", 15)?.clamp(1, 100);
                let analysis = self.active()?;
                let capture = analysis.overview();
                let counter_data = analysis
                    .counter_info()
                    .map_err(|error| error.to_string())?
                    .clone();
                let scan = analysis
                    .scan_all_metrics()
                    .map_err(|error| error.to_string())?;
                Ok(json!({
                    "capture": capture,
                    "counter_data": counter_data,
                    "diagnostics": top_down_report(&scan, top),
                }))
            }
            "trace_schema" => {
                let path = string(arguments, "path").unwrap_or("");
                let analysis = self.active()?;
                Ok(json!({
                    "path": path,
                    "fields": analysis.document().schema(path).map_err(|error| error.to_string())?,
                }))
            }
            "trace_query" => {
                let path = string(arguments, "path").unwrap_or("");
                let offset = integer(arguments, "offset", 0)?;
                let limit = integer(arguments, "limit", 50)?.clamp(1, 200);
                let max_depth = integer(arguments, "max_depth", 5)?.clamp(1, 12);
                self.active()?
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
            _ => Err(format!("unknown analysis tool: {name}")),
        }
    }

    fn list_metrics(
        &mut self,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        let regex = regex(arguments, "pattern")?;
        let kind = metric_kind(arguments.get("kind").and_then(Value::as_str))?;
        let offset = integer(arguments, "offset", 0)?;
        let limit = integer(arguments, "limit", 100)?.clamp(1, 200);
        let catalog = self
            .active()?
            .metric_catalog()
            .map_err(|error| error.to_string())?;
        let metrics = catalog
            .metrics
            .into_iter()
            .filter(|metric| kind.is_none_or(|kind| metric.kind == kind))
            .filter(|metric| {
                regex
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(&metric.name))
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "chip_name": catalog.chip_name,
            "supported_submetrics": catalog.supported_submetrics,
            "metrics": paged(&metrics, offset, limit)?,
            "name_rule": "Catalog names are bases; use the supported PerfWorks suffixes to request exact metrics.",
        }))
    }

    fn scan_metrics(
        &mut self,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        let regex = regex(arguments, "pattern")?;
        let kind = metric_kind(arguments.get("kind").and_then(Value::as_str))?;
        let start = integer(arguments, "sample_start", 0)?;
        let stop = optional_integer(arguments, "sample_stop")?;
        let include_unavailable = boolean(arguments, "include_unavailable", false)?;
        let offset = integer(arguments, "offset", 0)?;
        let limit = integer(arguments, "limit", 100)?.clamp(1, 200);
        let analysis = self.active()?;
        let catalog = analysis
            .metric_catalog()
            .map_err(|error| error.to_string())?;
        let selected = catalog
            .metrics
            .into_iter()
            .filter(|metric| kind.is_none_or(|kind| metric.kind == kind))
            .filter(|metric| {
                regex
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(&metric.name))
            })
            .collect::<Vec<_>>();
        let scan = analysis
            .scan_metrics(&selected, start, stop)
            .map_err(|error| error.to_string())?;
        let available = scan
            .metrics
            .iter()
            .filter(|metric| metric.valid_samples > 0)
            .count();
        let metrics = scan
            .metrics
            .into_iter()
            .filter(|metric| include_unavailable || metric.valid_samples > 0)
            .collect::<Vec<_>>();
        Ok(json!({
            "chip_name": scan.chip_name,
            "sample_start": scan.sample_start,
            "sample_stop": scan.sample_stop,
            "selected_samples": scan.selected_samples,
            "selected_metric_bases": selected.len(),
            "available_metric_bases": available,
            "unavailable_metric_bases": selected.len() - available,
            "metrics": paged(&metrics, offset, limit)?,
            "null_semantics": "Unavailable/not collected is omitted by default and never means zero.",
        }))
    }

    fn list_scopes(
        &mut self,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        let kind = scope_kind(required_string(arguments, "kind")?)?;
        let regex = regex(arguments, "pattern")?;
        let call_kind = call_kind(arguments.get("call_kind").and_then(Value::as_str))?;
        let parent_id = string(arguments, "parent_id");
        let offset = integer(arguments, "offset", 0)?;
        let limit = integer(arguments, "limit", 50)?.clamp(1, 200);
        let analysis = self.active()?;
        let scopes = analysis.scopes(kind).map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        for scope in scopes {
            if regex
                .as_ref()
                .is_some_and(|regex| !regex.is_match(&scope.label))
            {
                continue;
            }
            let mut record = serde_json::to_value(&scope)
                .map_err(|error| error.to_string())?
                .as_object()
                .cloned()
                .unwrap();
            if kind == ScopeKind::DebugGroup
                && let Some(group) = analysis
                    .debug_groups()
                    .iter()
                    .find(|group| group.id == scope.id)
            {
                if parent_id.is_some() && group.parent_id.as_deref() != parent_id {
                    continue;
                }
                record.insert("depth".into(), json!(group.depth));
                record.insert("parent_id".into(), json!(group.parent_id));
                record.insert("closed".into(), json!(group.closed));
            }
            if let Some((start, stop)) = scope.call_start.zip(scope.call_stop) {
                let calls = &analysis.calls()[start..stop];
                if call_kind.is_some_and(|kind| !calls.iter().any(|call| call.kind == kind)) {
                    continue;
                }
                let mut kinds = BTreeMap::new();
                for call in calls {
                    *kinds
                        .entry(format!("{:?}", call.kind).to_lowercase())
                        .or_insert(0usize) += 1;
                }
                record.insert("call_count".into(), json!(calls.len()));
                record.insert("call_kinds".into(), json!(kinds));
            }
            records.push(Value::Object(record));
        }
        Ok(json!({
            "kind": arguments["kind"],
            "scopes": paged(&records, offset, limit)?,
        }))
    }

    fn query_metrics(
        &mut self,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        let metrics = string_array(arguments, "metrics")?;
        if metrics.is_empty() || metrics.len() > 64 {
            return Err("query_metrics requires between 1 and 64 metric names".into());
        }
        let scope = string(arguments, "scope").unwrap_or("capture");
        let include_series = boolean(arguments, "include_series", false)?;
        let offset = integer(arguments, "offset", 0)?;
        let limit = integer(arguments, "limit", 100)?.clamp(1, 200);
        let analysis = self.active()?;
        let scope = analysis
            .parse_scope(scope)
            .map_err(|error| error.to_string())?;
        let report = analysis
            .evaluate_scope(&scope, &metrics)
            .map_err(|error| error.to_string())?;
        let mut value = json!({
            "scope": report.scope,
            "metrics": report.metrics,
            "summary": report.summary,
            "sample_count": report.samples.len(),
            "null_semantics": "Unavailable/not collected is null, never zero.",
        });
        if include_series {
            value["samples"] = paged(&report.samples, offset, limit)?;
        }
        Ok(value)
    }

    fn rank_scopes(
        &mut self,
        arguments: &Map<String, Value>,
    ) -> std::result::Result<Value, String> {
        let kind = scope_kind(required_string(arguments, "kind")?)?;
        let metric = required_string(arguments, "metric")?.to_owned();
        let statistic = MetricStatistic::parse(string(arguments, "statistic").unwrap_or("mean"))
            .map_err(|error| error.to_string())?;
        let regex = regex(arguments, "pattern")?;
        let call_kind = call_kind(arguments.get("call_kind").and_then(Value::as_str))?;
        let descending = boolean(arguments, "descending", true)?;
        let top = integer(arguments, "top", 20)?.clamp(1, 100);
        let analysis = self.active()?;
        let scopes = analysis
            .scopes(kind)
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|scope| {
                regex
                    .as_ref()
                    .is_none_or(|regex| regex.is_match(&scope.label))
            })
            .filter(|scope| {
                call_kind.is_none_or(|kind| {
                    scope
                        .call_start
                        .zip(scope.call_stop)
                        .is_some_and(|(start, stop)| {
                            analysis.calls()[start..stop]
                                .iter()
                                .any(|call| call.kind == kind)
                        })
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_value(
            analysis
                .rank_scopes(&scopes, &metric, statistic, descending, top)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }
}

fn server_info() -> Value {
    json!({ "name": "nsight-gpu-trace", "version": env!("CARGO_PKG_VERSION") })
}

fn tool_catalog() -> Vec<Value> {
    let read_only = json!({ "readOnlyHint": true });
    vec![
        tool(
            "open_capture",
            "Open or replace the active .ngfx-gputrace. Call this before other tools when the server was started without a trace.",
            json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
                "additionalProperties": false,
            }),
            json!({ "readOnlyHint": true }),
        ),
        tool(
            "capture_overview",
            "Summarize capture shape, frames, calls, markers, timing buckets, artifacts, and optional counter metadata. Call this first.",
            json!({
                "type": "object",
                "properties": { "with_counters": { "type": "boolean", "default": false } },
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "list_metrics",
            "Discover dynamic PerfWorks metric bases by regex and kind.",
            metric_list_schema(false),
            read_only.clone(),
        ),
        tool(
            "describe_metric",
            "Describe one exact metric, its suffix, hardware unit, and dependencies.",
            json!({
                "type": "object",
                "properties": { "metric": { "type": "string" } },
                "required": ["metric"],
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "scan_metrics",
            "Evaluate canonical forms to find which matching metric bases were collected.",
            metric_list_schema(true),
            read_only.clone(),
        ),
        tool(
            "list_scopes",
            "List bounded stable scope IDs for debug groups, NVTX ranges, frames, actions, or timing buckets.",
            json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["debug_group", "nvtx_range", "frame", "action", "timing_bucket"] },
                    "pattern": { "type": "string" },
                    "call_kind": { "type": "string", "enum": ["draw", "dispatch", "copy", "clear", "sync", "marker", "present", "other"] },
                    "parent_id": { "type": "string" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                },
                "required": ["kind"],
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "inspect_scope",
            "Inspect bounded calls or timing buckets supporting one exact scope ID or range expression.",
            json!({
                "type": "object",
                "properties": {
                    "scope": { "type": "string", "default": "capture" },
                    "include_arguments": { "type": "boolean", "default": true },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                },
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "query_metrics",
            "Evaluate exact metric names over a stable scope with overlap-weighted summaries and optional bounded samples.",
            json!({
                "type": "object",
                "properties": {
                    "metrics": { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 64 },
                    "scope": { "type": "string", "default": "capture" },
                    "include_series": { "type": "boolean", "default": false },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 100 }
                },
                "required": ["metrics"],
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "rank_scopes",
            "Rank scopes by one exact metric with one shared PerfWorks evaluation; equivalent shared-bucket actions are grouped.",
            json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["debug_group", "nvtx_range", "frame", "action", "timing_bucket"] },
                    "metric": { "type": "string" },
                    "statistic": { "type": "string", "enum": ["mean", "min", "max", "p50", "p95", "sum"], "default": "mean" },
                    "pattern": { "type": "string" },
                    "call_kind": { "type": "string", "enum": ["draw", "dispatch", "copy", "clear", "sync", "present", "other"] },
                    "top": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                    "descending": { "type": "boolean", "default": true }
                },
                "required": ["kind", "metric"],
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "top_down_report",
            "Scan all metric bases and return compact, explicitly heuristic top-down diagnostics.",
            json!({
                "type": "object",
                "properties": { "top": { "type": "integer", "minimum": 1, "maximum": 100, "default": 15 } },
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "trace_schema",
            "Discover dynamic protobuf fields at a trace path before querying uncommon data.",
            json!({
                "type": "object",
                "properties": { "path": { "type": "string", "default": "" } },
                "additionalProperties": false,
            }),
            read_only.clone(),
        ),
        tool(
            "trace_query",
            "Read a depth- and item-bounded dynamic protobuf subtree by dot path.",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "default": "" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 },
                    "max_depth": { "type": "integer", "minimum": 1, "maximum": 12, "default": 5 }
                },
                "additionalProperties": false,
            }),
            read_only,
        ),
    ]
}

fn metric_list_schema(scan: bool) -> Value {
    let mut properties = json!({
        "pattern": { "type": "string" },
        "kind": { "type": "string", "enum": ["counter", "ratio", "throughput"] },
        "offset": { "type": "integer", "minimum": 0, "default": 0 },
        "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 100 }
    });
    if scan {
        properties["sample_start"] = json!({ "type": "integer", "minimum": 0, "default": 0 });
        properties["sample_stop"] = json!({ "type": "integer", "minimum": 0 });
        properties["include_unavailable"] = json!({ "type": "boolean", "default": false });
    }
    json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false,
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
    let text = serde_json::to_string(&value).unwrap_or_else(|_| "null".into());
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": false,
    });
    if modern {
        result["resultType"] = json!("complete");
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn tool_error(id: Value, message: &str, modern: bool) -> Value {
    let mut result = json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    });
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

fn string_array(
    arguments: &Map<String, Value>,
    name: &str,
) -> std::result::Result<Vec<String>, String> {
    arguments
        .get(name)
        .and_then(Value::as_array)
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

fn paged<T: Serialize>(
    items: &[T],
    offset: usize,
    limit: usize,
) -> std::result::Result<Value, String> {
    let offset = offset.min(items.len());
    let stop = items.len().min(offset.saturating_add(limit));
    Ok(json!({
        "items": serde_json::to_value(&items[offset..stop]).map_err(|error| error.to_string())?,
        "page": {
            "offset": offset,
            "returned": stop - offset,
            "total": items.len(),
            "next_offset": (stop < items.len()).then_some(stop),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_and_lists_tools_without_a_capture() {
        let mut server = McpServer::new(AnalysisOptions::default());
        let initialized = server
            .handle(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2025-06-18" }
            }))
            .unwrap();
        assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");

        let listed = server
            .handle(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
            .unwrap();
        assert!(
            listed["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "open_capture")
        );
    }

    #[test]
    fn tool_errors_stay_inside_successful_json_rpc_results() {
        let mut server = McpServer::new(AnalysisOptions::default());
        let response = server
            .handle(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "capture_overview", "arguments": {} }
            }))
            .unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("open_capture")
        );
    }

    #[test]
    fn modern_discovery_marks_results_complete() {
        let mut server = McpServer::new(AnalysisOptions::default());
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
