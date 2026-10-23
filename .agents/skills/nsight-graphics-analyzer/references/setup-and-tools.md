# Setup and Tools

`ngfx-trace` requires Rust 1.88 or newer and a matching NVIDIA Nsight Graphics
installation. Install the CLI from a checkout and register its read-only stdio
MCP server:

```sh
cargo install --path .
codex mcp add nsight-gpu-trace -- ngfx-trace mcp
```

Restart the MCP client after registration or rebuilding. Capture requests supply
a path and own their analysis for that call. Immutable results remain available
through `query_result`; the server keeps an in-memory LRU and also writes the
content-addressed result JSON to a disk cache, so IDs survive a restart unless
the cache is removed.

## Nsight libraries

The analyzer discovers the matching schema and PerfWorks libraries from normal
Nsight installation roots:

| Platform | Schema binary | PerfWorks library | Default root |
|---|---|---|---|
| Linux | `libWarpVizPlugin.so` | `libnvperf_grfx_host.so` | `~/nvidia`, `/opt/nvidia/nsight-graphics` |
| Windows | `WarpVizPlugin.dll` | `nvperf_grfx_host.dll` | `%ProgramFiles%\NVIDIA Corporation` |

For a nonstandard install or to pin the libraries that match a capture, set
`NGFX_SCHEMA_BINARY` and `NGFX_NVPERF_LIBRARY`, or pass `--schema-binary` and
`--nvperf-library`. Do not redistribute NVIDIA binaries or extracted schemas.

## MCP tools

| Tool | Use |
|---|---|
| `analyze_capture` | Compute a complete report and return a compact triage view plus `result_id` |
| `compare_captures` | Compare baseline and candidate evidence, including quality/comparability, metric/scope deltas, and shader deltas |
| `query_capture` | Compute new evidence in a batch against one freshly opened capture |
| `query_result` | Filter, sort, project, and page saved evidence without reopening the capture |

`analyze_capture` accepts `capture`, optional `scope_pattern`, optional
`metric_patterns` or exact `metrics`, `top`, and a `preset` (`triage`, `metrics`,
or `full`). Presets change the output view; complete computed evidence is saved.
Regex metric selectors match collected canonical metrics and evaluate them in
that call.

`query_capture` accepts `capture` and one to 16 query objects. Available query
types are `container_info`, `calls`, `timings`, `scopes`, `counter_samples`,
`capture_quality`, `timeline`, `action_state`, `frame_series`, `scope_evidence`,
`metric_discovery`, `metric_evaluation`, `scope_ranking`, `trace_schema`,
`trace_query`, `artifact_inventory`, and `artifact_read`. `metric_discovery`
lists by regex or describes one exact metric; `metric_evaluation` accepts exact
names, regexes, or both. Pass `scopes` (up to 1024 IDs) instead of `scope` for
one shared metric evaluation across regions or frames. NVTX scopes require a caller-supplied
`nvtx_offset_ns` (and optionally `nvtx_residual_ns`) because the analyzer does
not guess clock calibration. `scope_ranking` takes a scope `kind`, optional
`pattern`, exact `metric`, `statistic`, `descending`, and bounded `top`; use it
to rank all matching scopes without enumerating their metrics in the transcript.
`scope_evidence` joins one scope's timing, metric summary, bounded calls, and
action state in one reply. `frame_series` evaluates selected metrics per frame
and returns duration, gap, and metric summaries for each frame.
`timeline` reports queue lanes, gaps, overlap, and frame pacing with bounded gap
lists. `action_state` reports observed bindings, barrier counts, and
state-change counts for draw/dispatch actions. Calls omit arguments and metric
evaluations omit samples unless requested. Artifact reads are hex encoded and
limited to 16 KiB per query. Use each query's offset for stateless paging.

## Keep follow-ups small

Replies contain `result_id`, `path`, and `data`. Every tool accepts `view` and
`max_bytes` (12 KiB by default, 1–64 KiB allowed for the entire JSON-RPC reply).
The default `query_capture` view is `/results`. Identically shaped records use
`columns`/`rows`, with `keys` for object maps; request `view.format: "json"` when
ordinary objects are useful. Paths always address the saved JSON before this
formatting. Explicit views override analysis presets.

Use `query_result` with the returned ID and a `view`:

```json
{
  "result_id": "<returned ID>",
  "view": {
    "path": "/regions/items",
    "sort_by": "/timing/duration_ns",
    "select": ["/scope_id", "/label", "/timing", "/counter_coverage"],
    "limit": 5
  }
}
```

`filter` is an array of `{path, op, value}` predicates combined with AND;
operators are `eq`, `ne`, `gt`, `ge`, `lt`, `le`, and string `contains`. Filters
and sorting run before paging, and selection runs last. Object maps can be
viewed as `{key, value}` rows with `entries: true`. Null/missing sort values stay
last; selecting an absent field is an error. Preserve timing precision,
warnings, and metric coverage needed for the claim when projecting fields.

Follow `$ref` using the same result ID and the reference as `view.path`. If a
single row exceeds the budget, its returned count is zero and the offset stays
unchanged: narrow `select`, follow the reference, or increase `max_bytes`.
`page.next_offset` applies to the current view. A saved result contains only the
original computation: use capture-query offsets or increase `top` to compute
more. Analysis region metrics live at `/region_metrics/<scope ID>`.

Results are capped at 16 MiB each, with 16 distinct results / 64 MiB retained
in insertion order. An expired ID returns an error; rerun the original capture
query. Repeated views do not create new results or evict existing ones.

Use CLI `json`, `extract`, `section`, and `unpack` for complete protobuf or
multi-megabyte binary output.
