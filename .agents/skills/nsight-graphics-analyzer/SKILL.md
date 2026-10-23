---
name: nsight-graphics-analyzer
description: Inspect completed .ngfx-gputrace captures and diagnose GPU bottlenecks with the read-only ngfx-trace CLI or MCP server.
metadata:
  version: 0.2.0
  short-description: Analyze Nsight traces with Rust MCP
---

# Nsight Graphics Analyzer

Use `ngfx-trace` to inspect completed `.ngfx-gputrace` files. The analyzer is
read-only: it does not launch applications, control Nsight, or create captures.
Use the capture path supplied by the user or capture workflow instead of
searching broad default folders and guessing which file belongs to a run.

## Route the task

- For installation, platform library discovery, MCP registration, and the tool
  surface, read [references/setup-and-tools.md](references/setup-and-tools.md).
- For a bottleneck investigation or optimization experiment, read
  [references/optimization-guide.md](references/optimization-guide.md).

## Analyze a trace

For a broad diagnosis, start with `analyze_capture` and its triage view. Check
`quality` before using timing or metric claims, then use the `timeline`
summary, burst/limiter findings, and regions. Reuse the `result_id` with
`query_result` to select, filter, sort, or page saved evidence; follow `$ref`
paths into the saved JSON before table formatting. Use `query_capture` for new
evidence and batch related queries against the same capture. Prefer
`metric_evaluation.scopes` or `scope_ranking` over a query loop per region.
Inspect identity, timing precision, coverage, and diagnostics relevant to the
claim; query only the missing evidence. Metric availability varies by capture.
Region ranking is multi-factor: inspect `regions.ranking` and its
`metric_pressure`/`metric_anomaly` inputs instead of assuming the longest region
is the only candidate. Use `scope_evidence` to join one scope's timing, metric
summary, calls, and action state, and `frame_series` for frame-to-frame behavior.

For a comparison, use `compare_captures` with a baseline and candidate. Read
`comparability`, `quality`, `metric_summary`, matched `scopes`, and `shaders`
before interpreting deltas. Bootstrap intervals describe within-capture sampling
noise; they do not prove that a code change caused a difference.

For draw/dispatch questions, use `action_state` (or CLI `actions`) to see
observed bindings, barrier counts, and state-change counts. Use
`shader_inventory`/`shader_sass` and CLI `sass` for cubin and SASS evidence,
including structured instruction statistics and static occupancy estimates.

Request bounded samples only for temporal questions. Use `trace_schema` and
`trace_query` for uncommon fields. View offsets page saved output; query offsets
request more capture data. If a result ID expires, rerun its original query.
Search source when attribution is needed, distinguishing exact marker matches,
symbol/string evidence, and hypotheses.

For shader evidence, use `shader_inventory` to list `Shader Profiler` code
blocks, attached cubin/SASS blobs, entry points, stages, registers, static
occupancy estimates, and PC-sampling summary fields. Use `shader_sass` for a
bounded disassembly preview, or the CLI `shaders` and `sass` commands for
complete cubins and SASS. `sass` reports structured instruction statistics and
source-line instruction counts from the debug line mapping. SASS is captured
driver output, not source; do not infer source-level causality from an
instruction listing.

For an optimization task, define an experiment with an expected timing or
metric change and compare a same-settings recapture when available. An
analysis-only request does not require code changes or a new capture.

## Evidence rules

- `null` means unavailable or not collected. It never means zero.
- Support findings with the relevant metric names, values, units, coverage,
  scope IDs, and timing precision.
- Capture-wide metrics expose duration-weighted mean, sample mean, weighted
  p50/p95, max, standard deviation, and burst ratio. A high p95 with a lower
  mean is burst pressure, not sustained pressure.
- `quality` is a usability gate. Do not treat `warn` as an optimization verdict;
  propagate the specific coverage, window, marker, or clock limitation.
- `bucket_shared` timing or metrics apply to the complete timestamp bucket.
  Never claim per-action evidence for each call inside it.
- `multi_stream_envelope` is elapsed overlap across streams, not serialized GPU
  duration. An unclosed marker or unvalidated NVTX clock weakens attribution.
- Action state reports observed bindings, workload counts, and barrier
  stage/access evidence. Missing workload or barrier fields mean the capture did
  not expose them, not that the event had zero work.
- A high percent-of-peak value identifies pressure, not causality. Compare
  neighboring units and timing before naming a limiter. A throughput cluster is
  evidence of co-located pressure, not a single winner.
- Thresholds in the optimization guide suggest hypotheses. A causal claim
  needs evidence from a controlled change. `compare_captures` reports deltas and
  uncertainty; it does not accept or reject the change.

Stop querying when the requested question is answered or the capture cannot
resolve it. State evidence limits and the next useful measurement when needed.
