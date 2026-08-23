---
name: nsight-graphics-analyzer
description: Analyze completed NVIDIA Nsight Graphics GPU Trace captures with the Rust ngfx-trace CLI or MCP server. Use for .ngfx-gputrace inspection, GPU bottleneck analysis, metric evaluation, scope attribution, or capture-driven optimization on Linux and Windows. Do not use for launching or controlling the captured application.
metadata:
  version: 0.1.0
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

1. Call `open_capture`, then `capture_overview`. Confirm capture identity,
   workload shape, timing precision, counter availability, and sample coverage.
2. Use `top_down_report` for bounded triage. Use `list_metrics`, `scan_metrics`,
   and `describe_metric` to discover exact collected metric names; never assume
   a metric exists because it appeared in another capture.
3. Resolve work with `list_scopes`, reuse its stable IDs, and call
   `inspect_scope` before attributing a cost. Rank candidate scopes with
   `rank_scopes`; query only the metrics needed to test the current hypothesis.
4. Request a bounded series from `query_metrics` only when temporal behavior is
   relevant. Use `trace_schema` followed by bounded `trace_query` for uncommon
   captured fields.
5. Correlate scope labels and captured strings with source using normal
   workspace search. Classify the result as an exact marker match,
   symbol/string evidence, or a hypothesis. Do not present a search candidate
   as proof.
6. Turn the finding into one experiment with an expected timing or metric
   movement, then compare a same-settings recapture.

## Evidence rules

- `null` means unavailable or not collected. It never means zero.
- Cite exact metric names, values, coverage, scope IDs, and timing precision.
- `bucket_shared` timing or metrics apply to the complete timestamp bucket.
  Never claim per-action evidence for each call inside it.
- `multi_stream_envelope` is elapsed overlap across streams, not serialized GPU
  duration. An unclosed marker or unvalidated NVTX clock weakens attribution.
- A high percent-of-peak value identifies pressure, not causality. Compare
  neighboring units and timing before naming a limiter.
- Treat thresholds in the optimization guide as heuristics and verify them with
  a controlled change.

Keep results bounded. Stop drilling when the evidence identifies a marker-level
region or metric pattern precise enough to define the next experiment.
