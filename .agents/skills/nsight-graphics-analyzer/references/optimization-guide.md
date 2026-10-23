# Nsight GPU Optimization Guide

Use this guide after a capture is open. It combines practical heuristics with
NVIDIA's documented top-down and peak-performance methods. Thresholds narrow an
investigation; they do not prove causality.

## Capture quality first

Run `quality` (or read the `quality` block from `analyze_capture`) before using
timing or metric claims. Check counter completeness, timestamp coverage, whether
the API timing window fits inside the counter window, frame markers, `Time Every
Action`, GPU clock mode, V-Sync, and action-attribution limits. A `warn` status
is not an optimization verdict; carry the specific limitation into the claim.

Before comparing measurements, use the same representative workload, camera,
resolution, quality settings, and warmed frame window. Disable VSync and frame
caps where practical, let background shader and pipeline compilation finish,
minimize unrelated GPU activity, and keep traces short enough to isolate the
workload. Change one variable per recapture. Use `compare_captures` to check
environment/settings comparability before interpreting deltas.

Prefer fixed base clocks for A/B comparisons. Boost clocks answer a different
question: attainable peak performance. Unaltered clocks are useful when clock
control would perturb a thermal or battery-sensitive workload.

`Time Every Action` improves action attribution but adds timestamp overhead and
can perturb a busy frame. Without it, several calls may share one
`bucket_shared` result. The Real-Time Shader Profiler provides source-level
sampling but trades away detailed SM and L1TEX counter collection; use it in a
separate capture after ordinary counters identify a shader-limited region.

## Top-down investigation

Use this sequence for an open-ended bottleneck diagnosis. For a focused
question, start with the relevant evidence and expand only if it is inconclusive.

1. Establish elapsed GPU time, frame pacing, counter-window coverage, idle
   periods, synchronization, and whether the GPU is being fed. Use the
   `timeline` queues, gaps, overlap, and frame summary. Investigate idle or
   stalls before bandwidth or shader tuning.
2. Compare SM and fixed-function percent-of-peak throughputs at both
   duration-weighted mean and p95/max. A high p95 with a lower mean is burst
   pressure; inspect per-sample series and timing buckets rather than calling it
   sustained pressure. Treat units within about 10 percentage points as a
   limiter cluster rather than forcing a single winner. A lead of roughly 15
   points is stronger, still provisional evidence.
3. Compare memory tiers with compute. For a memory-heavy region, follow traffic
   through L1TEX, L2, VRAM, then PCIe. For a compute-heavy region, inspect SM
   issue, shader-stage work, dependency stalls, registers, shared memory, and
   occupancy constraints.
4. Inspect raster/geometry, overdraw, copies, and small actions only after the
   dominant axis is known.
5. Localize the signal in `analyze_capture` regions. Regions are ranked by
   duration, metric pressure, and metric anomaly; do not assume the longest
   region is the only candidate. Use `scope_evidence` to join timing, metric
   summaries, calls, and action state for one scope, then batch `scopes`,
   `timings`, and `metric_evaluation` queries for other candidates. Use
   `frame_series` when the question is about frame-to-frame behavior or
   regression rather than one capture-wide average. Compare adjacent units to
   distinguish backpressure from the unit that originated it.
6. Form one falsifiable experiment and state the metric and timing change that
   would support or reject it.

## Heuristic ranges

These are operational starting points, not NVIDIA pass/fail specifications.

| Signal | Investigation guide |
|---|---|
| Percent of peak throughput | `<60%`: underutilized or blocked territory; `60-80%`: gray zone/pressure; `>=80%`: near saturation |
| Competing unit throughput | Within about 10 percentage points: treat as a limiter cluster |
| General cache hit rate | `>90%`: great; `70-90%`: good; `<70%`: investigate if cache traffic is material |
| L1TEX hit rate | `<50%`: strong thrashing/locality warning when downstream traffic is high |
| Miss traffic reaching DRAM | `>=10%`: investigate cache locality, mips, and reuse |
| PCIe throughput | `>=30%` sustained: investigate host/device transfer churn |
| Overdraw ratio | `>3`: investigate depth ordering, prepass, culling, or redundant shading |
| ZCull rejection rate | `<0.3`: investigate why hierarchical depth rejection is ineffective |
| Pixels per primitive | `<4`: micro-triangle warning; `>=16` is a healthier starting region |
| Small timed actions | `<5 us` each and numerous: batching/state-churn candidate, subject to timestamp precision |

Ratios may be reported as `0..1` or percentages depending on the exact PerfWorks
metric. Use an exact `metric_discovery` query and preserve the returned units
before applying a threshold. A cache with a low hit rate but negligible traffic
is not the limiter; a saturated downstream unit may be backpressure rather than
root cause.

## Optimization branches

For GPU idle or gaps, inspect CPU submission, waits, barriers, queue dependencies,
frame caps, and marker coverage. Optimizing shader arithmetic cannot fill a GPU
that has no work.

For memory pressure, test fewer bytes before fewer instructions: eliminate
redundant loads/stores, improve contiguous/coalesced access, compact hot data,
separate cold fields, improve texture mips/locality, and reduce spills. Confirm
that lower cache traffic does not increase registers enough to reduce useful
residency.

For shader/SM pressure, identify the responsible stage and source first. Shorten
live ranges, remove duplicated/divergent work, reduce expensive dependencies,
and inspect compiled registers and shared memory. Occupancy is a means of hiding
latency, not the target; a non-spilling kernel at lower occupancy can be faster.

For geometry or raster pressure, test frustum/occlusion culling, LOD, primitive
size, early depth, draw ordering, and alpha/discard behavior. Do not recommend a
depth prepass solely from overdraw: measure its extra geometry/bandwidth cost.

For many small actions, first verify that timing is action-precise. Then test
batching, indirect/multi-draw submission, state sorting, or moving repeated CPU
work to GPU-driven structures. Preserve ordering and synchronization semantics.

## Reporting

Report the evidence needed to support the answer: scope and timing attribution,
relevant metrics with units and coverage, and uncertainty in causal or source
attribution. For optimization proposals, include the expected effect and material
correctness or quality risks. Include baseline/recapture comparisons only when
measured; do not require another capture to deliver an analysis-only result.

For a measured comparison, use `compare_captures` and report:

- comparability warnings for GPU, driver, product version, API, and settings;
- the metric and scope deltas with their bootstrap intervals;
- whether the interval includes zero; and
- shader/cubin changes when both captures contain Shader Profiler data.

The comparison is evidence, not a verdict. Do not claim that a change caused an
improvement from a single pair of captures or from an interval that includes
zero. Repeat captures belong to the external experiment loop.

## Source basis

Authoritative guidance, reviewed 2026-08-23:

- [NVIDIA GPU Trace overview](https://docs.nvidia.com/nsight-graphics/UserGuide/gpu-trace-overview.html): capture setup, trace scope, and metric workflow.
- [NVIDIA GPU Trace UI](https://docs.nvidia.com/nsight-graphics/UserGuide/gpu-trace-ui.html): throughput rows, timing, markers, and top-down inspection.
- [NVIDIA GPU architecture guide](https://docs.nvidia.com/nsight-graphics/UserGuide/gpu-trace-system-architecture.html): unit relationships and pressure propagation.
- [NVIDIA Shader Profiler](https://docs.nvidia.com/nsight-graphics/UserGuide/shader-profiler.html): source correlation, sampling, and counter tradeoffs.
- [Peak Performance Analysis Method](https://developer.nvidia.com/blog/the-peak-performance-analysis-method-for-optimizing-any-gpu-workload/): identify the limiting subsystem, optimize it, and remeasure rather than tuning by intuition.
