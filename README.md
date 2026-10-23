# nsight-gpu-trace

[![CI](https://github.com/xirreal/nsight-gpu-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/xirreal/nsight-gpu-trace/actions/workflows/ci.yml)

Read and analyze NVIDIA Nsight Graphics GPU Trace (`.ngfx-gputrace`) captures
without exporting them through the GUI. The project provides a Rust library, a
JSON CLI named `ngfx-trace`, and a read-only MCP server for analysis agents.

The capture and the matching Nsight installation remain authoritative. This
project does not redistribute NVIDIA binaries, protobuf schemas, counter
formulas, or capture data.

## What it does

- Validates WRPV v10 containers and streams their LZ4 sections.
- Recovers the matching protobuf descriptors from the installed Nsight WarpViz
  plugin, then exposes complete dynamic ProtoJSON and bounded field queries.
- Indexes OpenGL, Vulkan, and D3D12 calls, frames, debug groups, NVTX ranges,
  timestamp buckets, artifacts, and stable attribution scopes.
- Loads the installed PerfWorks host library at runtime to discover and evaluate
  the metrics actually present in a capture.
- Decodes the Shader Profiler blob table (LZ4 plus the reused
  `OBFUSCATION_SIMPLE` XOR stream), extracts attached driver ELF/cubins, and
  disassembles them with `nvdisasm`.
- Computes duration-weighted metric summaries with explicit coverage, weighted
  p50/p95, burst ratios, and `null` semantics.
- Classifies capture quality and extracts normalized GPU, driver, product, API,
  and capture-setting identity.
- Builds queue-lane timelines with gaps, overlap, frame pacing, and frame-rate
  evidence.
- Ranks triage regions by duration, metric pressure, and metric anomaly, not
  duration alone, and returns the ranking inputs.
- Compares two captures with comparability warnings, metric/scope deltas, and
  bootstrap confidence intervals. It reports evidence; the caller decides.
- Reconstructs observed action bindings, barrier counts, and state-change counts
  from captured API calls without claiming full pipeline state.
- Reports structured SASS statistics, source-line instruction counts, and static
  occupancy estimates alongside shader inventory.
- Exports the raw protobuf, descriptors, JSON, byte fields, counter image, and
  WRPV sections without overwriting existing files.
- Provides bounded MCP tools for trace triage, comparison, and capture-driven
  optimization.

## Platform support

| Platform | Schema binary | PerfWorks library | Automatic discovery |
|---|---|---|---|
| Linux x86_64 | `libWarpVizPlugin.so` | `libnvperf_grfx_host.so` | `~/nvidia` and `/opt/nvidia/nsight-graphics` |
| Windows x86_64 | `WarpVizPlugin.dll` | `nvperf_grfx_host.dll` | `%ProgramFiles%\NVIDIA Corporation` |

The parser is validated against WRPV version 10 captures produced by Nsight
Graphics 2026.3. Linux and Windows builds are tested in CI. Runtime schema and
metric compatibility require libraries from the Nsight generation that matches
the capture.

## Install

Requirements:

- Rust 1.88 or newer
- A 64-bit NVIDIA Nsight Graphics installation matching the capture

Install the latest source directly from GitHub:

```sh
cargo install --locked --git https://github.com/xirreal/nsight-gpu-trace
```

Or install from a checkout:

```sh
cargo install --locked --path .
```

Check the installation with `ngfx-trace --help`. Commands that only inspect the
outer WRPV container, such as `info` and `section`, do not load Nsight libraries.

## Library discovery

The CLI normally finds both runtime files inside the newest discovered Nsight
installation. Pin explicit files when Nsight is installed elsewhere or several
versions are present.

Linux:

```sh
export NGFX_SCHEMA_BINARY=/path/to/libWarpVizPlugin.so
export NGFX_NVPERF_LIBRARY=/path/to/libnvperf_grfx_host.so
```

Windows PowerShell:

```powershell
$env:NGFX_SCHEMA_BINARY = 'C:\Program Files\NVIDIA Corporation\Nsight Graphics 2026.3.0\host\windows-desktop-nomad-x64\Plugins\WarpVizPlugin\WarpVizPlugin.dll'
$env:NGFX_NVPERF_LIBRARY = 'C:\Program Files\NVIDIA Corporation\Nsight Graphics 2026.3.0\host\windows-desktop-nomad-x64\nvperf_grfx_host.dll'
```

The equivalent command-line options are `--schema-binary` and
`--nvperf-library`. The older `WRPV_SCHEMA_BINARY` and `WRPV_NVPERF_LIBRARY`
environment names remain accepted for compatibility.

## Quick start

Every read or query command emits JSON on stdout and errors on stderr. Bounded
commands default to 100 rows and accept `--offset` and `--limit`; add `--compact`
for single-line output.

```sh
# Inspect the container without loading Nsight libraries.
ngfx-trace info capture.ngfx-gputrace

# Summarize workload, timing, scopes, and collected counter metadata.
ngfx-trace summary capture.ngfx-gputrace --with-counters

# Discover fields before querying an uncommon protobuf subtree.
ngfx-trace schema capture.ngfx-gputrace
ngfx-trace query capture.ngfx-gputrace devices.0

# Find collected metrics instead of guessing their names.
ngfx-trace metrics scan capture.ngfx-gputrace --filter 'sm|l1tex|lts|dram'
ngfx-trace metrics describe capture.ngfx-gputrace sm__throughput.avg.pct_of_peak_sustained_elapsed

# Rank scopes and run bounded top-down triage.
ngfx-trace scopes capture.ngfx-gputrace debug-group --limit 50
ngfx-trace report capture.ngfx-gputrace --top 20

# Check whether the capture can support the claims you want to make.
ngfx-trace quality capture.ngfx-gputrace

# Inspect queue lanes, gaps, overlap, and frame pacing.
ngfx-trace timeline capture.ngfx-gputrace --min-gap-ns 1000

# Compare a baseline and a candidate without deciding whether the change is good.
ngfx-trace compare baseline.ngfx-gputrace candidate.ngfx-gputrace --top 20

# Inspect observed bindings and barrier counts around draw/dispatch actions.
ngfx-trace actions capture.ngfx-gputrace --kind draw --limit 20

# List Shader Profiler shaders and their attached cubin/SASS blobs.
ngfx-trace shaders capture.ngfx-gputrace --limit 20
ngfx-trace shaders capture.ngfx-gputrace --filter 'terrain|sky' --blobs

# Extract the driver cubin and disassemble it with register liveness.
ngfx-trace sass capture.ngfx-gputrace 0
ngfx-trace sass capture.ngfx-gputrace terrain.frag --cubin terrain.cubin \
  --output terrain.sass
```

`sass` runs `nvdisasm -c -g -plr -lrm count` when the cubin supports register
life ranges, and retries with `-c -g` when the ELF format does not. It also runs
`nvdisasm --emit-json -c -g` to report instruction counts, opcode mix, loads,
stores, spills, branches, barriers, texture operations, predication, and the
source-line instruction counts produced by the debug line mapping. Use
`--nvdisasm` or `NGFX_NVDISASM` to pin the tool. The decoder uses a recovered
stream that is reused across Nsight 2026.3 captures. The shipped stream was
audited on 12 captures and 664 obfuscated blobs with zero decode errors; every
independently recovered prefix matched it, and cross-decoding with one stream
failed on no shader-bearing capture. If a future producer uses a different
stream, pass `--keystream FILE` or recover it from one known plaintext blob with
`--known-plaintext shader.spv`. A reused XOR stream is not a secret: one known
plaintext recovers the stream for every other blob in the capture.

Run `ngfx-trace <command> --help` for the complete options. Major command groups
include `calls`, `timings`, `scopes`, `actions`, `quality`, `timeline`, `compare`,
`metrics`, `shaders`, `sass`, `artifacts`, `extract`, `section`, `unpack`,
`schema`, `query`, and `json`.

## MCP server

Register one long-lived stdio server with Codex:

```sh
codex mcp add nsight-gpu-trace -- ngfx-trace mcp
```

This follows the [official Codex MCP configuration](https://developers.openai.com/codex/mcp/).
Restart the client after registration. Each capture request opens and drops its
own capture. There is no mutable current capture for interleaved clients to
replace. Complete query results are retained separately under immutable IDs so
follow-ups can select existing evidence without reopening or rescanning a trace.

For another MCP client:

```json
{
  "mcpServers": {
    "nsight-gpu-trace": {
      "command": "ngfx-trace",
      "args": ["mcp"]
    }
  }
}
```

The MCP advertises four tools:

- `analyze_capture` runs the complete one-shot pipeline. It accepts `capture`,
  an optional `scope_pattern`, optional `metric_patterns` or exact `metrics`,
  a bounded `top`, and a `preset`: `triage` (default), `metrics`, or `full`.
  Presets select output; the saved result includes capture/workload identity,
  capture quality and environment identity, a queue-lane timeline, timing and
  counter coverage, a complete metric scan with top-down diagnostics,
  representative capture and region summaries, automatic debug-group/NVTX/
  frame/timing-bucket fallback, and a raw-data manifest.
- `compare_captures` opens a baseline and a candidate, checks environment and
  capture-setting comparability, and returns common-metric deltas with weighted
  bootstrap intervals plus matched scope and shader/cubin deltas. It does not
  accept or reject a change.
- `query_capture` executes up to 16 discriminated queries against one freshly
  opened capture. Query types cover container sections, calls, timings, scopes,
  counter samples, capture quality, queue timelines, action state, frame-series
  metrics, scope evidence dossiers, metric discovery/descriptions/evaluation,
  trace schema/data, artifact inventory, bounded artifact reads, Shader Profiler
  inventories, and bounded SASS disassembly. `metric_evaluation.scopes`
  aggregates up to 1024 scope IDs in one evaluation; `scope_ranking` finds the top
  scopes for one metric using the library's coverage and shared-bucket rules.
  Each paged query accepts its own stateless offset. The default output view
  pages through `/results`.
- `query_result` selects evidence from a saved `result_id`. It can filter, sort,
  project fields, and page arrays or object entries entirely on the server.
  It does not reload Nsight libraries, reopen the capture, or evaluate counters.

Every tool reply contains `result_id`, `path`, and `data`. The default budget is
12 KiB for the **entire JSON-RPC reply**, including legacy JSON escaping and all
queries in a batch. Set `max_bytes` from 1 to 64 KiB when needed. Arrays return
`page` metadata with a resumable `next_offset`. Values that cannot fit become
`$ref` pointers into the saved JSON; an oversized single row returns zero rows
and keeps its offset, so narrow `select` or follow its `$ref`. Evidence is never
deleted to make a preview fit.

Repeated record fields are factored into `columns` and `rows`; `keys` identifies
the rows of an object map. `view.format: "json"` retains ordinary JSON. All view
paths are JSON Pointers into the **saved, unformatted** result, not the displayed
tables. `filter` and `sort_by` run before view paging; `select` runs afterward.
`entries: true` exposes an object map as `{key, value}` rows. Missing selected
fields are errors; unavailable measurements remain `null`. Sorting keeps null
and missing values last in either direction.

For example, after `analyze_capture`, inspect the longest returned regions with
`query_result`:

```json
{
  "result_id": "<ID returned by analyze_capture>",
  "view": {
    "path": "/regions/items",
    "sort_by": "/timing/duration_ns",
    "select": ["/scope_id", "/label", "/timing", "/counter_coverage"],
    "limit": 5
  }
}
```

The analysis stores region summaries under `/region_metrics/<scope ID>` and
capture summaries under `/representative_metrics/capture_summary`. An explicit
`view` overrides an analysis preset and can select only the needed evidence in
the initial call. View paging covers the computed result; increase the original
query's limit/offset or analysis `top` when more evidence must be computed.

The server retains at most 16 distinct results and 64 MiB of serialized JSON in
memory, evicting in insertion order. Each result is limited to 16 MiB. IDs are
hashes of the complete result, so eviction cannot redirect an ID to another
capture. Results are also written to a disk-backed cache (`$NGFX_RESULT_CACHE`,
`$XDG_CACHE_HOME/ngfx-trace`, or `~/.cache/ngfx-trace`), so `query_result` can
survive a restart. An expired ID produces an explicit error; rerun the original
query.
Capture requests remain independent, but saved-result retrieval needs the same
running server. The server cannot remove replies already in a client's history.

**Migration:** MCP replies now use the `result_id`/`data` envelope and default
table formatting. Update consumers expecting the former raw object; use an
explicit `view` with `format: "json"` for ordinary JSON. The CLI and Rust
analysis APIs retain their existing output. Rebuild and restart the MCP server
to refresh its tool catalog.

Default responses omit metric sample series, call arguments, and binary
payloads. Regex metric selectors in `metric_evaluation` scan and evaluate the
matching collected canonical metrics in the same call. Use CLI `json`,
`extract`, `section`, and `unpack` for complete or multi-megabyte raw output.
The existing transport behavior is preserved: clients using the 2026-07-28
per-request protocol metadata receive structured content only; other clients
receive text JSON only. Neither path duplicates the payload. MCP makes tool
results available to the client; smaller views reduce the evidence supplied to
its conversation. See the [MCP tool-result specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#tool-result).

A generic analysis skill is included in
[`.agents/skills/nsight-graphics-analyzer`](https://github.com/xirreal/nsight-gpu-trace/tree/main/.agents/skills/nsight-graphics-analyzer).

## Rust library

Add the repository as a Git dependency until the crate is published to
crates.io:

```toml
[dependencies]
nsight-gpu-trace = { git = "https://github.com/xirreal/nsight-gpu-trace", tag = "v0.2.0" }
```

```rust
use nsight_gpu_trace::{Analysis, AnalysisOptions, Result};

fn main() -> Result<()> {
    let analysis = Analysis::open(
        "capture.ngfx-gputrace",
        AnalysisOptions::default(),
    )?;
    println!("{} API calls", analysis.calls().len());
    Ok(())
}
```

The `container`, `trace`, `analysis`, `perfworks`, and `diagnostics` modules are
public. `TraceDocument` also exposes the descriptor pool, decoded dynamic
message, and raw protobuf for callers that need direct `prost-reflect` access.

## Evidence model

- An unavailable metric is `null`, never zero.
- Metric names and suffixes come from the loaded PerfWorks catalog.
- Time-based summaries weight each periodic sample by nanosecond overlap, and
  weighted p50/p95 use the same overlap.
- Capture-wide evidence includes duration-weighted mean, sample mean, weighted
  p50/p95, max, standard deviation, burst ratio, and peak sample index.
- `bucket_shared` evidence applies to the whole timestamp bucket, not each call
  inside it.
- `multi_stream_envelope` is elapsed overlap across streams, not serialized GPU
  duration.
- Capture quality is a usability gate, not an optimization verdict. It reports
  counter completeness, timestamp coverage, counter/timing window alignment,
  frame markers, clock/V-Sync settings, and action-attribution limits.
- Percent-of-peak metrics show pressure, not causality. The top-down report
  labels every threshold as a heuristic and separates sustained pressure, burst
  pressure, idle evidence, and throughput clusters.
- Triage regions are ranked by duration, metric pressure, and metric anomaly.
  The ranking inputs are returned; the tool does not declare a single winning
  region. `scope_evidence` joins one scope's timing, metric summary, calls, and
  action state; `frame_series` evaluates selected metrics per frame.
- `compare_captures` reports deltas and bootstrap intervals. Accepting or
  rejecting a change belongs to the external decision loop.
- Action state is reconstructed from captured bind/barrier calls. It includes
  observed bindings, draw/dispatch workload counts when the arguments were
  captured, and barrier stage/access evidence. It is not a complete API state
  tracker and does not infer unobserved pipeline state.

## Current limits

- Only WRPV version 10 is accepted. Unknown versions, compression modes, and
  section roles are rejected instead of guessed.
- Proprietary `GPUTrace.*` UI formulas are not reimplemented.
- Opaque bytes without a documented inner format are inventoried and exported,
  not interpreted speculatively.
- PC-sampling payloads are preserved as a summary (`sample_type_names`, range
  count, pass/sample counts, stall-reason means) but individual PC ranges are not
  interpreted when the producer omits them.
- Legacy NVTX ranges retain an unvalidated clock. The analyzer does not guess a
  clock offset; callers can supply `nvtx_offset_ns` (and an optional residual)
  to `metric_evaluation` or `scope_ranking` when they have calibrated it.
- SASS statistics come from `nvdisasm --emit-json`; register-life text output is
  retained separately. Occupancy is a static estimate from registers, block size,
  and static shared memory, not a measured runtime occupancy.
- Action state reconstructs observed bindings and barriers only; it does not
  rebuild full D3D12/Vulkan/OpenGL pipeline state.
- The analyzer reads completed captures; it does not launch applications or
  control Nsight capture sessions. Capture orchestration and change decisions
  belong to an external loop.

See [FORMAT.md](FORMAT.md) for the inferred WRPV v10 layout and [NOTICE](NOTICE)
for NVIDIA SDK and schema provenance.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked
```

The ignored integration tests exercise real captures and the matching Nsight
installation:

```sh
NGFX_TEST_CAPTURE_DIR=/path/to/captures \
  cargo test --test real_captures -- --ignored --nocapture
```

They verify real timing-bucket validity, metric scan statistics, capture
quality, timeline invariants, action state, shader/cubin decode, `nvdisasm`
SASS statistics, and side-by-side comparison. They are intentionally ignored by
default because captures and Nsight versions are environment-specific.

## License

MIT. This is an independent project and is not affiliated with, sponsored by,
or endorsed by NVIDIA Corporation.
