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
- Computes time-weighted metric summaries with explicit coverage and `null`
  semantics.
- Decodes real-time shader profiler PC samples and attributes each one to its
  shader, SASS instruction, SPIR-V instruction, and source line, optionally
  restricted to any time, call, frame, or labeled scope.
- Exports the raw protobuf, descriptors, JSON, byte fields, counter image, and
  WRPV sections without overwriting existing files.
- Provides bounded MCP tools for trace triage and capture-driven optimization.

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

# Real-time shader profiler PC samples (captured with --real-time-shader-profiler).
ngfx-trace pc-samples summary capture.ngfx-gputrace --scope frame:presented:0:0:0
ngfx-trace pc-samples summary capture.ngfx-gputrace --scope frame:presented:0:0:0 --warp-weighted
ngfx-trace pc-samples hotspots capture.ngfx-gputrace --group-by line --limit 20
ngfx-trace pc-samples hotspots capture.ngfx-gputrace --group-by instruction --shader lighting
ngfx-trace pc-samples shaders capture.ngfx-gputrace
ngfx-trace pc-samples records capture.ngfx-gputrace --scope calls:120..140 --sm 3
```

Run `ngfx-trace <command> --help` for the complete options. Major command groups
include `calls`, `timings`, `scopes`, `metrics`, `pc-samples`, `artifacts`,
`extract`, `section`, `unpack`, `schema`, `query`, and `json`.

## PC samples

`pc-samples` reads the per-SM sample storage of real-time shader profiler
captures and joins it with the shader profiler tables:

- `summary`: sample type (stall reason) distribution, instruction mix, and
  samples per shader. With `--warp-weighted` it also reports stall reasons and
  shaders as average warps and percent of the SM warp slots, the
  `GPUTrace.PCSampler` values of Nsight's GPU Trace export (needs PerfWorks);
- `shaders`: SPIR-V modules, code blocks, debug-info coverage, and sample counts;
- `hotspots`: source lines per pipeline, SPIR-V instructions
  (`--group-by instruction`), or SASS instructions (`--group-by sass`) ranked
  by samples, each with its sample types, instruction mix, and SASS
  instruction count;
- `records`: individual samples with PC, interpolated time, SM, and attribution.

The instruction mix uses Nsight's classes (pipe, family, operation, for example
`LSU Shared Memory Load`) from a table generated with
`tools/generate_sass_classes.py`.

Shares are percent of the samples selected by `--scope`. Samples have no own
timestamps. As in Nsight, every sample belongs to the periodic counter range
its anchors assign it to, and a time-based scope selects the samples whose
range overlaps it. Records report the midpoint of their slot between two
anchors. The Nsight UI counts only its trace range, so `--scope frame:...`
reproduces the UI's sample total and percentages; the default scope covers the
whole capture. Like the UI's hotspot table, line hotspots count every pipeline
on its own.

The warp weighting distributes the active warps the counters measured per TPC
over each SM's samples in that counter range. It reads per-instance counter
values through a host function that PerfWorks does not export by name. Shader
blobs are decoded with a key recovered at runtime from the installed WarpViz
plugin. Captures without samples report `available: false` and the reason.

## MCP server

Register one long-lived stdio server with Codex:

```sh
codex mcp add nsight-gpu-trace -- ngfx-trace mcp
```

This follows the [official Codex MCP configuration](https://developers.openai.com/codex/mcp/).
Restart the client after registration. The server is stateless: every tool call
includes a capture path, opens that capture once, completes its analysis, and
drops it before returning. Interleaved clients cannot replace one another's
capture.

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

The MCP advertises two tools:

- `analyze_capture` runs the complete one-shot pipeline. It accepts `capture`,
  an optional `scope_pattern`, optional `metric_patterns` or exact `metrics`,
  and a bounded `top`. The result includes capture/workload identity, timing and
  counter coverage, a complete metric scan with top-down diagnostics,
  representative capture and region summaries, automatic debug-group/NVTX/
  frame/timing-bucket fallback, and a raw-data manifest.
- `query_capture` executes up to 16 discriminated queries against one freshly
  opened capture. Query types cover container sections, calls, timings, scopes,
  counter samples, metric discovery/descriptions/evaluation, trace schema/data,
  artifact inventory, bounded artifact reads, and PC sampling (`pc_sampling`
  with the views `summary`, `shaders`, `hotspots`, and `records`). Each paged
  query accepts its own stateless offset.

`analyze_capture` also includes a compact PC sampling section with the leading
sample types, shaders, and source lines when the capture has samples, plus
their warp-weighted values. The `pc_sampling` summary view adds them with
`warp_weighted: true`.

Default responses omit metric sample series, call arguments, and binary
payloads. Regex metric selectors in `metric_evaluation` scan and evaluate the
matching collected canonical metrics in the same call. Use CLI `json`,
`extract`, `section`, and `unpack` for complete or multi-megabyte raw output.
Modern MCP clients receive structured content only; legacy clients receive text
JSON only.

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
- Time-based summaries weight each periodic sample by nanosecond overlap.
- `bucket_shared` evidence applies to the whole timestamp bucket, not each call
  inside it.
- `multi_stream_envelope` is elapsed overlap across streams, not serialized GPU
  duration.
- Percent-of-peak metrics show pressure, not causality. The top-down report
  labels every threshold as a heuristic.

## Current limits

- Only WRPV version 10 is accepted. Unknown versions, compression modes, and
  section roles are rejected instead of guessed.
- Proprietary `GPUTrace.*` UI formulas are not reimplemented, except the
  `GPUTrace.PCSampler` warp weighting of PC samples.
- Opaque bytes without a documented inner format are inventoried and exported,
  not interpreted speculatively.
- PC sample attribution is validated on Vulkan/SPIR-V captures from Ada GPUs.
  SASS is reported as raw encodings with instruction mix classes, without
  mnemonics. The class table covers the SM versions Nsight Graphics 2026.3.1
  classifies. The warp-weighted values match the export to two decimals; a
  single value can differ by 0.01 points.
- The analyzer reads completed captures; it does not launch applications or
  control Nsight capture sessions.

See [FORMAT.md](FORMAT.md) for the inferred WRPV v10 layout and [NOTICE](NOTICE)
for NVIDIA SDK and schema provenance.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked
```

## License

MIT. This is an independent project and is not affiliated with, sponsored by,
or endorsed by NVIDIA Corporation.
