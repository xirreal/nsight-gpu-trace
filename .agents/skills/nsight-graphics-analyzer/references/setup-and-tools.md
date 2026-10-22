# Setup and Tools

`ngfx-trace` requires Rust 1.88 or newer and a matching NVIDIA Nsight Graphics
installation. Install the CLI from a checkout and register its read-only stdio
MCP server:

```sh
cargo install --path .
codex mcp add nsight-gpu-trace -- ngfx-trace mcp
```

Restart the MCP client after registration. The long-lived server is stateless;
every tool call supplies a capture path and owns its analysis for that call.

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
| `analyze_capture` | Run bounded one-shot identity, workload, timing, counter, complete metric-scan, diagnostic, fallback-region, manifest, and PC sampling analysis |
| `query_capture` | Execute a bounded batch of typed follow-up queries against one freshly opened capture |

`analyze_capture` accepts `capture`, optional `scope_pattern`, optional
`metric_patterns` or exact `metrics`, and `top`. Regex metric selectors are
matched against collected canonical metrics and evaluated in that call.

`query_capture` accepts `capture` and one to 16 query objects. Available query
types are `container_info`, `calls`, `timings`, `scopes`, `counter_samples`,
`metric_discovery`, `metric_evaluation`, `trace_schema`, `trace_query`,
`artifact_inventory`, `artifact_read`, and `pc_sampling`. `metric_discovery`
lists by regex or describes one exact metric; `metric_evaluation` accepts exact
names, regexes, or both. Calls omit arguments and metric evaluations omit
samples unless requested. Artifact reads are hex encoded and limited to 16 KiB
per query. Use each query's offset for stateless paging.

`pc_sampling` reads Real-Time Shader Profiler samples:

- `view` is `summary`, `shaders`, `hotspots`, or `records`. `scope` takes the
  same scope IDs and ranges as the other queries.
- A time-based scope selects the samples whose counter range, assigned as in
  Nsight, overlaps it. A `frame:presented:…` scope therefore reproduces the
  UI's sample total and percentages.
- `hotspots` ranks source lines per pipeline (`group_by: "line"`), SPIR-V
  instructions (`"instruction"`), or SASS instructions (`"sass"`), optionally
  filtered by `shader_pattern`. Each row lists sample types, instruction mix,
  and SASS instruction counts.
- `summary` with `warp_weighted: true` adds stall reasons and shaders as average
  warps and percent of SM warp slots, the `GPUTrace.PCSampler` values of the
  GPU Trace export. It evaluates per-TPC counters through PerfWorks.

The CLI offers the same views as `ngfx-trace pc-samples summary|shaders|hotspots|records`
(`--warp-weighted` for the summary).

Use CLI `json`, `extract`, `section`, and `unpack` for complete protobuf or
multi-megabyte binary output.
