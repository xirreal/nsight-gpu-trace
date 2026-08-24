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
| `analyze_capture` | Run bounded one-shot identity, workload, timing, counter, complete metric-scan, diagnostic, fallback-region, and manifest analysis |
| `query_capture` | Execute a bounded batch of typed follow-up queries against one freshly opened capture |

`analyze_capture` accepts `capture`, optional `scope_pattern`, optional
`metric_patterns` or exact `metrics`, and `top`. Regex metric selectors are
matched against collected canonical metrics and evaluated in that call.

`query_capture` accepts `capture` and one to 16 query objects. Available query
types are `container_info`, `calls`, `timings`, `scopes`, `counter_samples`,
`metric_discovery`, `metric_evaluation`, `trace_schema`, `trace_query`,
`artifact_inventory`, and `artifact_read`. `metric_discovery` lists by regex or
describes one exact metric; `metric_evaluation` accepts exact names, regexes, or
both. Calls omit arguments and metric evaluations omit samples unless requested.
Artifact reads are hex encoded and limited to 16 KiB per query. Use each query's
offset for stateless paging.

Use CLI `json`, `extract`, `section`, and `unpack` for complete protobuf or
multi-megabyte binary output.
