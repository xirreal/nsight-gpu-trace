# Setup and Tools

`ngfx-trace` requires Rust 1.88 or newer and a matching NVIDIA Nsight Graphics
installation. Install the CLI from a checkout and register its read-only stdio
MCP server:

```sh
cargo install --path .
codex mcp add nsight-gpu-trace -- ngfx-trace mcp
```

Restart the MCP client after registration. Prefer a pathless long-lived server
and use `open_capture` to replace the active trace. An optional trace argument
can make one capture active at startup: `ngfx-trace mcp capture.ngfx-gputrace`.

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
| `open_capture` | Open or replace the active `.ngfx-gputrace` |
| `capture_overview` | Check workload, frames, scopes, timing, artifacts, and counter metadata |
| `list_metrics` | Discover PerfWorks metric bases by regex and kind |
| `describe_metric` | Confirm an exact name, suffix, unit, and dependencies |
| `scan_metrics` | Find which matching metric bases were collected |
| `list_scopes` | Resolve bounded stable IDs for markers, frames, actions, and buckets |
| `inspect_scope` | Read calls and timing evidence supporting one scope |
| `query_metrics` | Evaluate exact names over one scope and optionally return a bounded series |
| `rank_scopes` | Rank scopes with one metric evaluation; shared-bucket actions stay grouped |
| `top_down_report` | Run compact heuristic triage over collected metrics |
| `trace_schema`, `trace_query` | Discover and inspect uncommon dynamic protobuf fields |

Start with `open_capture` and `capture_overview`. Discover metric names from the
capture, resolve named work to stable scope IDs, and request sample series only
when temporal shape matters.
