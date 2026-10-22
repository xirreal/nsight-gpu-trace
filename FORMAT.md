# WRPV version 10 format notes

These notes describe the WRPV v10 `.ngfx-gputrace` captures examined during
development.
All integers are little-endian. Sizes and flag meanings were checked against
the installed Nsight Graphics 2026.3 producer. Names for the two section flag
fields remain inferred, so the analyzer preserves their raw values.

## File header

| Offset | Type | Observed value | Meaning |
|---:|---|---:|---|
| `0x00` | `char[4]` | `WRPV` | File magic |
| `0x04` | `u32` | `10` | Container version |

One or more sections follow immediately and continue to end of file. There is
no observed file-level section count or table of contents.

## Section

Each section begins with 24 bytes (`<HHHHIIQ`):

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u16` | Section magic, `0x1234` |
| `0x02` | `u16` | Unknown flag A |
| `0x04` | `u16` | Unknown flag B |
| `0x06` | `u16` | Reserved, observed `0` |
| `0x08` | `u32` | Chunk count |
| `0x0c` | `u32` | Reserved, observed `0` |
| `0x10` | `u64` | Total uncompressed section size |

Observed section roles are:

| Flag A | Flag B | Payload |
|---:|---:|---|
| `1` | `0` | Serialized `NV.WarpViz.PbTraceData` protobuf |
| `0` | `1` | NVIDIA PerfWorks counter-data image (`LOPDATA\0`) |

## Chunk

The section header is followed by `chunk_count` inline chunk records. Each
record has a 24-byte header (`<HHIQQ`) followed immediately by its stored data:

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u16` | Chunk magic, `0x4321` |
| `0x02` | `u16` | Compression: `0` stored, `1` raw LZ4 block |
| `0x04` | `u32` | Reserved, observed `0` |
| `0x08` | `u64` | Stored byte count |
| `0x10` | `u64` | Uncompressed byte count |
| `0x18` | bytes | Stored payload |

The uncompressed sizes of all chunks must sum to the section's declared size.
Decompressed chunks are concatenated in record order to reconstruct a section.
In particular, the 35 chunks in each large section 1 form one PerfWorks image;
they are not independent `LOPDATA` images.

## Protobuf trace

Section 0 decodes as `NV.WarpViz.PbTraceData`. Nsight's WarpViz plugin contains
complete serialized `FileDescriptorProto` records, including `WarpViz.proto`,
shader profiler messages, and graphics event parameters. `TraceDocument` extracts
those descriptors at runtime and builds a dynamic protobuf descriptor pool.

Observed trace content includes:

- system/session information tables and process metadata;
- devices, command queues, command streams, API calls, and typed arguments;
- timestamp boundaries keyed by `NextCallIndex` and pipeline stage;
- swapchains, presented/application frames, and screenshots;
- NVTX, pipeline, semaphore, FECS, and hardware-event records;
- shader-profiler tables and compressed blobs;
- per-SM PC sampling storage and counter-data prefixes.

`NextCallIndex` partitions a command stream. The elapsed PTIMER value between
two adjacent boundaries applies to calls in `[previous.NextCallIndex,
current.NextCallIndex)`. The first boundary provides no start time for calls
before it.

## PerfWorks counter data

Section 1 begins with `LOPDATA\0` after concatenation and decompression. The
matching Nsight 2026.3 PerfWorks host library accepts it as a periodic-sampler
counter-data image. Across the samples it reports chip name `GB203`, populated
range counts from hundreds to tens of thousands, and complete ranges.

The following metadata is decoded through public PerfWorks entry points rather
than by treating internal offsets as stable:

- chip name and total range count;
- periodic sampler total, populated, and completed ranges;
- per-range timestamps, trigger counts, completeness, and descriptions.

The matching graphics metrics evaluator also maps named counter, ratio, and
throughput requests to each range. `PerfWorks::evaluate` uses that API directly,
while `PerfWorks::scan` evaluates one canonical form of every selected metric
base in a single pass.

## Real-time shader profiler (PC sampling)

These notes were checked with Nsight Graphics 2026.3.1 on Windows against
Vulkan captures from an Ada GPU, with and without samples. Function addresses
refer to the 2026.3.1 Windows binaries so the findings can be re-checked
against later releases. Each item states whether it is established (code or
exact match with the UI) or inferred (consistent with the data but not traced
in code).

### Per-SM sample storage

`gpus[].SamplingData.PcSamplingPerSM[]` holds one entry per virtual SM
(`vsmid`, `version`). Captures without samples have no entries. All observed
entries have `version` 1.

`pcSamplesStorage` is a sequence of 16-byte records:

| Offset | Type | Meaning | Status |
|---:|---|---|---|
| `0x00` | `u64` | Sampled PC as a GPU virtual address | established |
| `0x08` | `u32` | Observed `0` | — |
| `0x0c` | `u8` | Warp slot; per shader the highest value is its warps per SM minus one | inferred |
| `0x0d` | `u8` | Sample type (hardware stall reason code), see below | established |
| `0x0e` | `u8` | Observed 0 or 1; `selected`/`not_selected` occur only with 0 | unknown |
| `0x0f` | `u8` | Observed `0` | — |

`timestampsStorage` is a sequence of 16-byte anchors `(u64 PTIMER, u64
cumulative sample index)`. Anchor `i` closes the samples
`[index[i-1], index[i])` of the same SM; the last index equals the record
count. Anchors are about 4 µs apart, and samples carry no individual
timestamps.

The anchor times coincide with the ends of the PerfWorks periodic counter
ranges. An SM apparently writes an anchor only for ranges in which it took
samples (inferred: gaps occur where the SM's shader work pauses).

#### Samples to counter ranges

WarpViz (`0x18013dab0`) assigns every sample to one counter range; this is
established from the code and from the exact UI total:

1. The samples before an SM's first anchor are dropped, unless no further
   anchor exists ("Keeping %zu pre-first-anchor PC samples …").
2. Each later anchor closes the counter range that ends at its time.
3. If an anchor's slot spans several ranges, its samples stay in the first
   range of the gap. Only among the last 3 samples (`0x1808a2838`, the same
   for every supported architecture) a sample and those after it move to the
   range after the anchor. That happens to the first one that is closer by PC
   to the next anchor's samples than to the current range's samples. The
   distance is `|Δpc| / 3` plus a large penalty when the PCs lie in different
   code blocks.

A time range such as the UI's trace range contains the samples whose counter
range overlaps it. This is established: it reproduces the UI's sample total
exactly, while interpolated sample times or anchor intervals do not. The union
of all anchor times serves as the range grid when the counter image is not at
hand. `ngfx-trace` selects samples for every time-based scope this way, so a
scope boundary inside a range takes the whole range.

### Sample type codes

`WarpVizPlugin.dll` (`0x1800b4680`, switch at `0x1800b470c`) selects a code
table by `gpus[].gpuType.Arch`. Each entry is a
`smsp__pcsamp_warps_issue_stalled_<name>` metric name; the code is the table
index.

| Code | `Arch` 0x170, 0x190 | `Arch` 0x1A0, 0x1B0 |
|---:|---|---|
| 0 | misc | misc |
| 1 | drain | drain |
| 2 | imc_miss | barrier |
| 3 | barrier | membar |
| 4 | membar | sleeping |
| 5 | sleeping | branch_resolving |
| 6 | branch_resolving | wait |
| 7 | wait | long_scoreboard (RT core) |
| 8 | long_scoreboard (RT core) | long_scoreboard (L1TEX) |
| 9 | long_scoreboard (L1TEX) | short_scoreboard |
| 10 | short_scoreboard | no_instructions |
| 11 | no_instructions | math_pipe_throttle |
| 12 | math_pipe_throttle | tex_throttle |
| 13 | tex_throttle | mio_throttle (RT core) |
| 14 | mio_throttle (RT core) | lg_throttle |
| 15 | lg_throttle | mio_throttle (MIO) |
| 16 | mio_throttle (MIO) | dispatch_stall |
| 17 | dispatch_stall | selected |
| 18 | selected | not_selected |
| 19 | not_selected | misc |
| 20 | misc | — |

Any other architecture gets the single entry `misc`. The tables name both
long-scoreboard and both MIO-throttle codes identically. The pipe split is
inferred from the auto-exported `GPUTrace.PCSampler.tpc__warps_issue_stalled_*`
rows, which appear exactly in code order 1–20 and report zero for both RT-core
variants, matching codes 8 and 14 never occurring in a compute-only capture.
Ada GPUs report `Arch` 400 (0x190) and use the first table.

### Exported warp metrics (`GPUTrace.PCSampler`)

The GPU Trace export reports stall reasons and shaders as
`GPUTrace.PCSampler.tpc__warps_issue_stalled_<reason>` and
`…tpc__warps_active_shader_node_main_<hash>`. These are not sample shares but
warps per cycle: the samples are weighted by the active warps that the
periodic counters measured. `PCSamplerMetricsEvaluator` in `WarpVizPlugin.dll`
computes them (established from code; values match the export):

- For every counter range, WarpViz evaluates two metrics per TPC instance
  through `NVPW_MetricsEvaluator_EvaluateToInstanceValues` (`0x180142180`):
  - `tpc__cycles_elapsed.avg`;
  - `GPUTrace.tpc__warps_active_realtime.avg`, defined in the plugin
    (`0x180002560`) as `tpc__warps_active_shader_vtg_realtime +
    tpc__warps_active_shader_ps_realtime +
    tpc__warps_active_shader_cs_queue_sync_realtime +
    tpc__warps_active_shader_cs_queue_async_realtime` with peak 96.

  The host library does not export the instance function by name. WarpViz
  gets a resolver from `NVPA_GetProcAddress("1111")` and looks up the names
  through it (`0x180151a40`).
- The SM streams are sorted by `gpus[].gpuType.VsmMappings`
  (`gpcPhysicalIndex`, `tpcPhysicalIndexInGpc`, `smPhysicalIndexInTpc`;
  `0x18013d300`). Position `p` in that order belongs to TPC instance `p / 2`.
  For Ampere, Ada, and Blackwell the plugin uses 2 SMs per TPC and 96 warps per
  TPC.
- In `0x18014fc20`, for counter range `r` and SM `s` with `n` samples in `r`,
  every sample of `s` gets the weight
  `min(warps[tpc(s)], 96 · cycles[tpc(s)]) / n / SM count`. Weights are summed
  per sample type (`code − 1` indexes the reason list), per shader type, and
  per shader hash. Samples outside known code blocks count as
  `…_unattributed`.
- The metric set's "Avg Warps" sub-metric is
  `.avg.per_cycle_elapsed` × 0.5 (per SM); "Occupancy %" is that value over
  48 warps. A range that only partly overlaps the reported range counts by its
  time overlap.

The metric set is stored in `gpus[].SamplingData.MetricSetAsString`
(`Obfuscated: true`). Its `Data` is base64 text XORed byte by byte with
`0x55`; it decodes to YAML with the metric definitions, sub-metric suffixes,
and multipliers.

`ngfx-trace pc-samples summary --warp-weighted` computes the values this way
and matches the export to two decimals. A single value can still differ by
0.01 percentage points; the cause is not established, and the PC lookup in the
gap split (time-dependent in WarpViz) is a candidate.

Raw sample shares are no substitute. Every active SM is sampled at the same
rate however many warps it holds, so a shader limited to few warps per SM
holds a much larger share of the samples than of the warps.

### Shader profiler blobs

`devices[].ShaderProfilerReport.blobTable.blobs[]` entries are referenced by
index (`PbBlobRef.idx`). `ShaderProfilerPlugin.dll` unpacks an entry in this
order (established, `0x1800645e0`):

1. `COMPRESSION_LZ4`: the data is one raw LZ4 block that expands to exactly
   `uncompressedSize` bytes (`0x1800502d0`).
2. `OBFUSCATION_SIMPLE`: the decompressed bytes are XORed with a ChaCha20
   keystream (`0x180316320`): original 20-round variant with constants
   `expand 32-byte k`, 64-bit block counter starting at 0, 64-bit nonce of
   zero bytes, and a fixed 32-byte key stored in `.rdata` of
   `ShaderProfilerPlugin.dll`, `WarpVizPlugin.dll` and
   `PylonGpuTraceFusionPlugin.dll`.

`ngfx-trace` does not ship the key. It tries every 4-byte aligned 32-byte
window of the schema binary as a key and keeps the one whose keystream turns
the first bytes of the capture's SPIR-V and cubin blobs into their known
headers.

All blobs of every examined capture unpack this way. Their contents:

| Reference | Content |
|---|---|
| `modules[].graphicsAPIModule.bytecode` | SPIR-V module as passed to the driver (`ILBytecodeType_SPIRV`) |
| `codeBlocks[].shaderInstance.instructions` | Raw SASS of the code block, `vaRange.size` bytes, 16 bytes per instruction |
| `codeBlocks[].shaderInstance.debugInfo.ref` | CUDA cubin (ELF64, machine 190, OS ABI 0x33) |

The cubin contains the same SASS in `.text.<function>`, plus `.debug_line`
(DWARF 2), `.debug_info` (producer `SPIRV Compiler`), `.nv.info` and constant
bank sections.

### Code block to module and source line

Each cubin's `.debug_line` has one include directory of
`"`-separated `key>value` pairs, for example
`./"stage>cs"fmt>spir"ShaderModuleHash>36cf63efe2e621e`, and one file such as
`comp.10000.spv`. Nsight parses the pairs and reads `ShaderModuleHash` as hex
(`0x1801b74b0`).

`ShaderModuleHash` is Bob Jenkins' 64-bit `lookup8` hash (initial level 0)
over the unpacked SPIR-V bytes (`0x180238470`). For all twelve distinct
modules of the examined captures the hash equals the value in the cubin, and
for the capture with samples it also equals the shader hash shown in the UI.
This is the only link from a code block to its module; the protobuf has no
module index.

The line program maps SASS offsets (relative to `vaRange.address`) to a
"line" in the virtual `.spv` file. That line is the zero-based index of a
SPIR-V instruction plus 6, i.e. the line in a `spirv-dis` listing with a
five-line header (inferred: at this offset every mapped line in four checked
modules lands on a non-debug instruction; at any other offset 30–115 lines
land on `OpLine`, `OpLabel` or similar). The source file and line then come
from the SPIR-V `OpLine` in effect for that instruction.

Unlike the SPIR-V rule, Nsight keeps that line across `OpNoLine` and `OpLabel`
until the next `OpLine` or `OpFunctionEnd`. This is inferred from UI values:
the UI counts samples on instructions after `OpNoLine` or `OpLabel` for the
preceding line. With this rule, line and per-instruction shares match the UI's
source view and hotspot table to 0.01 percentage points.

The UI's hotspot table and source view count every code block, i.e. every
pipeline, on its own (established by exact match). A source line that two
pipelines of one module share appears once per pipeline.

The instruction columns of the source view count every SASS instruction of the
code block mapped to the line, sampled or not, in total and per instruction
mix class. The per-line stall columns are plain sample shares of the line.
Both are established by exact match.

For `NonSemantic.Shader.DebugInfo.100` modules (`glslang -gVS`) `ngfx-trace`
uses `DebugLine`, `DebugSource`, and `DebugCompilationUnit` the same way. The
Nsight UI does not use this debug information, so this path has no UI
reference.

The UI's own SPIR-V listing numbers lines differently from index + 6; it
apparently also counts embedded source text.

### Instruction mix

`ShaderProfilerPlugin.dll` classifies every SASS instruction itself
(`0x1800b6250`); neither `NvSD.dll` nor the capture stores a class
(established):

- The key is the 12-bit opcode plus instruction bit 91:
  `((word2 >> 15) & 0x1000) | (word0 & 0xfff)` over the little-endian 32-bit
  words of the 128-bit instruction.
- `codeBlocks[].shaderInstance.commonProgramMeta.cudaSmVersion` selects one
  function per generation (`0x180064510`): 0x70005 → `0x1800af6f0`,
  0x80006–0x80009 → `0x1800b2530`, 0xb0000 → `0x1800a9240`, 0xc0000 and
  0xc0001 → `0x1800ac420`. Other versions, such as 0x80000, 0x90000 and
  0xa0000, get no class.
- Each function maps the key to an instruction ID and reads byte tables for
  family, operation and pipe; the pipe table differs per SM version. An
  all-zero class counts as "no category".
- The UI names a class as pipe, family and operation, for example
  `LSU Shared Memory Load`.

| Code | Pipe | Family | Operation |
|---:|---|---|---|
| 1–10 | ADU, ALU, CBU, FMA, FP16, FP64, IPA, LDCU, LSU, REDUX | Bit Manipulation, Constant Memory, Control Flow, Data Movement, FP16 Comparison, FP16 Math, FP32 Comparison, FP32 Logic, FP32 Math, FP32 Rounding | Async Memcpy, Atomic, Bitwise, Branch, Breakpoint, Cache Control, Call, DEPBAR, Discard, ERRBAR |
| 11–20 | RTCORE, SCH, SYNCS, TEX, TMA, TMEM, Tensor, UDP, WORKID, XU | FP64 Comparison, FP64 Conversion, FP64 Math, FP64 Rounding, Float Math, Float-To-Float, Float-To-Int, Generic Memory, Global Memory, Int-To-Float | Exit, FP!64->FP!64, FP!64->FP64, FP->INT!64, FP->INT64, FP16, FP32->INT8, FP4, FP64, FP8 |
| 21–30 | — | Integer Arithmetic, Integer Comparison, Integer Multiply/Add, Local Memory, Logic Operation, Multicast Memory, NOP, PS Attribute, Performance Monitor, Ray Tracing | Fetch, Fetch w/ Derivatives, Global MEMBAR, INT, INT->FP!64, INT->FP64, INT->INT, INT32->FP32, LDGDEPBAR, LOD |
| 31–40 | — | Resource Control, Scalar Constant, Shared Memory, Special Function, Special Register, Surface, Sync. Barrier, Tensor, Tensor Descriptor, Tensor Memory | Load, Load 4, MEMBAR, NANOSLEEP, Prefetch, Program Start, Query, Register, Return, SIMT |
| 41–50 | — | Texture, Texture Memory, Uniform Constant, VTG Attribute, Vector Constant, Warp-Level Primitive | Shared MEMBAR, Shared Memory, Special, Store, TMA, TMA Memcpy, TMA Prefetch, TMA Reduction, Virtual Resource |

`tools/generate_sass_classes.py` calls the four functions of the 2026.3.1
plugin for all 8192 keys and writes `src/sass_classes.rs` (847 keys, eight SM
versions). The resulting instruction mix matches the UI to 0.01 percentage
points, both overall and per source line.

## Confidence and unknowns

Confirmed on all six samples:

- the v10 file/section/chunk headers and LZ4 mode;
- section concatenation and exact uncompressed sizes;
- the section 0 protobuf type and descriptor source;
- section 1 as one valid PerfWorks periodic counter image.
- arbitrary named metric evaluation and complete catalog scanning.

Confirmed on the three Vulkan captures from Nsight Graphics 2026.3.1:

- the shader profiler blob encoding (LZ4 block, then ChaCha20) and the
  SPIR-V/SASS/cubin blob contents;
- `ShaderModuleHash` as `lookup8` over the SPIR-V module;
- the 16-byte PC sample and timestamp anchor records (one capture with
  samples);
- the per-architecture sample type tables in the 2026.3.1 WarpViz plugin;
- the SASS instruction mix classification of the 2026.3.1 shader profiler;
- WarpViz's sample-to-counter-range assignment and its `GPUTrace.PCSampler`
  warp weighting (one capture with samples).

Not yet established:

- compatibility with WRPV versions other than 10;
- official names or broader meanings of the section flag fields;
- other compression identifiers or section roles;
- the full set of proprietary `GPUTrace.*` formulas behind every UI row;
- the meaning of PC sample byte `0x0e`;
- the cause of single 0.01-point differences in the exported warp weighting;
- the UI's SPIR-V line numbering;
- SASS mnemonics (the instruction mix classes need none);
- PC sampling on architectures other than Ada and on D3D12 or OpenGL.

The parser rejects unvalidated WRPV versions instead of assuming the v10
layout. It also retains unknown protobuf fields when `trace.pb` is extracted,
allowing future schema work without lossy conversion.
