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

## Confidence and unknowns

Confirmed on all six samples:

- the v10 file/section/chunk headers and LZ4 mode;
- section concatenation and exact uncompressed sizes;
- the section 0 protobuf type and descriptor source;
- section 1 as one valid PerfWorks periodic counter image.
- arbitrary named metric evaluation and complete catalog scanning.

Not yet established:

- compatibility with WRPV versions other than 10;
- official names or broader meanings of the section flag fields;
- other compression identifiers or section roles;
- the full set of proprietary `GPUTrace.*` formulas behind every UI row;
- opaque shader and hardware sampling record layouts not described by protobuf.

The parser rejects unvalidated WRPV versions instead of assuming the v10
layout. It also retains unknown protobuf fields when `trace.pb` is extracted,
allowing future schema work without lossy conversion.
