//! Real-time shader profiler PC samples: per-SM records, sample type tables,
//! anchor-interpolated timestamps, and attribution to shaders, SASS, SPIR-V,
//! and source lines through [`ShaderProfile`].

use std::collections::{BTreeMap, HashMap};

use regex::Regex;
use serde::Serialize;

use crate::{
    Error, Result, Scope, ScopeKind, TraceDocument,
    analysis::{message_items, optional_bytes, optional_message, optional_string, optional_u64},
    shader_profiler::{
        CodeBlock, InstructionClass, SPIRV_FIRST_INSTRUCTION_LINE, ShaderProfile, file_basename,
        format_hash,
    },
};

const RECORD_SIZE: usize = 16;
const ANCHOR_SIZE: usize = 16;
const SUPPORTED_STORAGE_VERSION: u64 = 1;
/// Samples carry no individual timestamps. Like Nsight, every sample belongs to
/// the periodic counter range its anchors assign it to, and a time scope
/// selects the samples whose range overlaps it. A record reports the midpoint
/// of its slot between the enclosing anchors.
pub const TIME_ATTRIBUTION: &str = "counter_range_overlap_with_midpoint_time";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleKind {
    Stalled,
    Issued,
    Eligible,
    Unknown,
}

/// One hardware sample type (stall reason) code.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SampleType {
    pub code: u8,
    /// Suffix of the exported `tpc__warps_issue_stalled_*` metric.
    pub name: &'static str,
    pub label: &'static str,
    pub kind: SampleKind,
}

const fn stalled(code: u8, name: &'static str, label: &'static str) -> SampleType {
    SampleType {
        code,
        name,
        label,
        kind: SampleKind::Stalled,
    }
}

const SELECTED: &str = "selected";
const NOT_SELECTED: &str = "not_selected";

/// WarpViz table for `gpuType.Arch` 0x170 (Ampere) and 0x190 (Ada).
const AMPERE_ADA_TYPES: [SampleType; 21] = [
    stalled(0, "misc", "Miscellaneous"),
    stalled(1, "drain", "Drain"),
    stalled(2, "imc_miss", "IMC Miss"),
    stalled(3, "barrier", "Barrier"),
    stalled(4, "membar", "Memory Barrier"),
    stalled(5, "sleeping", "Sleeping"),
    stalled(6, "branch_resolving", "Branch Resolving"),
    stalled(7, "wait", "Wait"),
    stalled(
        8,
        "long_scoreboard_pipe_rtcore",
        "Long Scoreboard (RT Core)",
    ),
    stalled(9, "long_scoreboard_pipe_l1tex", "Long Scoreboard (L1TEX)"),
    stalled(10, "short_scoreboard", "Short Scoreboard"),
    stalled(11, "no_instruction", "No Instruction"),
    stalled(12, "math_pipe_throttle", "Math Pipe Throttle"),
    stalled(13, "tex_throttle", "Texture Throttle"),
    stalled(14, "mio_throttle_pipe_rtcore", "MIO Throttle (RT Core)"),
    stalled(15, "lg_throttle", "LG Throttle"),
    stalled(16, "mio_throttle_pipe_mio", "MIO Throttle"),
    stalled(17, "dispatch_stall", "Dispatch Stall"),
    SampleType {
        code: 18,
        name: SELECTED,
        label: "Selected",
        kind: SampleKind::Issued,
    },
    SampleType {
        code: 19,
        name: NOT_SELECTED,
        label: "Not Selected",
        kind: SampleKind::Eligible,
    },
    stalled(20, "misc", "Miscellaneous"),
];

/// WarpViz table for `gpuType.Arch` 0x1A0 and 0x1B0 (Blackwell).
const BLACKWELL_TYPES: [SampleType; 20] = [
    stalled(0, "misc", "Miscellaneous"),
    stalled(1, "drain", "Drain"),
    stalled(2, "barrier", "Barrier"),
    stalled(3, "membar", "Memory Barrier"),
    stalled(4, "sleeping", "Sleeping"),
    stalled(5, "branch_resolving", "Branch Resolving"),
    stalled(6, "wait", "Wait"),
    stalled(
        7,
        "long_scoreboard_pipe_rtcore",
        "Long Scoreboard (RT Core)",
    ),
    stalled(8, "long_scoreboard_pipe_l1tex", "Long Scoreboard (L1TEX)"),
    stalled(9, "short_scoreboard", "Short Scoreboard"),
    stalled(10, "no_instruction", "No Instruction"),
    stalled(11, "math_pipe_throttle", "Math Pipe Throttle"),
    stalled(12, "tex_throttle", "Texture Throttle"),
    stalled(13, "mio_throttle_pipe_rtcore", "MIO Throttle (RT Core)"),
    stalled(14, "lg_throttle", "LG Throttle"),
    stalled(15, "mio_throttle_pipe_mio", "MIO Throttle"),
    stalled(16, "dispatch_stall", "Dispatch Stall"),
    SampleType {
        code: 17,
        name: SELECTED,
        label: "Selected",
        kind: SampleKind::Issued,
    },
    SampleType {
        code: 18,
        name: NOT_SELECTED,
        label: "Not Selected",
        kind: SampleKind::Eligible,
    },
    stalled(19, "misc", "Miscellaneous"),
];

/// Select the sample type table WarpViz uses for an architecture ID.
pub fn sample_type_table(arch: u64) -> Option<(&'static str, &'static [SampleType])> {
    match arch {
        0x170 => Some(("ampere", &AMPERE_ADA_TYPES)),
        0x190 => Some(("ada", &AMPERE_ADA_TYPES)),
        0x1a0 | 0x1b0 => Some(("blackwell", &BLACKWELL_TYPES)),
        _ => None,
    }
}

/// One decoded 16-byte PC sample record.
#[derive(Debug, Clone, Copy)]
pub struct PcSample {
    pub gpu_index: u16,
    pub vsmid: u32,
    pub pc: u64,
    pub time_ns: Option<u64>,
    /// PTIMER start and end of the periodic counter range Nsight assigns the
    /// sample to; `None` before the SM's first anchor (Nsight drops those).
    pub counter_range: Option<(u64, u64)>,
    /// Byte `0x0c`, 0-47 on Ada; probably the warp slot (not established).
    pub warp_slot: u8,
    pub sample_type: u8,
    /// Byte `0x0e`, observed 0 or 1 (meaning not established).
    pub flag: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmStream {
    pub gpu_index: usize,
    pub vsmid: u32,
    pub version: Option<u64>,
    pub records: usize,
    pub anchors: usize,
    pub dropped_storage_bytes: usize,
    pub first_ptimer: Option<u64>,
    pub last_ptimer: Option<u64>,
    #[serde(skip)]
    anchor_list: Vec<(u64, usize)>,
    /// Index of the stream's first record in the decoded sample list.
    #[serde(skip)]
    first_sample: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuSamplingInfo {
    pub gpu_index: usize,
    pub arch: Option<u64>,
    pub implementation: Option<u64>,
    pub chip_name: Option<String>,
    pub sampling_interval: Option<u64>,
    pub sample_type_table: Option<&'static str>,
    /// Virtual SM IDs ordered by physical GPC, TPC, and SM index
    /// (`gpuType.VsmMappings`), the order of the hardware counter instances.
    #[serde(skip)]
    physical_order: Vec<u32>,
}

/// All PC samples of a trace plus the shader tables needed to attribute them.
#[derive(Debug, Clone)]
pub struct PcSampling {
    pub gpus: Vec<GpuSamplingInfo>,
    pub streams: Vec<SmStream>,
    samples: Vec<PcSample>,
    sample_types: &'static [SampleType],
    profile: ShaderProfile,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampleTypeCount {
    pub code: u8,
    pub name: String,
    pub label: String,
    pub kind: SampleKind,
    pub samples: usize,
    pub share_pct: f64,
}

/// Samples of one instruction mix class; `None` fields mark unclassified samples.
#[derive(Debug, Clone, Serialize)]
pub struct InstructionClassCount {
    pub label: String,
    pub pipe: Option<&'static str>,
    pub family: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<&'static str>,
    pub samples: usize,
    pub share_pct: f64,
    /// SASS instructions of this class in the hotspot, sampled or not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionCounts {
    pub in_code_blocks: usize,
    pub outside_code_blocks: usize,
    pub with_spirv_instruction: usize,
    pub with_source_line: usize,
    pub with_instruction_class: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShaderSamples {
    pub shader: String,
    pub hash: Option<String>,
    pub code_blocks: Vec<usize>,
    pub samples: usize,
    pub share_pct: f64,
    pub sample_types: Vec<SampleTypeCount>,
    pub instruction_mix: Vec<InstructionClassCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcSamplingSummary {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<&'static str>,
    pub gpus: Vec<GpuSamplingInfo>,
    pub records: usize,
    pub sm_streams: usize,
    pub anchors: usize,
    pub scope: Scope,
    pub selected_samples: usize,
    pub untimed_samples_excluded: usize,
    pub attribution: AttributionCounts,
    pub sample_types: Vec<SampleTypeCount>,
    pub instruction_mix: Vec<InstructionClassCount>,
    pub shaders: Vec<ShaderSamples>,
    pub time_attribution: &'static str,
    pub exact_per_sample_timestamps: bool,
    pub warnings: Vec<String>,
}

/// Periodic counter read per TPC instance as the elapsed cycles of each range.
pub const TPC_CYCLES_METRIC: &str = "tpc__cycles_elapsed.avg";
/// Summed per TPC instance to Nsight's `GPUTrace.tpc__warps_active_realtime`
/// (vtg + ps + cs warps in flight).
pub const TPC_ACTIVE_WARP_METRICS: [&str; 3] = [
    "tpc__warps_active_shader_vtg_realtime.avg",
    "tpc__warps_active_shader_ps_realtime.avg",
    "tpc__warps_active_shader_cs_realtime.avg",
];

/// Per-TPC counter values of one periodic counter range.
#[derive(Debug, Clone)]
pub struct TpcCounterRange {
    pub range_index: usize,
    pub start_ns: u64,
    pub end_ns: u64,
    /// [`TPC_CYCLES_METRIC`] per TPC instance; NaN when unavailable.
    pub cycles: Vec<f64>,
    /// Sum of [`TPC_ACTIVE_WARP_METRICS`] per TPC instance.
    pub active_warps: Vec<f64>,
}

/// One stall reason or shader of [`WarpWeightedSummary`].
#[derive(Debug, Clone, Serialize)]
pub struct WarpWeightedCount {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Warps per SM and elapsed cycle (Nsight's "Avg Warps").
    pub avg_warps: f64,
    /// Percent of the SM's warp slots (Nsight's "Occupancy %").
    pub pct_of_peak: f64,
    /// Percent of all weighted warps.
    pub share_pct: f64,
}

/// Nsight's `GPUTrace.PCSampler` warp metrics, the stall and shader values of
/// the GPU Trace export.
#[derive(Debug, Clone, Serialize)]
pub struct WarpWeightedSummary {
    pub scope: Scope,
    pub basis: &'static str,
    pub counter_ranges: usize,
    pub peak_warps_per_sm: f64,
    /// Warps attributed to a shader (`tpc__warps_active_shader_<type>`).
    pub attributed_avg_warps: f64,
    /// Warps of samples outside every code block.
    pub unattributed_avg_warps: f64,
    pub sample_types: Vec<WarpWeightedCount>,
    pub shaders: Vec<WarpWeightedCount>,
    pub warnings: Vec<String>,
}

/// Hardware layout WarpViz assumes when it weights samples by counted warps.
#[derive(Debug, Clone, Copy)]
struct WarpLayout {
    sms_per_tpc: usize,
    max_warps_per_tpc: f64,
    /// Trailing samples of an anchor gap that may move to the next range.
    split_window: usize,
}

/// WarpViz 2026.3.1 uses the same layout for Ampere, Ada, and Blackwell and
/// rejects other architectures.
fn warp_layout(arch: u64) -> Option<WarpLayout> {
    matches!(arch, 0x170 | 0x190 | 0x1a0 | 0x1b0).then_some(WarpLayout {
        sms_per_tpc: 2,
        max_warps_per_tpc: 96.0,
        split_window: 3,
    })
}

const WARP_WEIGHTING_BASIS: &str = "counted active warps of each TPC and counter range, split equally over the TPC's SMs and then over each SM's samples in that range (Nsight GPUTrace.PCSampler)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HotspotGrouping {
    Line,
    Instruction,
    Sass,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hotspot {
    pub shader: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shader_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spirv_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spirv_listing_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spirv_instruction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_block: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sass_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sass_encoding: Option<String>,
    /// SASS instructions of the code block attributed to the hotspot, sampled or not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sass_instructions: Option<usize>,
    pub samples: usize,
    pub share_pct: f64,
    pub sample_types: Vec<SampleTypeCount>,
    pub instruction_mix: Vec<InstructionClassCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HotspotReport {
    pub group_by: HotspotGrouping,
    pub scope: Scope,
    pub selected_samples: usize,
    pub matching_samples: usize,
    pub hotspots: Vec<Hotspot>,
    pub share_basis: &'static str,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampleRecord {
    pub index: usize,
    pub gpu_index: u16,
    pub vsmid: u32,
    pub pc: u64,
    pub time_ns: Option<u64>,
    pub sample_type: u8,
    pub sample_type_name: String,
    pub warp_slot: u8,
    pub flag: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shader: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shader_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_block: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sass_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spirv_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// Per-group sample counts by sample type and instruction mix class.
struct GroupCounts {
    types: Box<[usize; 256]>,
    classes: HashMap<Option<InstructionClass>, usize>,
}

impl GroupCounts {
    fn new() -> Self {
        Self {
            types: Box::new([0; 256]),
            classes: HashMap::new(),
        }
    }

    fn add(&mut self, sample_type: u8, class: Option<InstructionClass>) {
        self.types[usize::from(sample_type)] += 1;
        *self.classes.entry(class).or_default() += 1;
    }

    fn total(&self) -> usize {
        self.types.iter().sum()
    }
}

/// Samples chosen by a scope, as indices into the decoded sample list.
struct Selection {
    scope: Scope,
    indices: Vec<usize>,
    untimed: usize,
    warnings: Vec<String>,
}

impl PcSampling {
    pub fn from_document(document: &TraceDocument) -> Result<Self> {
        let mut gpus = Vec::new();
        let mut streams = Vec::new();
        let mut samples = Vec::new();
        let mut warnings = Vec::new();
        let mut sample_types: Option<&'static [SampleType]> = None;
        for (gpu_index, gpu) in message_items(document.message(), "gpus")?.enumerate() {
            let gpu_type = optional_message(gpu, "gpuType")?;
            let arch = gpu_type.and_then(|value| optional_u64(value, "Arch"));
            let table = arch.and_then(sample_type_table);
            let Some(sampling) = optional_message(gpu, "SamplingData")? else {
                continue;
            };
            let mut mappings = Vec::new();
            if let Some(gpu_type) = gpu_type {
                for mapping in message_items(gpu_type, "VsmMappings")? {
                    let index = |name| optional_u64(mapping, name).unwrap_or(0);
                    mappings.push((
                        index("gpcPhysicalIndex"),
                        index("tpcPhysicalIndexInGpc"),
                        index("smPhysicalIndexInTpc"),
                    ));
                }
            }
            gpus.push(GpuSamplingInfo {
                gpu_index,
                arch,
                implementation: gpu_type.and_then(|value| optional_u64(value, "Impl")),
                chip_name: optional_string(sampling, "ChipName"),
                sampling_interval: optional_u64(sampling, "pcSamplingInterval"),
                sample_type_table: table.map(|table| table.0),
                physical_order: physical_order(&mappings),
            });
            let per_sm: Vec<_> = message_items(sampling, "PcSamplingPerSM")?.collect();
            if per_sm.is_empty() {
                continue;
            }
            match table {
                Some((_, table)) if sample_types.is_none_or(|current| current.len() == table.len()) => {
                    sample_types = Some(table)
                }
                Some(_) => warnings.push(
                    "GPUs with different sample type tables; codes use the first GPU's table."
                        .into(),
                ),
                None => warnings.push(format!(
                    "GPU {gpu_index} architecture {} has no known sample type table; codes are reported without names.",
                    arch.map_or_else(|| "unknown".into(), |arch| format!("{arch:#x}"))
                )),
            }
            for stream in per_sm {
                let vsmid = optional_u64(stream, "vsmid").unwrap_or(0) as u32;
                let version = optional_u64(stream, "version");
                let records = optional_bytes(stream, "pcSamplesStorage").unwrap_or_default();
                let timestamps = optional_bytes(stream, "timestampsStorage").unwrap_or_default();
                let dropped =
                    optional_bytes(stream, "droppedPcSamplesStorage").map_or(0, <[u8]>::len);
                let mut info = SmStream {
                    gpu_index,
                    vsmid,
                    version,
                    records: 0,
                    anchors: 0,
                    dropped_storage_bytes: dropped,
                    first_ptimer: None,
                    last_ptimer: None,
                    anchor_list: Vec::new(),
                    first_sample: samples.len(),
                };
                if version != Some(SUPPORTED_STORAGE_VERSION) {
                    warnings.push(format!(
                        "SM {vsmid} of GPU {gpu_index} uses unsupported PC sample storage version {version:?}; it was skipped."
                    ));
                    streams.push(info);
                    continue;
                }
                if !records.len().is_multiple_of(RECORD_SIZE) {
                    warnings.push(format!(
                        "SM {vsmid} of GPU {gpu_index} has {} sample bytes, not a multiple of {RECORD_SIZE}; it was skipped.",
                        records.len()
                    ));
                    streams.push(info);
                    continue;
                }
                let count = records.len() / RECORD_SIZE;
                let anchors = match decode_anchors(timestamps, count) {
                    Ok(anchors) => anchors,
                    Err(error) => {
                        warnings.push(format!(
                            "SM {vsmid} of GPU {gpu_index}: {error}; its samples have no time."
                        ));
                        Vec::new()
                    }
                };
                let times = sample_times(&anchors, count);
                if anchors.last().is_some_and(|anchor| anchor.1 != count) {
                    warnings.push(format!(
                        "SM {vsmid} of GPU {gpu_index}: anchors end before the last sample."
                    ));
                }
                info.records = count;
                info.anchors = anchors.len();
                info.first_ptimer = anchors.first().map(|anchor| anchor.0);
                info.last_ptimer = anchors.last().map(|anchor| anchor.0);
                info.anchor_list = anchors;
                for (record, time) in records.as_chunks::<RECORD_SIZE>().0.iter().zip(times) {
                    samples.push(PcSample {
                        gpu_index: gpu_index as u16,
                        vsmid,
                        pc: u64::from_le_bytes(record[..8].try_into().unwrap()),
                        time_ns: time,
                        counter_range: None,
                        warp_slot: record[12],
                        sample_type: record[13],
                        flag: record[14],
                    });
                }
                streams.push(info);
            }
        }
        let profile = ShaderProfile::from_document(document)?;
        assign_sample_counter_ranges(&gpus, &streams, &mut samples, &profile);
        if gpus
            .iter()
            .filter(|gpu| gpu.sample_type_table.is_some())
            .count()
            > 1
        {
            warnings.push("Several GPUs have PC samples; shader attribution assumes one shared address space.".into());
        }
        warnings.extend(profile.warnings.iter().cloned());
        Ok(Self {
            gpus,
            streams,
            samples,
            sample_types: sample_types.unwrap_or(&[]),
            profile,
            warnings,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Why the capture has no usable samples, or `None` when it has some.
    pub fn unavailable_reason(&self) -> Option<&'static str> {
        if !self.samples.is_empty() {
            None
        } else if self.streams.is_empty() {
            Some(
                "The capture contains no real-time shader profiler PC samples (gpus[].SamplingData.PcSamplingPerSM is empty); record with --real-time-shader-profiler.",
            )
        } else {
            Some("The capture's PC sample storage could not be decoded; see warnings.")
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn samples(&self) -> &[PcSample] {
        &self.samples
    }

    pub fn profile(&self) -> &ShaderProfile {
        &self.profile
    }

    pub fn sample_types(&self) -> &[SampleType] {
        self.sample_types
    }

    pub fn sample_type_name(&self, code: u8) -> String {
        self.sample_types
            .get(usize::from(code))
            .map_or_else(|| format!("unknown_{code}"), |entry| entry.name.to_owned())
    }

    pub fn summary(&self, scope: &Scope) -> Result<PcSamplingSummary> {
        let selection = self.select(scope)?;
        let total = selection.indices.len();
        let mut overall = GroupCounts::new();
        let mut attribution = AttributionCounts {
            in_code_blocks: 0,
            outside_code_blocks: 0,
            with_spirv_instruction: 0,
            with_source_line: 0,
            with_instruction_class: 0,
        };
        let mut shaders: BTreeMap<ShaderKey, (Vec<usize>, GroupCounts)> = BTreeMap::new();
        for index in &selection.indices {
            let sample = &self.samples[*index];
            let location = self.profile.locate(sample.pc);
            let class = location.and_then(|location| location.correlation.class);
            overall.add(sample.sample_type, class);
            let key = match location {
                Some(location) => {
                    attribution.in_code_blocks += 1;
                    if location.correlation.spirv_index.is_some() {
                        attribution.with_spirv_instruction += 1;
                    }
                    if location.correlation.location.is_some() {
                        attribution.with_source_line += 1;
                    }
                    if class.is_some() {
                        attribution.with_instruction_class += 1;
                    }
                    self.shader_key(location.code_block)
                }
                None => {
                    attribution.outside_code_blocks += 1;
                    ShaderKey::Unattributed
                }
            };
            let entry = shaders
                .entry(key)
                .or_insert_with(|| (Vec::new(), GroupCounts::new()));
            if let Some(location) = location
                && !entry.0.contains(&location.code_block)
            {
                entry.0.push(location.code_block);
            }
            entry.1.add(sample.sample_type, class);
        }
        let mut shader_rows: Vec<_> = shaders
            .into_iter()
            .map(|(key, (mut blocks, counts))| {
                blocks.sort_unstable();
                let samples = counts.total();
                ShaderSamples {
                    shader: self.shader_label(&key),
                    hash: key.hash(),
                    code_blocks: blocks
                        .iter()
                        .map(|block| self.profile.code_blocks[*block].index)
                        .collect(),
                    samples,
                    share_pct: share(samples, total),
                    sample_types: self.type_counts(&counts.types, samples),
                    instruction_mix: class_counts(&counts.classes, samples, None),
                }
            })
            .collect();
        shader_rows.sort_by_key(|row| std::cmp::Reverse(row.samples));
        let mut warnings = selection.warnings;
        warnings.extend(self.warnings.iter().cloned());
        Ok(PcSamplingSummary {
            available: !self.samples.is_empty(),
            unavailable_reason: self.unavailable_reason(),
            gpus: self.gpus.clone(),
            records: self.samples.len(),
            sm_streams: self
                .streams
                .iter()
                .filter(|stream| stream.records > 0)
                .count(),
            anchors: self.streams.iter().map(|stream| stream.anchors).sum(),
            scope: selection.scope,
            selected_samples: total,
            untimed_samples_excluded: selection.untimed,
            attribution,
            sample_types: self.type_counts(&overall.types, total),
            instruction_mix: class_counts(&overall.classes, total, None),
            shaders: shader_rows,
            time_attribution: TIME_ATTRIBUTION,
            exact_per_sample_timestamps: false,
            warnings,
        })
    }

    /// GPU whose samples the warp weighting uses, with its layout and the
    /// number of TPC counter instances it needs.
    fn warp_weighting_gpu(&self) -> Result<(&GpuSamplingInfo, WarpLayout, usize)> {
        let gpu = self
            .gpus
            .iter()
            .find(|gpu| {
                self.streams
                    .iter()
                    .any(|stream| stream.gpu_index == gpu.gpu_index && stream.records > 0)
            })
            .ok_or_else(|| Error::TracePath("the capture has no PC samples".into()))?;
        let layout = gpu.arch.and_then(warp_layout).ok_or_else(|| {
            Error::TracePath(format!(
                "Nsight defines no warp weighting for architecture {:?}",
                gpu.arch
            ))
        })?;
        let sms = self
            .streams
            .iter()
            .filter(|stream| stream.gpu_index == gpu.gpu_index)
            .count();
        Ok((gpu, layout, sms / layout.sms_per_tpc))
    }

    /// Number of TPC instances whose counters [`Self::warp_weighted`] needs.
    pub fn tpc_instances(&self) -> Result<usize> {
        Ok(self.warp_weighting_gpu()?.2)
    }

    /// Reproduce Nsight's `GPUTrace.PCSampler` warp metrics. For every
    /// counter range and SM, the counted active warps of the SM's TPC are
    /// divided by the SM count and spread evenly over the SM's samples in that
    /// range. Ranges that only partly overlap the scope count by their overlap.
    pub fn warp_weighted(
        &self,
        ranges: &[TpcCounterRange],
        scope: &Scope,
    ) -> Result<WarpWeightedSummary> {
        let (gpu, layout, instances) = self.warp_weighting_gpu()?;
        let mut warnings = Vec::new();
        let fractions: Vec<f64> = ranges
            .iter()
            .map(|range| {
                if range.start_ns == 0 || range.end_ns <= range.start_ns {
                    return 0.0;
                }
                match (scope.kind, scope.start_ns.zip(scope.end_ns)) {
                    (ScopeKind::Capture, _) => 1.0,
                    (ScopeKind::SampleRange, _) => {
                        let inside = scope
                            .sample_start
                            .is_none_or(|start| range.range_index >= start)
                            && scope
                                .sample_stop
                                .is_none_or(|stop| range.range_index < stop);
                        f64::from(u8::from(inside))
                    }
                    (_, Some((start, end))) => {
                        let overlap = range
                            .end_ns
                            .min(end)
                            .saturating_sub(range.start_ns.max(start));
                        overlap as f64 / (range.end_ns - range.start_ns) as f64
                    }
                    (_, None) => 0.0,
                }
            })
            .collect();
        let range_ends: Vec<u64> = ranges.iter().map(|range| range.end_ns).collect();
        let position: HashMap<u32, usize> = gpu
            .physical_order
            .iter()
            .enumerate()
            .map(|(position, vsmid)| (*vsmid, position))
            .collect();
        if position.is_empty() {
            warnings.push(
                "gpuType.VsmMappings is missing; TPCs are assumed in virtual SM order.".into(),
            );
        }
        let streams: Vec<_> = self
            .streams
            .iter()
            .filter(|stream| stream.gpu_index == gpu.gpu_index)
            .collect();
        let sm_count = streams.len() as f64;
        let finite = |value: f64| if value.is_finite() { value } else { 0.0 };

        let mut reasons = [0.0f64; 256];
        let mut shaders: BTreeMap<ShaderKey, f64> = BTreeMap::new();
        for stream in &streams {
            let samples = &self.samples[stream.first_sample..stream.first_sample + stream.records];
            let pcs: Vec<u64> = samples.iter().map(|sample| sample.pc).collect();
            let tpc = position
                .get(&stream.vsmid)
                .copied()
                .unwrap_or(stream.vsmid as usize)
                / layout.sms_per_tpc;
            if tpc >= instances {
                continue;
            }
            let assigned = assign_counter_ranges(
                &stream.anchor_list,
                &pcs,
                &range_ends,
                layout.split_window,
                |pc| self.profile.locate(pc).map(|location| location.code_block),
            );
            for (index, members) in assigned {
                let fraction = fractions[index];
                let range = &ranges[index];
                if fraction == 0.0 || members.is_empty() || tpc >= range.cycles.len() {
                    continue;
                }
                let cycles = finite(range.cycles[tpc]);
                let warps = finite(range.active_warps.get(tpc).copied().unwrap_or(f64::NAN))
                    .min(cycles * layout.max_warps_per_tpc);
                let weight = fraction * warps / members.len() as f64 / sm_count;
                for sample in &samples[members] {
                    if sample.sample_type > 0 {
                        reasons[usize::from(sample.sample_type)] += weight;
                    }
                    let key = self
                        .profile
                        .locate(sample.pc)
                        .map_or(ShaderKey::Unattributed, |location| {
                            self.shader_key(location.code_block)
                        });
                    *shaders.entry(key).or_default() += weight;
                }
            }
        }
        let cycles: f64 = ranges
            .iter()
            .zip(&fractions)
            .filter(|(_, fraction)| **fraction > 0.0)
            .map(|(range, fraction)| {
                let values: Vec<f64> = range
                    .cycles
                    .iter()
                    .copied()
                    .filter(|value| value.is_finite())
                    .collect();
                if values.is_empty() {
                    0.0
                } else {
                    fraction * values.iter().sum::<f64>() / values.len() as f64
                }
            })
            .sum();
        let counter_ranges = fractions.iter().filter(|fraction| **fraction > 0.0).count();
        if cycles == 0.0 {
            warnings.push("The scope covers no counter range with elapsed cycles.".into());
        }
        // Per TPC and cycle, scaled to one SM as Nsight's "Avg Warps" does.
        let scale = if cycles > 0.0 {
            1.0 / (cycles * layout.sms_per_tpc as f64)
        } else {
            0.0
        };
        let peak = layout.max_warps_per_tpc / layout.sms_per_tpc as f64;
        let total: f64 = shaders.values().sum::<f64>() * scale;
        let entry = |name: String, label: Option<String>, hash: Option<String>, value: f64| {
            let avg_warps = value * scale;
            WarpWeightedCount {
                name,
                label,
                hash,
                avg_warps,
                pct_of_peak: 100.0 * avg_warps / peak,
                share_pct: if total > 0.0 {
                    100.0 * avg_warps / total
                } else {
                    0.0
                },
            }
        };
        let mut sample_types: Vec<_> = reasons
            .iter()
            .enumerate()
            .filter(|(_, value)| **value > 0.0)
            .map(|(code, value)| {
                let entry_type = self.sample_types.get(code);
                entry(
                    self.sample_type_name(code as u8),
                    entry_type.map(|entry| entry.label.to_owned()),
                    None,
                    *value,
                )
            })
            .collect();
        sample_types.sort_by(|left, right| right.avg_warps.total_cmp(&left.avg_warps));
        let unattributed = shaders
            .get(&ShaderKey::Unattributed)
            .copied()
            .unwrap_or(0.0)
            * scale;
        let mut shader_rows: Vec<_> = shaders
            .iter()
            .map(|(key, value)| entry(self.shader_label(key), None, key.hash(), *value))
            .collect();
        shader_rows.sort_by(|left, right| right.avg_warps.total_cmp(&left.avg_warps));
        Ok(WarpWeightedSummary {
            scope: scope.clone(),
            basis: WARP_WEIGHTING_BASIS,
            counter_ranges,
            peak_warps_per_sm: peak,
            attributed_avg_warps: total - unattributed,
            unattributed_avg_warps: unattributed,
            sample_types,
            shaders: shader_rows,
            warnings,
        })
    }

    /// Rank source lines, SPIR-V instructions, or SASS instructions by sample count.
    pub fn hotspots(
        &self,
        scope: &Scope,
        group_by: HotspotGrouping,
        shader_filter: Option<&Regex>,
    ) -> Result<HotspotReport> {
        let selection = self.select(scope)?;
        let total = selection.indices.len();
        let mut groups: HashMap<HotspotKey, GroupCounts> = HashMap::new();
        let mut matching = 0usize;
        for index in &selection.indices {
            let sample = &self.samples[*index];
            let location = self.profile.locate(sample.pc);
            let shader = location.map_or(ShaderKey::Unattributed, |location| {
                self.shader_key(location.code_block)
            });
            if let Some(filter) = shader_filter
                && !(filter.is_match(&self.shader_label(&shader))
                    || shader.hash().is_some_and(|hash| filter.is_match(&hash)))
            {
                continue;
            }
            matching += 1;
            let key = match (group_by, location) {
                (_, None) => HotspotKey::Unattributed,
                (HotspotGrouping::Line, Some(location)) => {
                    HotspotKey::Line(shader, location.code_block, location.correlation.location)
                }
                (HotspotGrouping::Instruction, Some(location)) => HotspotKey::Instruction(
                    shader,
                    location.code_block,
                    location.correlation.spirv_index,
                ),
                (HotspotGrouping::Sass, Some(location)) => {
                    HotspotKey::Sass(location.code_block, location.offset & !15)
                }
            };
            groups.entry(key).or_insert_with(GroupCounts::new).add(
                sample.sample_type,
                location.and_then(|location| location.correlation.class),
            );
        }
        let mut hotspots: Vec<_> = groups
            .into_iter()
            .map(|(key, counts)| self.hotspot(&key, &counts, total))
            .collect();
        hotspots.sort_by(|left, right| {
            right
                .samples
                .cmp(&left.samples)
                .then_with(|| left.shader.cmp(&right.shader))
                .then_with(|| left.code_block.cmp(&right.code_block))
                .then_with(|| left.file.cmp(&right.file))
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.spirv_index.cmp(&right.spirv_index))
                .then_with(|| left.sass_offset.cmp(&right.sass_offset))
        });
        let mut warnings = selection.warnings;
        warnings.extend(self.warnings.iter().cloned());
        Ok(HotspotReport {
            group_by,
            scope: selection.scope,
            selected_samples: total,
            matching_samples: matching,
            hotspots,
            share_basis: "percent of all samples selected by the scope",
            warnings,
        })
    }

    /// Decode one page of attributed sample records selected by a scope.
    pub fn records(
        &self,
        scope: &Scope,
        vsmid: Option<u32>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<SampleRecord>, usize, Scope)> {
        let selection = self.select(scope)?;
        let indices: Vec<_> = selection
            .indices
            .into_iter()
            .filter(|index| vsmid.is_none_or(|vsmid| self.samples[*index].vsmid == vsmid))
            .collect();
        let start = offset.min(indices.len());
        let stop = indices.len().min(start.saturating_add(limit));
        let records = indices[start..stop]
            .iter()
            .map(|index| {
                let sample = &self.samples[*index];
                let location = self.profile.locate(sample.pc);
                let block = location.map(|location| &self.profile.code_blocks[location.code_block]);
                let source = location.and_then(|location| {
                    self.source_of(location.code_block, location.correlation.location)
                });
                SampleRecord {
                    index: *index,
                    gpu_index: sample.gpu_index,
                    vsmid: sample.vsmid,
                    pc: sample.pc,
                    time_ns: sample.time_ns,
                    sample_type: sample.sample_type,
                    sample_type_name: self.sample_type_name(sample.sample_type),
                    warp_slot: sample.warp_slot,
                    flag: sample.flag,
                    shader: block.map(|block| self.profile.shader_name(block)),
                    shader_hash: block.and_then(|block| block.module_hash.clone()),
                    code_block: block.map(|block| block.index),
                    sass_offset: location.map(|location| location.offset),
                    instruction_class: location
                        .and_then(|location| location.correlation.class)
                        .map(|class| class.label()),
                    spirv_index: location.and_then(|location| location.correlation.spirv_index),
                    file: source.as_ref().map(|source| file_basename(&source.0)),
                    line: source.map(|source| source.1),
                }
            })
            .collect();
        Ok((records, indices.len(), selection.scope))
    }

    /// Modules and code blocks with their whole-capture sample counts.
    pub fn shaders(&self) -> serde_json::Value {
        let mut per_block = vec![0usize; self.profile.code_blocks.len()];
        let mut outside = 0usize;
        for sample in &self.samples {
            match self.profile.locate(sample.pc) {
                Some(location) => per_block[location.code_block] += 1,
                None => outside += 1,
            }
        }
        let modules: Vec<_> = self
            .profile
            .modules
            .iter()
            .enumerate()
            .map(|(position, module)| {
                let samples: usize = self
                    .profile
                    .code_blocks
                    .iter()
                    .zip(&per_block)
                    .filter(|(block, _)| block.module_index == Some(position))
                    .map(|(_, count)| *count)
                    .sum();
                let mut value = serde_json::to_value(module).unwrap_or_default();
                value["samples"] = samples.into();
                value
            })
            .collect();
        let code_blocks: Vec<_> = self
            .profile
            .code_blocks
            .iter()
            .zip(&per_block)
            .map(|(block, samples)| {
                let mut value = serde_json::to_value(block).unwrap_or_default();
                value["shader"] = self.profile.shader_name(block).into();
                value["samples"] = (*samples).into();
                value
            })
            .collect();
        serde_json::json!({
            "available": !self.samples.is_empty(),
            "unavailable_reason": self.unavailable_reason(),
            "records": self.samples.len(),
            "samples_outside_code_blocks": outside,
            "blob_count": self.profile.blob_count,
            "blob_key_source": self.profile.key_source,
            "modules": modules,
            "code_blocks": code_blocks,
            "spirv_listing_line_rule": format!("spirv_listing_line = spirv_index + {SPIRV_FIRST_INSTRUCTION_LINE}"),
            "warnings": self.warnings,
        })
    }

    fn select(&self, scope: &Scope) -> Result<Selection> {
        let mut warnings = Vec::new();
        if scope.kind == ScopeKind::Capture {
            return Ok(Selection {
                scope: scope.clone(),
                indices: (0..self.samples.len()).collect(),
                untimed: 0,
                warnings,
            });
        }
        if scope.kind == ScopeKind::SampleRange {
            return Err(Error::TracePath(
                "PC samples cannot be selected by counter sample range; use a time, call, frame, or labeled scope".into(),
            ));
        }
        let (start, end) = scope.start_ns.zip(scope.end_ns).ok_or_else(|| {
            Error::TracePath(format!("scope {} has no usable GPU timestamps", scope.id))
        })?;
        if scope.precision == "nvtx_clock_unvalidated" {
            warnings.push("NVTX range clock is not validated against GPU PTIMER; PC sample selection may be wrong.".into());
        }
        let mut untimed = 0usize;
        let indices = self
            .samples
            .iter()
            .enumerate()
            .filter_map(|(index, sample)| match sample.counter_range {
                Some((first, last)) => (first < end && last > start).then_some(index),
                None => {
                    untimed += 1;
                    None
                }
            })
            .collect();
        if untimed > 0 {
            warnings.push(format!(
                "{untimed} samples before their SM's first anchor have no counter range (Nsight drops them) and were excluded from the time scope."
            ));
        }
        Ok(Selection {
            scope: scope.clone(),
            indices,
            untimed,
            warnings,
        })
    }

    fn shader_key(&self, code_block: usize) -> ShaderKey {
        let block = &self.profile.code_blocks[code_block];
        match block.module_hash_value.or_else(|| {
            self.profile
                .module_of(block)
                .and_then(|module| module.hash_value)
        }) {
            Some(hash) => ShaderKey::Module(hash),
            None => ShaderKey::CodeBlock(code_block),
        }
    }

    fn shader_label(&self, key: &ShaderKey) -> String {
        match key {
            ShaderKey::Module(hash) => self
                .profile
                .modules
                .iter()
                .find(|module| module.hash_value == Some(*hash))
                .and_then(|module| module.name.clone())
                .unwrap_or_else(|| format_hash(*hash)),
            ShaderKey::CodeBlock(block) => {
                self.profile.shader_name(&self.profile.code_blocks[*block])
            }
            ShaderKey::Unattributed => "(outside known code blocks)".into(),
        }
    }

    fn source_of(&self, code_block: usize, location: Option<u32>) -> Option<(String, u32)> {
        let block = &self.profile.code_blocks[code_block];
        let module = self.profile.module_of(block)?.spirv.as_ref()?;
        let location = module.locations.get(location? as usize)?;
        Some((location.file.clone(), location.line))
    }

    fn type_counts(&self, counts: &[usize; 256], total: usize) -> Vec<SampleTypeCount> {
        let mut result: Vec<_> = counts
            .iter()
            .enumerate()
            .filter(|(_, samples)| **samples > 0)
            .map(|(code, samples)| {
                let code = code as u8;
                let entry = self.sample_types.get(usize::from(code));
                SampleTypeCount {
                    code,
                    name: entry
                        .map_or_else(|| format!("unknown_{code}"), |entry| entry.name.into()),
                    label: entry
                        .map_or_else(|| format!("Unknown ({code})"), |entry| entry.label.into()),
                    kind: entry.map_or(SampleKind::Unknown, |entry| entry.kind),
                    samples: *samples,
                    share_pct: share(*samples, total),
                }
            })
            .collect();
        result.sort_by(|left, right| {
            right
                .samples
                .cmp(&left.samples)
                .then(left.code.cmp(&right.code))
        });
        result
    }

    fn hotspot(&self, key: &HotspotKey, counts: &GroupCounts, total: usize) -> Hotspot {
        let samples = counts.total();
        // Every SASS instruction of the hotspot's code block, sampled or not,
        // like the instruction counts of the Nsight source view.
        let static_instructions = match *key {
            HotspotKey::Line(_, block, location) => Some(
                self.profile.code_blocks[block]
                    .instructions
                    .iter()
                    .filter(|item| item.location == location)
                    .collect::<Vec<_>>(),
            ),
            HotspotKey::Instruction(_, block, spirv_index) => Some(
                self.profile.code_blocks[block]
                    .instructions
                    .iter()
                    .filter(|item| item.spirv_index == spirv_index)
                    .collect(),
            ),
            HotspotKey::Sass(block, offset) => Some(
                self.profile.code_blocks[block]
                    .instructions
                    .get((offset / 16) as usize)
                    .into_iter()
                    .collect(),
            ),
            HotspotKey::Unattributed => None,
        };
        let static_classes = static_instructions.as_ref().map(|items| {
            let mut classes: HashMap<Option<InstructionClass>, usize> = HashMap::new();
            for item in items {
                *classes.entry(item.class).or_default() += 1;
            }
            classes
        });
        let block = match *key {
            HotspotKey::Line(_, block, _)
            | HotspotKey::Instruction(_, block, _)
            | HotspotKey::Sass(block, _) => Some(&self.profile.code_blocks[block]),
            HotspotKey::Unattributed => None,
        };
        let mut hotspot = Hotspot {
            shader: String::new(),
            shader_hash: None,
            file: None,
            path: None,
            line: None,
            spirv_index: None,
            spirv_listing_line: None,
            spirv_instruction: None,
            code_block: block.map(|block| block.index),
            pipeline: block.and_then(|block| block.pipeline.clone()),
            sass_offset: None,
            sass_encoding: None,
            sass_instructions: static_instructions.as_ref().map(Vec::len),
            samples,
            share_pct: share(samples, total),
            sample_types: self.type_counts(&counts.types, samples),
            instruction_mix: class_counts(&counts.classes, samples, static_classes.as_ref()),
        };
        match key {
            HotspotKey::Unattributed => {
                hotspot.shader = self.shader_label(&ShaderKey::Unattributed);
            }
            HotspotKey::Line(shader, block, location) => {
                hotspot.shader = self.shader_label(shader);
                hotspot.shader_hash = shader.hash();
                if let Some(source) = self.source_of(*block, *location) {
                    hotspot.file = Some(file_basename(&source.0));
                    hotspot.path = Some(source.0);
                    hotspot.line = Some(source.1);
                }
            }
            HotspotKey::Instruction(shader, block, spirv_index) => {
                hotspot.shader = self.shader_label(shader);
                hotspot.shader_hash = shader.hash();
                hotspot.spirv_index = *spirv_index;
                hotspot.spirv_listing_line =
                    spirv_index.map(|index| index + SPIRV_FIRST_INSTRUCTION_LINE);
                let block = &self.profile.code_blocks[*block];
                if let (Some(index), Some(spirv)) = (
                    spirv_index,
                    self.profile
                        .module_of(block)
                        .and_then(|module| module.spirv.as_ref()),
                ) {
                    hotspot.spirv_instruction = spirv.describe(*index as usize);
                    if let Some(source) = spirv
                        .instruction_locations
                        .get(*index as usize)
                        .copied()
                        .flatten()
                        .and_then(|location| spirv.locations.get(location as usize))
                    {
                        hotspot.file = Some(file_basename(&source.file));
                        hotspot.path = Some(source.file.clone());
                        hotspot.line = Some(source.line);
                    }
                }
            }
            HotspotKey::Sass(block_index, offset) => {
                let block = &self.profile.code_blocks[*block_index];
                let shader = self.shader_key(*block_index);
                hotspot.shader = self.shader_label(&shader);
                hotspot.shader_hash = shader.hash();
                hotspot.sass_offset = Some(*offset);
                hotspot.sass_encoding = sass_encoding(block, *offset);
                let correlation = block
                    .instructions
                    .get((*offset / 16) as usize)
                    .copied()
                    .unwrap_or_default();
                hotspot.spirv_index = correlation.spirv_index;
                hotspot.spirv_listing_line = correlation
                    .spirv_index
                    .map(|index| index + SPIRV_FIRST_INSTRUCTION_LINE);
                if let Some(spirv) = self
                    .profile
                    .module_of(block)
                    .and_then(|module| module.spirv.as_ref())
                {
                    hotspot.spirv_instruction = correlation
                        .spirv_index
                        .and_then(|index| spirv.describe(index as usize));
                }
                if let Some(source) = self.source_of(*block_index, correlation.location) {
                    hotspot.file = Some(file_basename(&source.0));
                    hotspot.path = Some(source.0);
                    hotspot.line = Some(source.1);
                }
            }
        }
        hotspot
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ShaderKey {
    Module(u64),
    CodeBlock(usize),
    Unattributed,
}

impl ShaderKey {
    fn hash(&self) -> Option<String> {
        match self {
            Self::Module(hash) => Some(format_hash(*hash)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HotspotKey {
    /// Shader, code block, and location index of the source line. Like the
    /// Nsight hotspot table, every pipeline of a module counts on its own.
    Line(ShaderKey, usize, Option<u32>),
    Instruction(ShaderKey, usize, Option<u32>),
    Sass(usize, u64),
    Unattributed,
}

/// Raw 128-bit SASS encoding as two little-endian 64-bit words, like `nvdisasm` comments.
fn sass_encoding(block: &CodeBlock, offset: u64) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    let bytes = block.sass.get(start..start + 16)?;
    let low = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    let high = u64::from_le_bytes(bytes[8..].try_into().ok()?);
    Some(format!("{low:#018x} {high:#018x}"))
}

/// Instruction mix rows sorted by samples; unclassified samples get `None` fields.
fn class_counts(
    counts: &HashMap<Option<InstructionClass>, usize>,
    total: usize,
    instructions: Option<&HashMap<Option<InstructionClass>, usize>>,
) -> Vec<InstructionClassCount> {
    let mut result: Vec<_> = counts
        .iter()
        .map(|(class, samples)| InstructionClassCount {
            label: class.map_or_else(|| "(unclassified)".into(), |class| class.label()),
            pipe: class.map(|class| class.pipe),
            family: class.map(|class| class.family),
            operation: class.and_then(|class| class.operation),
            samples: *samples,
            share_pct: share(*samples, total),
            instructions: instructions
                .map(|instructions| instructions.get(class).copied().unwrap_or_default()),
        })
        .collect();
    result.sort_by(|left, right| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left.label.cmp(&right.label))
    });
    result
}

fn share(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * part as f64 / total as f64
    }
}

/// Decode `(PTIMER, cumulative sample index)` anchors and validate their order.
fn decode_anchors(data: &[u8], count: usize) -> Result<Vec<(u64, usize)>> {
    if !data.len().is_multiple_of(ANCHOR_SIZE) {
        return Err(Error::InvalidCapture(format!(
            "timestamp storage has {} bytes, not a multiple of {ANCHOR_SIZE}",
            data.len()
        )));
    }
    let mut anchors = Vec::with_capacity(data.len() / ANCHOR_SIZE);
    let mut previous = (0u64, 0usize);
    for anchor in data.as_chunks::<ANCHOR_SIZE>().0 {
        let ptimer = u64::from_le_bytes(anchor[..8].try_into().unwrap());
        let end = u64::from_le_bytes(anchor[8..].try_into().unwrap());
        let end = usize::try_from(end)
            .ok()
            .filter(|end| *end >= previous.1 && *end <= count)
            .ok_or_else(|| {
                Error::InvalidCapture(
                    "timestamp anchors have an invalid cumulative sample index".into(),
                )
            })?;
        if ptimer < previous.0 {
            return Err(Error::InvalidCapture(
                "timestamp anchors are not monotonic".into(),
            ));
        }
        anchors.push((ptimer, end));
        previous = (ptimer, end);
    }
    Ok(anchors)
}

/// Virtual SM IDs (indices into `mappings`) sorted by physical GPC, TPC, and
/// SM index, the order in which WarpViz pairs SMs with TPC counter instances.
fn physical_order(mappings: &[(u64, u64, u64)]) -> Vec<u32> {
    let mut order: Vec<u32> = (0..mappings.len() as u32).collect();
    order.sort_by_key(|vsmid| mappings[*vsmid as usize]);
    order
}

/// Store the counter range Nsight assigns to every sample. The anchors of all
/// SMs of a GPU fall on the range ends, so their union serves as the grid.
fn assign_sample_counter_ranges(
    gpus: &[GpuSamplingInfo],
    streams: &[SmStream],
    samples: &mut [PcSample],
    profile: &ShaderProfile,
) {
    for gpu in gpus {
        let window = gpu
            .arch
            .and_then(warp_layout)
            .map_or(3, |layout| layout.split_window);
        let gpu_streams: Vec<_> = streams
            .iter()
            .filter(|stream| stream.gpu_index == gpu.gpu_index)
            .collect();
        let mut grid: Vec<u64> = gpu_streams
            .iter()
            .flat_map(|stream| stream.anchor_list.iter().map(|anchor| anchor.0))
            .collect();
        grid.sort_unstable();
        grid.dedup();
        for stream in gpu_streams {
            let first = stream.first_sample;
            let pcs: Vec<u64> = samples[first..first + stream.records]
                .iter()
                .map(|sample| sample.pc)
                .collect();
            let assigned = assign_counter_ranges(&stream.anchor_list, &pcs, &grid, window, |pc| {
                profile.locate(pc).map(|location| location.code_block)
            });
            for (index, members) in assigned {
                let span = (
                    index
                        .checked_sub(1)
                        .map_or(grid[index], |previous| grid[previous]),
                    grid[index],
                );
                for sample in &mut samples[first + members.start..first + members.end] {
                    sample.counter_range = Some(span);
                }
            }
        }
    }
}

/// Split one SM's samples into periodic counter ranges as WarpViz does.
/// Samples before the first anchor are dropped unless no later anchor exists.
/// Every later anchor closes the counter range that ends at its time. When an
/// anchor gap spans several ranges, its samples stay in the gap's first range,
/// except for up to `window` trailing samples that are closer by PC to the
/// next anchor's samples; those move to the range after the anchor.
fn assign_counter_ranges(
    anchors: &[(u64, usize)],
    pcs: &[u64],
    range_ends: &[u64],
    window: usize,
    block_of: impl Fn(u64) -> Option<usize>,
) -> Vec<(usize, std::ops::Range<usize>)> {
    let Some(&(first_time, first_end)) = anchors.first() else {
        return Vec::new();
    };
    let count = pcs.len();
    let dropped = if first_end >= count { 0 } else { first_end };
    let distance = |a: u64, b: u64| -> u64 {
        let penalty = match (block_of(a), block_of(b)) {
            (Some(left), Some(right)) if left == right => 0,
            (None, None) => 0x5555_5555_5555_5555,
            _ => 0xAAAA_AAAA_AAAA_AAAA,
        };
        (a.abs_diff(b) / 3).wrapping_add(penalty)
    };
    // bounds[r] is the first sample index of counter range r.
    let mut range = range_ends.partition_point(|end| *end <= first_time);
    let mut bounds = BTreeMap::from([(range, dropped)]);
    let mut last = dropped;
    for (index, &(time, end)) in anchors.iter().enumerate().skip(1) {
        if range >= range_ends.len() {
            break;
        }
        let end = end.clamp(last, count);
        if range_ends[range] < time {
            let next = anchors
                .get(index + 1)
                .map_or(end, |anchor| anchor.1.clamp(end, count));
            let start = bounds[&range];
            let mut split = end.saturating_sub(window).max(last);
            while split < end {
                let nearest = |others: std::ops::Range<usize>| {
                    others
                        .map(|other| distance(pcs[split], pcs[other]))
                        .min()
                        .unwrap_or(u64::MAX)
                };
                if nearest(start..split) > nearest(end..next) {
                    break;
                }
                split += 1;
            }
            bounds.insert(range + 1, split);
            while range + 1 < range_ends.len() && range_ends[range] < time {
                range += 1;
                bounds.insert(range + 1, split);
            }
            range += 1;
            last = split;
        } else {
            bounds.insert(range + 1, end);
            range += 1;
            last = end;
        }
    }
    bounds
        .iter()
        .zip(bounds.iter().skip(1))
        .filter(|((range, start), (next, end))| **next == **range + 1 && end > start)
        .map(|((range, start), (_, end))| (*range, *start..*end))
        .collect()
}

/// Midpoint time of every sample slot between the anchors that enclose it.
/// Samples before the first anchor get its time; samples after the last none.
fn sample_times(anchors: &[(u64, usize)], count: usize) -> Vec<Option<u64>> {
    let mut times = vec![None; count];
    let mut previous: Option<(u64, usize)> = None;
    for &(ptimer, end) in anchors {
        let start = previous.map_or(0, |anchor| anchor.1);
        let span = (end - start) as u64;
        let first = previous.map_or(ptimer, |anchor| anchor.0);
        for (ordinal, time) in times[start..end].iter_mut().enumerate() {
            *time = Some(
                first
                    + ((ptimer - first) as u128 * (2 * ordinal as u128 + 1) / (2 * span as u128))
                        as u64,
            );
        }
        previous = Some((ptimer, end));
    }
    times
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ada_table_matches_the_exported_metric_order() {
        // GPUTRACE_FRAME exports tpc__warps_issue_stalled_* rows in code order 1..20.
        let exported = [
            "drain",
            "imc_miss",
            "barrier",
            "membar",
            "sleeping",
            "branch_resolving",
            "wait",
            "long_scoreboard_pipe_rtcore",
            "long_scoreboard_pipe_l1tex",
            "short_scoreboard",
            "no_instruction",
            "math_pipe_throttle",
            "tex_throttle",
            "mio_throttle_pipe_rtcore",
            "lg_throttle",
            "mio_throttle_pipe_mio",
            "dispatch_stall",
            "selected",
            "not_selected",
            "misc",
        ];
        let (name, table) = sample_type_table(0x190).unwrap();
        assert_eq!(name, "ada");
        for (code, expected) in exported.iter().enumerate() {
            assert_eq!(table[code + 1].name, *expected);
            assert_eq!(usize::from(table[code + 1].code), code + 1);
        }
        assert!(sample_type_table(0x160).is_none());
        assert_eq!(sample_type_table(0x1b0).unwrap().1.len(), 20);
    }

    #[test]
    fn counter_ranges_follow_anchors_and_split_gaps_by_pc() {
        // Ranges end at 10, 20, ..., 60. The first anchor's sample is dropped,
        // the anchor at 50 closes a gap over the ranges ending at 30, 40, 50.
        let range_ends = [10, 20, 30, 40, 50, 60];
        let anchors = [(10, 1), (20, 3), (50, 8), (60, 10)];
        let pcs = [
            0x0100, 0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x9000, 0x9010, 0x9020, 0x9030,
        ];
        let block_of = |pc: u64| Some(usize::from(pc >= 0x8000));
        let assigned = assign_counter_ranges(&anchors, &pcs, &range_ends, 3, block_of);
        // Samples 6 and 7 resemble the next anchor's block and move past the gap.
        assert_eq!(assigned, [(1, 1..3), (2, 3..6), (5, 6..10)]);

        // Without a trailing match the whole gap stays in its first range.
        let same_block = |_: u64| Some(0);
        let flat = [0, 1, 2, 3, 4, 5, 6, 7, 1000, 1001];
        let assigned = assign_counter_ranges(&anchors, &flat, &range_ends, 3, same_block);
        assert_eq!(assigned, [(1, 1..3), (2, 3..8), (5, 8..10)]);

        // Samples before the first anchor are kept only if nothing follows it.
        assert_eq!(
            assign_counter_ranges(&[(10, 2)], &pcs[..2], &range_ends, 3, block_of),
            []
        );
    }

    /// `(vsmid, anchors, [(pc, sample type)])` of one synthetic SM.
    type SyntheticStream = (u32, Vec<(u64, usize)>, Vec<(u64, u8)>);

    /// One Ada GPU from synthetic SM streams, with no shader tables, so every
    /// sample is outside known code blocks.
    fn synthetic(mappings: &[(u64, u64, u64)], streams: &[SyntheticStream]) -> PcSampling {
        let gpus = vec![GpuSamplingInfo {
            gpu_index: 0,
            arch: Some(0x190),
            implementation: None,
            chip_name: None,
            sampling_interval: None,
            sample_type_table: Some("ada"),
            physical_order: physical_order(mappings),
        }];
        let mut infos = Vec::new();
        let mut samples = Vec::new();
        for (vsmid, anchors, records) in streams {
            infos.push(SmStream {
                gpu_index: 0,
                vsmid: *vsmid,
                version: Some(SUPPORTED_STORAGE_VERSION),
                records: records.len(),
                anchors: anchors.len(),
                dropped_storage_bytes: 0,
                first_ptimer: anchors.first().map(|anchor| anchor.0),
                last_ptimer: anchors.last().map(|anchor| anchor.0),
                anchor_list: anchors.clone(),
                first_sample: samples.len(),
            });
            let times = sample_times(anchors, records.len());
            for (&(pc, sample_type), time_ns) in records.iter().zip(times) {
                samples.push(PcSample {
                    gpu_index: 0,
                    vsmid: *vsmid,
                    pc,
                    time_ns,
                    counter_range: None,
                    warp_slot: 0,
                    sample_type,
                    flag: 0,
                });
            }
        }
        let profile = ShaderProfile::default();
        assign_sample_counter_ranges(&gpus, &infos, &mut samples, &profile);
        PcSampling {
            gpus,
            streams: infos,
            samples,
            sample_types: &AMPERE_ADA_TYPES,
            profile,
            warnings: Vec::new(),
        }
    }

    fn scope(kind: ScopeKind, range: Option<(u64, u64)>) -> Scope {
        Scope {
            kind,
            id: "test".into(),
            label: "test".into(),
            start_ns: range.map(|range| range.0),
            end_ns: range.map(|range| range.1),
            call_start: None,
            call_stop: None,
            sample_start: None,
            sample_stop: None,
            precision: "test".into(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn time_scopes_select_samples_by_their_counter_range() {
        // SM 0 has an anchor in every range; its first sample precedes the
        // first anchor. SM 1 has no anchor at 200, so its slot (100, 300]
        // spans two ranges and Nsight keeps it in the first one.
        let sampling = synthetic(
            &[(0, 0, 0), (0, 0, 1)],
            &[
                (
                    0,
                    vec![(100, 1), (200, 3), (300, 5)],
                    vec![(0x10, 7), (0x10, 7), (0x14, 7), (0x18, 7), (0x1c, 7)],
                ),
                (
                    1,
                    vec![(100, 0), (300, 3)],
                    vec![(0x20, 3), (0x24, 3), (0x28, 3)],
                ),
            ],
        );
        let ranges: Vec<_> = sampling
            .samples()
            .iter()
            .map(|sample| sample.counter_range)
            .collect();
        assert_eq!(
            ranges,
            [
                None,
                Some((100, 200)),
                Some((100, 200)),
                Some((200, 300)),
                Some((200, 300)),
                Some((100, 200)),
                Some((100, 200)),
                Some((100, 200)),
            ]
        );
        let selected = |kind, range| {
            let summary = sampling.summary(&scope(kind, range)).unwrap();
            (summary.selected_samples, summary.untimed_samples_excluded)
        };
        assert_eq!(selected(ScopeKind::Capture, None), (8, 0));
        assert_eq!(selected(ScopeKind::TimeRange, Some((150, 250))), (7, 1));
        // Anchor-interval overlap would also take SM 1's three samples here.
        assert_eq!(selected(ScopeKind::TimeRange, Some((210, 290))), (2, 1));
        // A range ending exactly at the scope start stays outside.
        assert_eq!(selected(ScopeKind::TimeRange, Some((200, 201))), (2, 1));
    }

    #[test]
    fn warp_weighting_splits_tpc_warps_over_each_sms_samples() {
        // Physical order: vsmid 1, 3 form TPC 0 and vsmid 0, 2 form TPC 1,
        // unlike the virtual order (0, 1 | 2, 3).
        let sampling = synthetic(
            &[(1, 0, 0), (0, 0, 0), (1, 0, 1), (0, 0, 1)],
            &[
                (0, vec![(100, 0), (200, 4), (300, 6)], vec![(0x40, 3); 6]),
                (
                    1,
                    vec![(100, 0), (200, 2), (300, 3)],
                    vec![(0x10, 7), (0x14, 9), (0x18, 7)],
                ),
                (2, Vec::new(), Vec::new()),
                (3, vec![(100, 0), (200, 1)], vec![(0x20, 19)]),
            ],
        );
        assert_eq!(sampling.tpc_instances().unwrap(), 2);
        let counters: Vec<_> = (0..3)
            .map(|index| TpcCounterRange {
                range_index: index,
                start_ns: index as u64 * 100,
                end_ns: (index as u64 + 1) * 100,
                cycles: vec![1000.0, 1000.0],
                active_warps: vec![40_000.0, 8_000.0],
            })
            .collect();
        let value = |summary: &WarpWeightedSummary, name: &str| {
            summary
                .sample_types
                .iter()
                .find(|entry| entry.name == name)
                .unwrap()
                .clone()
        };
        let close =
            |left: f64, right: f64| assert!((left - right).abs() < 1e-9, "{left} != {right}");

        // Range 0 has no valid start time, ranges 1 and 2 count fully. Per
        // range and SM, a sample gets TPC warps / samples of the SM / 4 SMs;
        // the sum is divided by 2000 cycles and by 2 SMs per TPC.
        let capture = sampling
            .warp_weighted(&counters, &scope(ScopeKind::Capture, None))
            .unwrap();
        assert_eq!(capture.counter_ranges, 2);
        close(value(&capture, "wait").avg_warps, 15_000.0 / 4000.0);
        close(value(&capture, "not_selected").avg_warps, 10_000.0 / 4000.0);
        close(
            value(&capture, "long_scoreboard_pipe_l1tex").avg_warps,
            5_000.0 / 4000.0,
        );
        close(value(&capture, "barrier").avg_warps, 4_000.0 / 4000.0);
        close(value(&capture, "wait").pct_of_peak, 100.0 * 3.75 / 48.0);
        close(value(&capture, "wait").share_pct, 100.0 * 15.0 / 34.0);
        close(capture.unattributed_avg_warps, 8.5);
        close(capture.attributed_avg_warps, 0.0);
        assert_eq!(capture.sample_types[0].name, "wait");

        // A time scope from 150 to 300 takes half of range 1 and all of range 2.
        let partial = sampling
            .warp_weighted(&counters, &scope(ScopeKind::TimeRange, Some((150, 300))))
            .unwrap();
        close(value(&partial, "wait").avg_warps, 12_500.0 / 3000.0);
        close(value(&partial, "barrier").avg_warps, 3_000.0 / 3000.0);
        close(value(&partial, "not_selected").avg_warps, 5_000.0 / 3000.0);
    }

    #[test]
    fn warp_layout_matches_the_warpviz_architectures() {
        for arch in [0x170, 0x190, 0x1a0, 0x1b0] {
            let layout = warp_layout(arch).unwrap();
            assert_eq!(
                (
                    layout.sms_per_tpc,
                    layout.max_warps_per_tpc,
                    layout.split_window
                ),
                (2, 96.0, 3)
            );
        }
        assert!(warp_layout(0x160).is_none());
    }

    #[test]
    fn anchors_interpolate_midpoints_and_reject_disorder() {
        let mut data = Vec::new();
        for (ptimer, end) in [(1000u64, 2u64), (1100, 4), (1100, 5)] {
            data.extend(ptimer.to_le_bytes());
            data.extend(end.to_le_bytes());
        }
        let anchors = decode_anchors(&data, 6).unwrap();
        let times = sample_times(&anchors, 6);
        assert_eq!(
            times,
            [
                Some(1000),
                Some(1000),
                Some(1025),
                Some(1075),
                Some(1100),
                None
            ]
        );

        let mut bad = Vec::new();
        for (ptimer, end) in [(1000u64, 3u64), (900, 4)] {
            bad.extend(ptimer.to_le_bytes());
            bad.extend(end.to_le_bytes());
        }
        assert!(decode_anchors(&bad, 4).is_err());
        assert!(decode_anchors(&data, 4).is_err());
    }
}
