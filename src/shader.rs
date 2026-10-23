//! Shader Profiler blobs, driver cubins, and SASS extraction.
//!
//! Nsight stores Shader Profiler payloads in `PbBlobTable`. Blobs may be LZ4
//! compressed and/or XOR-obfuscated with a stream that is reused across blobs.
//! A reused XOR stream is recoverable from any known plaintext blob and then
//! decrypts the remaining payloads. This module owns decompression, stream
//! removal, cubin selection, and optional external `nvdisasm` invocation.

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use prost::Message;
use prost_reflect::{ReflectMessage, Value as ReflectValue};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result, TraceDocument};

/// XOR stream used by `OBFUSCATION_SIMPLE` in the validated Nsight 2026.3
/// Shader Profiler payloads. It was reconstructed from a known SPIR-V plaintext
/// and audited across 12 captures / 664 obfuscated blobs with zero decode
/// errors; independent recoveries matched this stream. A caller can override or
/// recover it when working with another producer.
pub const BUILTIN_KEYSTREAM: &[u8] = include_bytes!("../assets/shader_profiler_keystream.bin");

const SPIRV_MAGIC: [u8; 4] = [0x03, 0x02, 0x23, 0x07];
const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobCompression {
    None,
    Lz4,
    Unknown(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobObfuscation {
    None,
    Simple,
    Unknown(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobKind {
    Spirv,
    Elf,
    Binary,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlobInfo {
    pub index: usize,
    pub id: u32,
    pub stored_size: usize,
    pub uncompressed_size: u64,
    pub compression: &'static str,
    pub obfuscation: &'static str,
    pub kind: BlobKind,
    pub decoded_size: Option<usize>,
    pub sha256: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Blob {
    pub info: BlobInfo,
    /// Data after decompression but before stream removal. This is what a
    /// known-plaintext recovery pass needs.
    unpacked: Option<Vec<u8>>,
    decoded: Option<Vec<u8>>,
}

impl Blob {
    pub fn decoded(&self) -> Result<&[u8]> {
        self.decoded.as_deref().ok_or_else(|| {
            Error::Shader(
                self.info
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("blob {} could not be decoded", self.info.index)),
            )
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub index: usize,
    pub kind: String,
    pub blob_index: Option<usize>,
    pub provider: Option<String>,
    pub driver_api: Option<String>,
    pub function_group_indices: Vec<u32>,
}

impl crate::Analysis {
    /// Decode Shader Profiler blobs using the built-in or environment-selected
    /// XOR stream. The catalog is independent of metric evaluation.
    pub fn shader_catalog(&self) -> Result<ShaderCatalog> {
        let (keystream, source) = load_keystream(None)?;
        ShaderCatalog::open(self.document(), &keystream, &source)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OccupancyEstimate {
    pub architecture: Option<String>,
    pub registers_per_thread: Option<u32>,
    pub threads_per_block: Option<u32>,
    pub static_smem_bytes: Option<u32>,
    pub max_warps_by_registers: Option<u32>,
    pub max_warps_by_threads: Option<u32>,
    pub max_warps_by_smem: Option<u32>,
    pub estimated_warps_per_sm: Option<u32>,
    pub estimated_occupancy_pct: Option<f64>,
    pub limiting_factor: Option<String>,
    pub assumptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcSamplingStatistics {
    pub pass_count: Option<u64>,
    pub total_samples: Option<u64>,
    pub start_clock_rate_hz: Option<u64>,
    pub end_clock_rate_hz: Option<u64>,
    pub stall_reason_means: Vec<f32>,
    pub stall_reason_std_devs: Vec<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcSamplingSummary {
    pub sample_type_names: Vec<String>,
    pub range_count: usize,
    pub statistics: Option<PcSamplingStatistics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShaderInfo {
    pub index: usize,
    pub device_index: usize,
    pub source: &'static str,
    pub name: String,
    pub entry_point: Option<String>,
    pub source_file: Option<String>,
    pub stage: String,
    pub shader_type: String,
    pub origin: String,
    pub pipeline: Option<String>,
    pub sm: Option<String>,
    pub registers_per_thread: Option<u32>,
    pub threads_per_block: Option<u32>,
    pub static_smem_bytes: Option<u32>,
    pub barrier_count: Option<u32>,
    pub occupancy: Option<OccupancyEstimate>,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub instructions_blob: Option<usize>,
    pub debug_blob: Option<usize>,
    pub cubin_blob: Option<usize>,
    pub cubin_size: Option<usize>,
    pub cubin_sha256: Option<String>,
    pub function_group_indices: Vec<u32>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceShaders {
    pub device_index: usize,
    pub blobs: Vec<BlobInfo>,
    pub modules: Vec<ModuleInfo>,
    pub shaders: Vec<ShaderInfo>,
    pub pc_sampling: Option<PcSamplingSummary>,
    #[serde(skip)]
    raw_blobs: Vec<Blob>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShaderCatalog {
    pub devices: Vec<DeviceShaders>,
    pub keystream_bytes: usize,
    pub keystream_source: String,
}

impl ShaderCatalog {
    /// Build a catalog using the supplied XOR stream. Pass an empty stream when
    /// only blob metadata or known-plaintext recovery is needed.
    pub fn open(document: &TraceDocument, keystream: &[u8], source: &str) -> Result<Self> {
        let reports = extract_reports(document)?;
        let mut devices = Vec::with_capacity(reports.len());
        for (device_index, (report, dynamic)) in reports.into_iter().enumerate() {
            let raw_blobs = decode_blobs(report.blob_table.as_ref(), keystream)?;
            let modules = decode_modules(report.pc_counters_info.as_ref(), &raw_blobs);
            let shaders = decode_shaders(
                device_index,
                report.pc_counters_info.as_ref(),
                &raw_blobs,
                &modules,
            );
            devices.push(DeviceShaders {
                device_index,
                blobs: raw_blobs.iter().map(|blob| blob.info.clone()).collect(),
                modules,
                shaders,
                pc_sampling: pc_sampling_summary(&dynamic),
                raw_blobs,
            });
        }
        Ok(Self {
            devices,
            keystream_bytes: keystream.len(),
            keystream_source: source.to_owned(),
        })
    }

    pub fn shaders(&self) -> impl Iterator<Item = &ShaderInfo> {
        self.devices.iter().flat_map(|device| &device.shaders)
    }

    /// Decode a cubin for one catalog shader.
    pub fn cubin(&self, device_index: usize, shader_index: usize) -> Result<Vec<u8>> {
        let shader = self
            .shaders()
            .find(|shader| shader.device_index == device_index && shader.index == shader_index)
            .ok_or_else(|| {
                Error::Shader(format!(
                    "shader index {shader_index} is out of range for device {device_index}"
                ))
            })?;
        let blob_index = shader.cubin_blob.ok_or_else(|| {
            Error::Shader(format!(
                "shader {} ({}) has no debug ELF/cubin blob",
                shader.index, shader.name
            ))
        })?;
        let device = self
            .devices
            .iter()
            .find(|device| device.device_index == device_index)
            .ok_or_else(|| Error::Shader(format!("device {device_index} is unavailable")))?;
        let blob = device
            .raw_blobs
            .get(blob_index)
            .ok_or_else(|| Error::Shader(format!("blob index {blob_index} is out of range")))?;
        Ok(blob.decoded()?.to_vec())
    }

    pub fn blob(&self, device_index: usize, blob_index: usize) -> Result<&Blob> {
        self.devices
            .iter()
            .find(|device| device.device_index == device_index)
            .and_then(|device| device.raw_blobs.get(blob_index))
            .ok_or_else(|| Error::Shader(format!("blob {blob_index} is out of range")))
    }

    fn raw_for_recovery(&self, device_index: usize, blob_index: usize) -> Option<&[u8]> {
        self.devices
            .iter()
            .find(|device| device.device_index == device_index)
            .and_then(|device| device.raw_blobs.get(blob_index))
            .and_then(|blob| blob.unpacked.as_deref())
    }
}

// ---------------------------------------------------------------------------
// Dynamic protobuf extraction
// ---------------------------------------------------------------------------

fn extract_reports(document: &TraceDocument) -> Result<Vec<(Report, serde_json::Value)>> {
    let message = document.message();
    let descriptor = message.descriptor();
    let Some(devices_field) = descriptor.get_field_by_name("devices") else {
        return Ok(Vec::new());
    };
    let devices_value = message.get_field(&devices_field);
    let ReflectValue::List(devices) = devices_value.as_ref() else {
        return Ok(Vec::new());
    };
    let mut reports = Vec::new();
    for device in devices.iter() {
        let ReflectValue::Message(device) = device else {
            continue;
        };
        let Some(report_field) = device
            .descriptor()
            .get_field_by_name("ShaderProfilerReport")
        else {
            continue;
        };
        let report_value = device.get_field(&report_field);
        let ReflectValue::Message(report) = report_value.as_ref() else {
            continue;
        };
        let dynamic = serde_json::to_value(report)?;
        reports.push((Report::decode(report.encode_to_vec().as_slice())?, dynamic));
    }
    Ok(reports)
}

fn pc_sampling_summary(report: &serde_json::Value) -> Option<PcSamplingSummary> {
    let session = [
        "/pcCountersInfo/pcSamplingSession",
        "/pc_counters_info/pc_sampling_session",
    ]
    .iter()
    .find_map(|path| report.pointer(path))
    .filter(|value| !value.is_null())?;
    let sample_type_names = ["/metaData/sampleTypeNames", "/meta_data/sample_type_names"]
        .iter()
        .find_map(|path| session.pointer(path))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let range_count = session
        .get("ranges")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let statistics = session.get("statistics").and_then(|statistics| {
        (!statistics.is_null()).then(|| PcSamplingStatistics {
            pass_count: json_u64(statistics, &["passCount", "pass_count"]),
            total_samples: json_u64(statistics, &["totalSamples", "total_samples"]),
            start_clock_rate_hz: json_u64(statistics, &["startClockRateHz", "start_clock_rate_hz"]),
            end_clock_rate_hz: json_u64(statistics, &["endClockRateHz", "end_clock_rate_hz"]),
            stall_reason_means: float_array(
                statistics
                    .get("stallReasonMeans")
                    .or_else(|| statistics.get("stall_reason_means")),
            ),
            stall_reason_std_devs: float_array(
                statistics
                    .get("stallReasonStdDevs")
                    .or_else(|| statistics.get("stall_reason_std_devs")),
            ),
        })
    });
    Some(PcSamplingSummary {
        sample_type_names,
        range_count,
        statistics,
    })
}

fn json_u64(value: &serde_json::Value, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(serde_json::Value::as_u64))
}

fn float_array(value: Option<&serde_json::Value>) -> Vec<f32> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_f64)
                .map(|value| value as f32)
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Wire types (subset of NV.ShaderProfiler.Messages and NV.WarpViz)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
struct Report {
    #[prost(message, optional, tag = "3")]
    pc_counters_info: Option<PcCountersInfo>,
    #[prost(message, optional, tag = "6")]
    blob_table: Option<BlobTable>,
}

#[derive(Clone, PartialEq, Message)]
struct BlobTable {
    #[prost(message, repeated, tag = "1")]
    blobs: Vec<BlobEntry>,
}

#[derive(Clone, PartialEq, Message)]
struct BlobEntry {
    #[prost(uint32, optional, tag = "1")]
    id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    data: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "3")]
    uncompressed_size: Option<u64>,
    #[prost(int32, optional, tag = "4")]
    compression: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    obfuscation: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct PcCountersInfo {
    #[prost(message, optional, tag = "1")]
    pc_sampling_session: Option<PcSamplingSession>,
}

#[derive(Clone, PartialEq, Message)]
struct PcSamplingSession {
    #[prost(message, repeated, tag = "7")]
    function_groups: Vec<FunctionGroup>,
    #[prost(message, repeated, tag = "8")]
    modules: Vec<Module>,
    #[prost(message, repeated, tag = "9")]
    code_blocks: Vec<GpuCodeBlock>,
}

#[derive(Clone, PartialEq, Message)]
struct FunctionGroup {
    #[prost(message, optional, tag = "1")]
    graphics_pipeline: Option<GraphicsPipeline>,
    #[prost(message, optional, tag = "2")]
    compute_pipeline: Option<ComputePipeline>,
    #[prost(message, optional, tag = "3")]
    generic_function_group: Option<GenericFunctionGroup>,
}

#[derive(Clone, PartialEq, Message)]
struct GraphicsPipeline {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    api_type_name: Option<String>,
    #[prost(int32, optional, tag = "3")]
    driver_api: Option<i32>,
    #[prost(message, optional, tag = "4")]
    vertex: Option<PipelineStageInfo>,
    #[prost(message, optional, tag = "5")]
    tess_control: Option<PipelineStageInfo>,
    #[prost(message, optional, tag = "6")]
    tess_eval: Option<PipelineStageInfo>,
    #[prost(message, optional, tag = "7")]
    geometry: Option<PipelineStageInfo>,
    #[prost(message, optional, tag = "8")]
    task: Option<PipelineStageInfo>,
    #[prost(message, optional, tag = "9")]
    mesh: Option<PipelineStageInfo>,
    #[prost(message, optional, tag = "10")]
    fragment: Option<PipelineStageInfo>,
}

#[derive(Clone, PartialEq, Message)]
struct ComputePipeline {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    api_type_name: Option<String>,
    #[prost(int32, optional, tag = "3")]
    driver_api: Option<i32>,
    #[prost(message, optional, tag = "4")]
    compute: Option<PipelineStageInfo>,
}

#[derive(Clone, PartialEq, Message)]
struct GenericFunctionGroup {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    api_type_name: Option<String>,
    #[prost(int32, optional, tag = "3")]
    driver_api: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct PipelineStageInfo {
    #[prost(string, optional, tag = "1")]
    entrypoint_name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pipeline_stage_name: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct Module {
    #[prost(message, optional, tag = "1")]
    graphics_api_module: Option<GraphicsApiModule>,
    #[prost(message, optional, tag = "2")]
    cu_module: Option<CuModule>,
    #[prost(message, optional, tag = "3")]
    rt_core_user_cubin: Option<RtCoreUserCubin>,
    #[prost(message, optional, tag = "4")]
    rt_core_internal_redacted_cubin: Option<RtCoreInternalCubin>,
    #[prost(message, optional, tag = "5")]
    rt_core_internal_unredacted_cubin: Option<RtCoreInternalCubin>,
}

#[derive(Clone, PartialEq, Message)]
struct GraphicsApiModule {
    #[prost(int32, optional, tag = "1")]
    bytecode_type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    bytecode: Option<BlobRef>,
    #[prost(message, optional, tag = "3")]
    pdb: Option<BlobRef>,
}

#[derive(Clone, PartialEq, Message)]
struct CuModule {
    #[prost(int32, optional, tag = "1")]
    provider: Option<i32>,
    #[prost(message, optional, tag = "2")]
    cubin: Option<Elf>,
}

#[derive(Clone, PartialEq, Message)]
struct RtCoreUserCubin {
    #[prost(message, optional, tag = "1")]
    cubin: Option<Elf>,
    #[prost(int32, optional, tag = "2")]
    driver_api: Option<i32>,
    #[prost(uint32, repeated, tag = "3")]
    function_group_indices: Vec<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct RtCoreInternalCubin {
    #[prost(message, optional, tag = "1")]
    cubin: Option<Elf>,
}

#[derive(Clone, PartialEq, Message)]
struct GpuCodeBlock {
    #[prost(message, optional, tag = "1")]
    shader_instance: Option<ShaderInstance>,
    #[prost(message, optional, tag = "2")]
    cu_function: Option<CuFunction>,
}

#[derive(Clone, PartialEq, Message)]
struct ShaderInstance {
    #[prost(message, optional, tag = "1")]
    va_range: Option<VaRange>,
    #[prost(int32, optional, tag = "2")]
    shader_type: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    origin: Option<i32>,
    #[prost(message, optional, tag = "4")]
    instructions: Option<BlobRef>,
    #[prost(message, optional, tag = "5")]
    debug_info: Option<Elf>,
    #[prost(uint32, repeated, tag = "6")]
    function_group_indices: Vec<u32>,
    #[prost(message, optional, tag = "7")]
    common_program_meta: Option<CommonProgramMeta>,
    #[prost(message, optional, tag = "200")]
    graphics_program_meta: Option<GraphicsProgramMeta>,
    #[prost(message, optional, tag = "201")]
    compute_program_meta: Option<ComputeProgramMeta>,
    #[prost(message, optional, tag = "300")]
    back_compat_data: Option<BackCompatData>,
}

#[derive(Clone, PartialEq, Message)]
struct CuFunction {
    #[prost(message, optional, tag = "1")]
    va_range: Option<VaRange>,
    #[prost(int32, optional, tag = "2")]
    origin: Option<i32>,
    #[prost(message, optional, tag = "3")]
    instructions: Option<BlobRef>,
    #[prost(uint64, optional, tag = "4")]
    cubin_hash: Option<u64>,
    #[prost(uint32, optional, tag = "5")]
    symbol_index: Option<u32>,
    #[prost(uint32, repeated, tag = "6")]
    function_group_indices: Vec<u32>,
    #[prost(message, optional, tag = "7")]
    common_program_meta: Option<CommonProgramMeta>,
    #[prost(message, optional, tag = "8")]
    compute_program_meta: Option<ComputeProgramMeta>,
    #[prost(int32, optional, tag = "9")]
    cubin_provider: Option<i32>,
    #[prost(message, optional, tag = "300")]
    back_compat_data: Option<BackCompatData>,
}

#[derive(Clone, PartialEq, Message)]
struct VaRange {
    #[prost(uint64, optional, tag = "1")]
    address: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    size: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct CommonProgramMeta {
    #[prost(uint32, optional, tag = "1")]
    cuda_sm_version: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    registers_per_thread: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct GraphicsProgramMeta {
    #[prost(message, optional, tag = "1")]
    sph: Option<BlobRef>,
}

#[derive(Clone, PartialEq, Message)]
struct ComputeProgramMeta {
    #[prost(uint32, optional, tag = "1")]
    thread_group_size: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    barrier_count: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    static_smem_size: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    dynamic_smem_size: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    gpu_cta_dim_x: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    gpu_cta_dim_y: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    gpu_cta_dim_z: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct BackCompatData {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    api_type_name: Option<String>,
    #[prost(uint64, optional, tag = "3")]
    shader_module_hash: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct Elf {
    #[prost(message, optional, tag = "1")]
    reference: Option<BlobRef>,
}

#[derive(Clone, PartialEq, Message)]
struct BlobRef {
    #[prost(uint32, optional, tag = "1")]
    idx: Option<u32>,
}

// ---------------------------------------------------------------------------
// Blob decoding
// ---------------------------------------------------------------------------

fn decode_blobs(table: Option<&BlobTable>, keystream: &[u8]) -> Result<Vec<Blob>> {
    let Some(table) = table else {
        return Ok(Vec::new());
    };
    table
        .blobs
        .iter()
        .enumerate()
        .map(|(index, entry)| decode_blob(index, entry, keystream))
        .collect()
}

fn decode_blob(index: usize, entry: &BlobEntry, keystream: &[u8]) -> Result<Blob> {
    let compressed = entry.data.clone().unwrap_or_default();
    let compression = match entry.compression.unwrap_or(1) {
        0 | 1 => BlobCompression::None,
        2 => BlobCompression::Lz4,
        value => BlobCompression::Unknown(value),
    };
    let obfuscation = match entry.obfuscation.unwrap_or(1) {
        0 | 1 => BlobObfuscation::None,
        2 => BlobObfuscation::Simple,
        value => BlobObfuscation::Unknown(value),
    };
    let uncompressed_size = entry.uncompressed_size.unwrap_or(compressed.len() as u64);
    let mut info = BlobInfo {
        index,
        id: entry.id.unwrap_or(index as u32),
        stored_size: compressed.len(),
        uncompressed_size,
        compression: compression_name(compression),
        obfuscation: obfuscation_name(obfuscation),
        kind: BlobKind::Binary,
        decoded_size: None,
        sha256: None,
        error: None,
    };

    let unpacked = match compression {
        BlobCompression::None => {
            if compressed.len() as u64 != uncompressed_size {
                info.error = Some(format!(
                    "blob {index} is uncompressed but stores {} bytes; expected {uncompressed_size}",
                    compressed.len()
                ));
                None
            } else {
                Some(compressed)
            }
        }
        BlobCompression::Lz4 => match usize::try_from(uncompressed_size) {
            Ok(size) => match lz4_flex::block::decompress(&compressed, size) {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    info.error = Some(format!("blob {index} LZ4 decompression failed: {error}"));
                    None
                }
            },
            Err(_) => {
                info.error = Some(format!("blob {index} is too large for this platform"));
                None
            }
        },
        BlobCompression::Unknown(value) => {
            info.error = Some(format!(
                "blob {index} uses unknown compression enum {value}"
            ));
            None
        }
    };

    let decoded = unpacked.as_ref().and_then(|bytes| match obfuscation {
        BlobObfuscation::None => Some(bytes.clone()),
        BlobObfuscation::Simple => match deobfuscate(index, bytes, keystream) {
            Ok(decoded) => Some(decoded),
            Err(error) => {
                info.error = Some(error.to_string());
                None
            }
        },
        BlobObfuscation::Unknown(value) => {
            info.error = Some(format!(
                "blob {index} uses unknown obfuscation enum {value}"
            ));
            None
        }
    });

    if let Some(bytes) = decoded.as_ref() {
        info.decoded_size = Some(bytes.len());
        info.kind = classify(bytes);
        info.sha256 = Some(hex_digest(bytes));
    }
    Ok(Blob {
        info,
        unpacked,
        decoded,
    })
}

fn deobfuscate(index: usize, data: &[u8], keystream: &[u8]) -> Result<Vec<u8>> {
    if keystream.is_empty() {
        return Err(Error::Shader(format!(
            "blob {index} is OBFUSCATION_SIMPLE but no keystream is available"
        )));
    }
    if data.len() > keystream.len() {
        return Err(Error::Shader(format!(
            "blob {index} needs {} keystream bytes, but only {} are available; pass --keystream or NGFX_SHADER_KEYSTREAM",
            data.len(),
            keystream.len()
        )));
    }
    Ok(data
        .iter()
        .zip(keystream.iter())
        .map(|(byte, key)| byte ^ key)
        .collect())
}

fn compression_name(value: BlobCompression) -> &'static str {
    match value {
        BlobCompression::None => "none",
        BlobCompression::Lz4 => "lz4",
        BlobCompression::Unknown(_) => "unknown",
    }
}

fn obfuscation_name(value: BlobObfuscation) -> &'static str {
    match value {
        BlobObfuscation::None => "none",
        BlobObfuscation::Simple => "simple",
        BlobObfuscation::Unknown(_) => "unknown",
    }
}

fn classify(bytes: &[u8]) -> BlobKind {
    if bytes.starts_with(&SPIRV_MAGIC) {
        BlobKind::Spirv
    } else if bytes.starts_with(&ELF_MAGIC) {
        BlobKind::Elf
    } else {
        BlobKind::Binary
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(bytes)
}

// ---------------------------------------------------------------------------
// Catalog construction
// ---------------------------------------------------------------------------

fn decode_modules(info: Option<&PcCountersInfo>, blobs: &[Blob]) -> Vec<ModuleInfo> {
    let Some(session) = info.and_then(|info| info.pc_sampling_session.as_ref()) else {
        return Vec::new();
    };
    session
        .modules
        .iter()
        .enumerate()
        .map(|(index, module)| {
            let (kind, blob_index, provider, driver_api, function_group_indices) =
                if let Some(graphics) = &module.graphics_api_module {
                    (
                        bytecode_kind(graphics.bytecode_type),
                        graphics
                            .bytecode
                            .as_ref()
                            .and_then(|reference| valid_ref(reference, blobs)),
                        None,
                        None,
                        Vec::new(),
                    )
                } else if let Some(cu) = &module.cu_module {
                    (
                        "cubin",
                        cu.cubin
                            .as_ref()
                            .and_then(elf_ref)
                            .and_then(|value| valid_index(value, blobs)),
                        Some(module_provider(cu.provider)),
                        None,
                        Vec::new(),
                    )
                } else if let Some(user) = &module.rt_core_user_cubin {
                    (
                        "rt_core_user_cubin",
                        user.cubin
                            .as_ref()
                            .and_then(elf_ref)
                            .and_then(|value| valid_index(value, blobs)),
                        None,
                        Some(driver_api_name(user.driver_api)),
                        user.function_group_indices.clone(),
                    )
                } else if let Some(internal) = &module.rt_core_internal_redacted_cubin {
                    (
                        "rt_core_internal_redacted_cubin",
                        internal
                            .cubin
                            .as_ref()
                            .and_then(elf_ref)
                            .and_then(|value| valid_index(value, blobs)),
                        None,
                        None,
                        Vec::new(),
                    )
                } else if let Some(internal) = &module.rt_core_internal_unredacted_cubin {
                    (
                        "rt_core_internal_unredacted_cubin",
                        internal
                            .cubin
                            .as_ref()
                            .and_then(elf_ref)
                            .and_then(|value| valid_index(value, blobs)),
                        None,
                        None,
                        Vec::new(),
                    )
                } else {
                    ("unknown", None, None, None, Vec::new())
                };
            ModuleInfo {
                index,
                kind: kind.to_owned(),
                blob_index,
                provider,
                driver_api,
                function_group_indices,
            }
        })
        .collect()
}

fn decode_shaders(
    device_index: usize,
    info: Option<&PcCountersInfo>,
    blobs: &[Blob],
    modules: &[ModuleInfo],
) -> Vec<ShaderInfo> {
    let Some(session) = info.and_then(|info| info.pc_sampling_session.as_ref()) else {
        return Vec::new();
    };
    session
        .code_blocks
        .iter()
        .enumerate()
        .map(|(index, code_block)| {
            if let Some(shader) = &code_block.shader_instance {
                shader_info(device_index, index, shader, session, blobs, modules)
            } else if let Some(function) = &code_block.cu_function {
                cu_function_info(device_index, index, function, session, blobs, modules)
            } else {
                empty_shader(device_index, index)
            }
        })
        .collect()
}

fn empty_shader(device_index: usize, index: usize) -> ShaderInfo {
    ShaderInfo {
        index,
        device_index,
        source: "unknown",
        name: format!("shader {index}"),
        entry_point: None,
        source_file: None,
        stage: "unknown".into(),
        shader_type: "unknown".into(),
        origin: "unknown".into(),
        pipeline: None,
        sm: None,
        registers_per_thread: None,
        threads_per_block: None,
        static_smem_bytes: None,
        barrier_count: None,
        occupancy: None,
        address: None,
        size: None,
        instructions_blob: None,
        debug_blob: None,
        cubin_blob: None,
        cubin_size: None,
        cubin_sha256: None,
        function_group_indices: Vec::new(),
        warnings: vec!["code block has neither a shader instance nor a CU function".into()],
    }
}

fn shader_info(
    device_index: usize,
    index: usize,
    shader: &ShaderInstance,
    session: &PcSamplingSession,
    blobs: &[Blob],
    modules: &[ModuleInfo],
) -> ShaderInfo {
    let mut warnings = Vec::new();
    let source_file = modules
        .get(index)
        .and_then(|module| module.blob_index)
        .and_then(|blob_index| blobs.get(blob_index))
        .and_then(|blob| blob.decoded().ok())
        .and_then(spirv_source_file);
    let group = session
        .function_groups
        .get(*shader.function_group_indices.first().unwrap_or(&0) as usize);
    let (pipeline_name, entry_point, stage) = group_details(group, shader.shader_type);
    let pipeline_name = pipeline_name.filter(|value| !looks_like_pointer(value));
    let instructions_blob = shader
        .instructions
        .as_ref()
        .and_then(|reference| valid_ref(reference, blobs));
    let debug_blob = shader
        .debug_info
        .as_ref()
        .and_then(elf_ref)
        .and_then(|value| valid_index(value, blobs));
    let cubin_blob = debug_blob.or_else(|| {
        instructions_blob.filter(|value| blob_kind(blobs, *value) == Some(BlobKind::Elf))
    });
    if shader.debug_info.is_none() {
        warnings.push("shader instance has no debug ELF reference".into());
    }
    if cubin_blob.is_none() {
        warnings.push("no ELF/cubin blob is attached to this shader instance".into());
    }
    if let Some(blob) = cubin_blob.and_then(|value| blobs.get(value))
        && blob.info.kind != BlobKind::Elf
    {
        warnings.push(format!(
            "debug blob {} is {:?}, not an ELF/cubin",
            blob.info.index, blob.info.kind
        ));
    }
    if instructions_blob.is_none() {
        warnings.push("shader instance has no SASS/instructions blob".into());
    }

    let name = shader
        .back_compat_data
        .as_ref()
        .and_then(|data| non_empty(data.name.as_deref()))
        .or_else(|| entry_point.clone().filter(|value| value != "main"))
        .or_else(|| source_file.as_deref().map(file_label))
        .or_else(|| pipeline_name.clone())
        .unwrap_or_else(|| format!("{} shader {index}", stage));
    let sm = shader
        .common_program_meta
        .as_ref()
        .and_then(|meta| meta.cuda_sm_version)
        .map(sm_name);
    let registers_per_thread = shader
        .common_program_meta
        .as_ref()
        .and_then(|meta| meta.registers_per_thread);
    let threads_per_block = shader
        .compute_program_meta
        .as_ref()
        .and_then(compute_threads);
    let static_smem_bytes = shader
        .compute_program_meta
        .as_ref()
        .and_then(|meta| meta.static_smem_size);
    let barrier_count = shader
        .compute_program_meta
        .as_ref()
        .and_then(|meta| meta.barrier_count);
    let occupancy = occupancy_estimate(
        sm.as_deref(),
        registers_per_thread,
        threads_per_block,
        static_smem_bytes,
    );

    ShaderInfo {
        index,
        device_index,
        source: "shader_instance",
        name,
        entry_point,
        source_file,
        stage,
        shader_type: shader_type_name(shader.shader_type),
        origin: origin_name(shader.origin),
        pipeline: pipeline_name,
        sm,
        registers_per_thread,
        threads_per_block,
        static_smem_bytes,
        barrier_count,
        occupancy,
        address: shader.va_range.as_ref().and_then(|range| range.address),
        size: shader.va_range.as_ref().and_then(|range| range.size),
        instructions_blob,
        debug_blob,
        cubin_blob,
        cubin_size: cubin_blob
            .and_then(|value| blobs.get(value))
            .and_then(|blob| blob.info.decoded_size),
        cubin_sha256: cubin_blob
            .and_then(|value| blobs.get(value))
            .and_then(|blob| blob.info.sha256.clone()),
        function_group_indices: shader.function_group_indices.clone(),
        warnings,
    }
}

fn cu_function_info(
    device_index: usize,
    index: usize,
    function: &CuFunction,
    session: &PcSamplingSession,
    blobs: &[Blob],
    modules: &[ModuleInfo],
) -> ShaderInfo {
    let mut warnings = Vec::new();
    let group = session
        .function_groups
        .get(*function.function_group_indices.first().unwrap_or(&0) as usize);
    let (pipeline_name, entry_point, stage) = group_details(group, Some(8));
    let pipeline_name = pipeline_name.filter(|value| !looks_like_pointer(value));
    let instructions_blob = function
        .instructions
        .as_ref()
        .and_then(|reference| valid_ref(reference, blobs));
    let wanted_provider = function
        .cubin_provider
        .map(|value| module_provider(Some(value)));
    let cubin_blob = modules
        .iter()
        .filter(|module| module.kind == "cubin")
        .find(|module| {
            wanted_provider
                .as_ref()
                .is_none_or(|wanted| module.provider.as_ref() == Some(wanted))
                && (function.function_group_indices.is_empty()
                    || module.function_group_indices.is_empty()
                    || module
                        .function_group_indices
                        .iter()
                        .any(|value| function.function_group_indices.contains(value)))
        })
        .and_then(|module| module.blob_index);
    if cubin_blob.is_none() {
        warnings.push("no CU module cubin is attached to this function".into());
    }
    if instructions_blob.is_none() {
        warnings.push("CU function has no SASS/instructions blob".into());
    }
    let name = function
        .back_compat_data
        .as_ref()
        .and_then(|data| non_empty(data.name.as_deref()))
        .or_else(|| entry_point.clone())
        .or_else(|| pipeline_name.clone())
        .unwrap_or_else(|| format!("function {index}"));
    let sm = function
        .common_program_meta
        .as_ref()
        .and_then(|meta| meta.cuda_sm_version)
        .map(sm_name);
    let registers_per_thread = function
        .common_program_meta
        .as_ref()
        .and_then(|meta| meta.registers_per_thread);
    let threads_per_block = function
        .compute_program_meta
        .as_ref()
        .and_then(compute_threads);
    let static_smem_bytes = function
        .compute_program_meta
        .as_ref()
        .and_then(|meta| meta.static_smem_size);
    let barrier_count = function
        .compute_program_meta
        .as_ref()
        .and_then(|meta| meta.barrier_count);
    let occupancy = occupancy_estimate(
        sm.as_deref(),
        registers_per_thread,
        threads_per_block,
        static_smem_bytes,
    );
    ShaderInfo {
        index,
        device_index,
        source: "cu_function",
        name,
        entry_point,
        source_file: None,
        stage,
        shader_type: "cuda".into(),
        origin: origin_name(function.origin),
        pipeline: pipeline_name,
        sm,
        registers_per_thread,
        threads_per_block,
        static_smem_bytes,
        barrier_count,
        occupancy,
        address: function.va_range.as_ref().and_then(|range| range.address),
        size: function.va_range.as_ref().and_then(|range| range.size),
        instructions_blob,
        debug_blob: None,
        cubin_blob,
        cubin_size: cubin_blob
            .and_then(|value| blobs.get(value))
            .and_then(|blob| blob.info.decoded_size),
        cubin_sha256: cubin_blob
            .and_then(|value| blobs.get(value))
            .and_then(|blob| blob.info.sha256.clone()),
        function_group_indices: function.function_group_indices.clone(),
        warnings,
    }
}

fn compute_threads(meta: &ComputeProgramMeta) -> Option<u32> {
    meta.thread_group_size.or_else(|| {
        meta.gpu_cta_dim_x
            .zip(meta.gpu_cta_dim_y)
            .zip(meta.gpu_cta_dim_z)
            .map(|((x, y), z)| x.saturating_mul(y).saturating_mul(z))
    })
}

fn occupancy_estimate(
    sm: Option<&str>,
    registers_per_thread: Option<u32>,
    threads_per_block: Option<u32>,
    static_smem_bytes: Option<u32>,
) -> Option<OccupancyEstimate> {
    let sm = sm?;
    let limits = sm_limits(sm)?;
    let mut assumptions = vec![
        "Per-SM limits are a conservative table for the reported SM generation; verify them on the target part.".into(),
        "Occupancy is a static estimate from registers, block size, and static shared memory; it ignores runtime limits, barriers, and allocation granularity.".into(),
    ];
    let warps_by_registers = registers_per_thread.map(|registers| {
        let per_warp = registers.max(1).saturating_mul(32);
        (limits.registers_per_sm / per_warp).min(limits.max_warps_per_sm)
    });
    let warps_by_threads = threads_per_block.map(|threads| {
        let threads = threads.max(1);
        (limits.max_threads_per_sm / threads)
            .saturating_mul(threads.div_ceil(32))
            .min(limits.max_warps_per_sm)
    });
    let warps_by_smem = static_smem_bytes.filter(|bytes| *bytes > 0).map(|bytes| {
        let blocks = (limits.smem_per_sm / bytes).max(1);
        blocks
            .saturating_mul(threads_per_block.unwrap_or(32).div_ceil(32))
            .min(limits.max_warps_per_sm)
    });
    let estimated = [warps_by_registers, warps_by_threads, warps_by_smem]
        .into_iter()
        .flatten()
        .min();
    let limiting_factor = estimated.map(|value| {
        if warps_by_registers == Some(value) {
            "registers"
        } else if warps_by_threads == Some(value) {
            "threads_per_block"
        } else {
            "shared_memory"
        }
    });
    if threads_per_block.is_none() {
        assumptions.push(
            "Block size was not captured; only the register-limited warp count is reported.".into(),
        );
    }
    Some(OccupancyEstimate {
        architecture: Some(sm.to_owned()),
        registers_per_thread,
        threads_per_block,
        static_smem_bytes,
        max_warps_by_registers: warps_by_registers,
        max_warps_by_threads: warps_by_threads,
        max_warps_by_smem: warps_by_smem,
        estimated_warps_per_sm: estimated,
        estimated_occupancy_pct: estimated
            .map(|warps| 100.0 * warps as f64 / limits.max_warps_per_sm as f64),
        limiting_factor: limiting_factor.map(str::to_owned),
        assumptions,
    })
}

struct SmLimits {
    max_threads_per_sm: u32,
    max_warps_per_sm: u32,
    registers_per_sm: u32,
    smem_per_sm: u32,
}

fn sm_limits(sm: &str) -> Option<SmLimits> {
    let generation: u32 = sm.strip_prefix("SM")?.parse().ok()?;
    let (threads, warps) = if generation >= 120 {
        (1536, 48)
    } else {
        (2048, 64)
    };
    Some(SmLimits {
        max_threads_per_sm: threads,
        max_warps_per_sm: warps,
        registers_per_sm: 65_536,
        smem_per_sm: 228 * 1024,
    })
}

fn group_details(
    group: Option<&FunctionGroup>,
    shader_type: Option<i32>,
) -> (Option<String>, Option<String>, String) {
    let Some(group) = group else {
        return (None, None, "unknown".into());
    };
    if let Some(graphics) = &group.graphics_pipeline {
        let stage = match shader_type.unwrap_or(0) {
            1 => graphics.vertex.as_ref(),
            2 => graphics.tess_control.as_ref(),
            3 => graphics.tess_eval.as_ref(),
            4 => graphics.geometry.as_ref(),
            5 => graphics.task.as_ref(),
            6 => graphics.mesh.as_ref(),
            7 => graphics.fragment.as_ref(),
            _ => None,
        };
        return (
            non_empty(graphics.name.as_deref())
                .or_else(|| non_empty(graphics.api_type_name.as_deref())),
            stage.and_then(|stage| non_empty(stage.entrypoint_name.as_deref())),
            stage
                .and_then(|stage| non_empty(stage.pipeline_stage_name.as_deref()))
                .unwrap_or_else(|| shader_type_stage(shader_type)),
        );
    }
    if let Some(compute) = &group.compute_pipeline {
        return (
            non_empty(compute.name.as_deref())
                .or_else(|| non_empty(compute.api_type_name.as_deref())),
            compute
                .compute
                .as_ref()
                .and_then(|stage| non_empty(stage.entrypoint_name.as_deref())),
            compute
                .compute
                .as_ref()
                .and_then(|stage| non_empty(stage.pipeline_stage_name.as_deref()))
                .unwrap_or_else(|| "compute".into()),
        );
    }
    if let Some(generic) = &group.generic_function_group {
        return (
            non_empty(generic.name.as_deref())
                .or_else(|| non_empty(generic.api_type_name.as_deref())),
            None,
            shader_type_stage(shader_type),
        );
    }
    (None, None, "unknown".into())
}

fn shader_type_stage(shader_type: Option<i32>) -> String {
    match shader_type.unwrap_or(0) {
        1 => "vertex",
        2 => "tess_control",
        3 => "tess_eval",
        4 => "geometry",
        5 => "task",
        6 => "mesh",
        7 => "fragment",
        8 => "compute",
        _ => "unknown",
    }
    .into()
}

fn shader_type_name(value: Option<i32>) -> String {
    match value.unwrap_or(0) {
        1 => "vertex",
        2 => "tess_control",
        3 => "tess_eval",
        4 => "geometry",
        5 => "task",
        6 => "mesh",
        7 => "fragment",
        8 => "compute",
        _ => "unknown",
    }
    .into()
}

fn origin_name(value: Option<i32>) -> String {
    match value.unwrap_or(0) {
        0 => "user",
        1 => "driver",
        2 => "nvidia_sdk",
        _ => "unknown",
    }
    .into()
}

fn bytecode_kind(value: Option<i32>) -> &'static str {
    match value.unwrap_or(0) {
        1 => "dxil",
        2 => "spirv",
        _ => "bytecode",
    }
}

fn module_provider(value: Option<i32>) -> String {
    match value.unwrap_or(0) {
        1 => "cuda",
        2 => "cugfx",
        3 => "rtcore",
        _ => "unknown",
    }
    .into()
}

fn driver_api_name(value: Option<i32>) -> String {
    match value.unwrap_or(0) {
        1 => "d3d12",
        2 => "vulkan",
        3 => "cuda",
        _ => "unknown",
    }
    .into()
}

fn sm_name(value: u32) -> String {
    if value == 0 {
        return "unknown".into();
    }
    let major = (value >> 16) & 0xff;
    let minor = (value >> 8) & 0xff;
    if major > 0 {
        format!("SM{major}{minor}")
    } else {
        format!("0x{value:x}")
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(str::to_owned)
}

fn looks_like_pointer(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit()))
}

fn valid_ref(reference: &BlobRef, blobs: &[Blob]) -> Option<usize> {
    reference
        .idx
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value < blobs.len())
}

fn valid_index(index: usize, blobs: &[Blob]) -> Option<usize> {
    (index < blobs.len()).then_some(index)
}

fn elf_ref(elf: &Elf) -> Option<usize> {
    elf.reference
        .as_ref()
        .and_then(|reference| reference.idx)
        .and_then(|value| usize::try_from(value).ok())
}

fn blob_kind(blobs: &[Blob], index: usize) -> Option<BlobKind> {
    blobs.get(index).map(|blob| blob.info.kind)
}

fn spirv_source_file(bytes: &[u8]) -> Option<String> {
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let printable = (0x20..=0x7e).contains(&byte);
        match (printable, start) {
            (true, None) => start = Some(index),
            (false, Some(begin)) => {
                if let Some(found) = source_file_in_run(&bytes[begin..index]) {
                    return Some(found);
                }
                start = None;
            }
            _ => {}
        }
    }
    start.and_then(|begin| source_file_in_run(&bytes[begin..]))
}

fn source_file_in_run(run: &[u8]) -> Option<String> {
    const EXTENSIONS: &[&str] = &[
        ".comp", ".vert", ".frag", ".geom", ".tesc", ".tese", ".mesh", ".task", ".rgen", ".rchit",
        ".rmiss", ".rahit", ".rint", ".rcall", ".slang",
    ];
    if run.len() < 5 {
        return None;
    }
    let candidate = std::str::from_utf8(run).ok()?;
    let lower = candidate.to_ascii_lowercase();
    EXTENSIONS
        .iter()
        .find_map(|extension| {
            lower
                .find(extension)
                .map(|end| &candidate[..end + extension.len()])
        })
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn file_label(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(path)
        .to_owned()
}

// ---------------------------------------------------------------------------
// Keystream and nvdisasm helpers
// ---------------------------------------------------------------------------

pub fn load_keystream(explicit: Option<&Path>) -> Result<(Vec<u8>, String)> {
    if let Some(path) = explicit {
        return Ok((fs::read(path)?, path.display().to_string()));
    }
    for variable in ["NGFX_SHADER_KEYSTREAM", "NGFX_KEYSTREAM"] {
        if let Some(value) = env::var_os(variable) {
            let path = PathBuf::from(value);
            return Ok((fs::read(&path)?, path.display().to_string()));
        }
    }
    Ok((
        BUILTIN_KEYSTREAM.to_vec(),
        "built-in Nsight 2026.3 stream".into(),
    ))
}

/// Recover a stream from a known plaintext that corresponds to one obfuscated
/// blob. The same XOR stream is reused by the other blobs, so this is enough
/// to decode the rest of the capture once a matching plaintext is available.
pub fn recover_keystream(
    document: &TraceDocument,
    known_plaintext: &Path,
) -> Result<(Vec<u8>, String)> {
    let plaintext = fs::read(known_plaintext)?;
    if plaintext.is_empty() {
        return Err(Error::Shader("known-plaintext file is empty".into()));
    }
    let catalog = ShaderCatalog::open(document, &[], "known-plaintext")?;
    let mut best: Option<(Vec<u8>, String, usize)> = None;
    for device in &catalog.devices {
        for blob in &device.blobs {
            if blob.obfuscation != "simple" {
                continue;
            }
            let Some(raw) = catalog.raw_for_recovery(device.device_index, blob.index) else {
                continue;
            };
            if raw.len() < plaintext.len() {
                continue;
            }
            let key = xor_recover(&raw[..plaintext.len()], &plaintext);
            let score = key_score(&catalog, &key);
            let label = if raw.len() == plaintext.len() {
                format!("recovered from {}", known_plaintext.display())
            } else {
                format!(
                    "prefix of {} bytes recovered from {}",
                    plaintext.len(),
                    known_plaintext.display()
                )
            };
            if best
                .as_ref()
                .is_none_or(|(_, _, best_score)| score > *best_score)
            {
                best = Some((key, label, score));
            }
        }
    }
    let (key, label, score) = best.ok_or_else(|| {
        Error::Shader(format!(
            "{} does not match any obfuscated blob length",
            known_plaintext.display()
        ))
    })?;
    if score == 0 {
        return Err(Error::Shader(format!(
            "{} did not validate against any decoded shader/ELF blob",
            known_plaintext.display()
        )));
    }
    let needed = catalog
        .devices
        .iter()
        .flat_map(|device| &device.blobs)
        .filter(|blob| blob.obfuscation == "simple")
        .map(|blob| blob.uncompressed_size as usize)
        .max()
        .unwrap_or(0);
    if needed > key.len()
        && key.len() <= BUILTIN_KEYSTREAM.len()
        && key
            .iter()
            .zip(BUILTIN_KEYSTREAM)
            .all(|(left, right)| left == right)
    {
        return Ok((
            BUILTIN_KEYSTREAM[..needed].to_vec(),
            format!("{label}; extended with the built-in Nsight 2026.3 stream"),
        ));
    }
    Ok((key, label))
}

fn xor_recover(obfuscated: &[u8], plaintext: &[u8]) -> Vec<u8> {
    obfuscated
        .iter()
        .zip(plaintext.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn key_score(catalog: &ShaderCatalog, key: &[u8]) -> usize {
    let mut score = 0;
    for device in &catalog.devices {
        for blob in &device.blobs {
            if blob.obfuscation != "simple" {
                continue;
            }
            let Some(raw) = catalog.raw_for_recovery(device.device_index, blob.index) else {
                continue;
            };
            let length = raw.len().min(key.len());
            let decoded: Vec<u8> = raw[..length]
                .iter()
                .zip(key[..length].iter())
                .map(|(left, right)| left ^ right)
                .collect();
            score += match classify(&decoded) {
                BlobKind::Spirv | BlobKind::Elf => 2,
                BlobKind::Binary => 0,
            };
        }
    }
    score
}

// ---------------------------------------------------------------------------
// External disassembly
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SassFunctionStats {
    pub name: String,
    pub start: u64,
    pub length: u64,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SassSourceLine {
    pub file: String,
    pub line: u32,
    pub instruction_count: usize,
    pub first_offset: u64,
    pub last_offset: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SassStats {
    pub instruction_count: usize,
    pub function_count: usize,
    pub functions: Vec<SassFunctionStats>,
    pub source_line_count: usize,
    pub source_lines: Vec<SassSourceLine>,
    pub opcodes: std::collections::BTreeMap<String, usize>,
    pub loads: usize,
    pub stores: usize,
    pub constant_loads: usize,
    pub spills_load: usize,
    pub spills_store: usize,
    pub atomics: usize,
    pub branches: usize,
    pub barriers: usize,
    pub textures: usize,
    pub predicated: usize,
    pub control_flow: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Disassembly {
    pub tool: String,
    pub args: Vec<String>,
    pub text: String,
    pub registers: Option<u32>,
    pub registers_hint: Option<String>,
    pub stats: SassStats,
    pub stats_source: String,
    pub warnings: Vec<String>,
}

pub fn disassemble(cubin: &[u8], nvdisasm: Option<&Path>) -> Result<Disassembly> {
    let tool = discover_nvdisasm(nvdisasm)?;
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(cubin)?;
    file.flush()?;
    let primary = ["-c", "-g", "-plr", "-lrm", "count"];
    let fallback = ["-c", "-g"];
    let mut warnings = Vec::new();
    let (args, output) = match run_nvdisasm(&tool, &primary, file.path()) {
        Ok(output) => (primary.as_slice(), output),
        Err(error) => {
            warnings.push(error);
            let output = run_nvdisasm(&tool, &fallback, file.path()).map_err(|fallback_error| {
                Error::Shader(format!(
                    "{} failed with register life ranges and without them: {fallback_error}",
                    tool.display()
                ))
            })?;
            warnings.push("register life ranges unavailable; retried with -c -g".into());
            (fallback.as_slice(), output)
        }
    };
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let registers_hint = text
        .lines()
        .find(|line| line.contains("SHI_REGISTERS"))
        .map(str::trim)
        .map(str::to_owned);
    let registers = registers_hint.as_deref().and_then(parse_registers);
    let (mut stats, stats_source) =
        match run_nvdisasm(&tool, &["--emit-json", "-c", "-g"], file.path()) {
            Ok(output) => match serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                Ok(value) => (sass_stats_from_json(&value), "nvdisasm_json".to_owned()),
                Err(error) => {
                    warnings.push(format!("nvdisasm JSON output could not be parsed: {error}"));
                    (SassStats::default(), "unavailable".to_owned())
                }
            },
            Err(error) => {
                warnings.push(format!("structured SASS stats unavailable: {error}"));
                (SassStats::default(), "unavailable".to_owned())
            }
        };
    let (source_line_count, source_lines) = sass_source_lines(&text);
    stats.source_line_count = source_line_count;
    stats.source_lines = source_lines;
    Ok(Disassembly {
        tool: tool.display().to_string(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        text,
        registers,
        registers_hint,
        stats,
        stats_source,
        warnings,
    })
}

fn sass_source_lines(text: &str) -> (usize, Vec<SassSourceLine>) {
    let mut current: Option<(String, u32)> = None;
    let mut lines: std::collections::BTreeMap<(String, u32), SassSourceLine> =
        std::collections::BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.split("//## File ").nth(1) {
            if let Some((file, line_number)) = rest.rsplit_once(", line ") {
                let file = file.trim().trim_matches('"').to_owned();
                if !file.is_empty()
                    && let Ok(line_number) = line_number.trim().parse::<u32>()
                {
                    current = Some((file, line_number));
                }
            }
            continue;
        }
        let Some((file, line_number)) = &current else {
            continue;
        };
        let Some(offset) = parse_instruction_offset(line) else {
            continue;
        };
        let entry = lines
            .entry((file.clone(), *line_number))
            .or_insert_with(|| SassSourceLine {
                file: file.clone(),
                line: *line_number,
                instruction_count: 0,
                first_offset: offset,
                last_offset: offset,
            });
        entry.instruction_count += 1;
        entry.first_offset = entry.first_offset.min(offset);
        entry.last_offset = entry.last_offset.max(offset);
    }
    let count = lines.len();
    let mut values: Vec<_> = lines.into_values().collect();
    values.sort_by(|left, right| {
        right
            .instruction_count
            .cmp(&left.instruction_count)
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.line.cmp(&right.line))
    });
    values.truncate(64);
    (count, values)
}

fn parse_instruction_offset(line: &str) -> Option<u64> {
    let start = line.find("/*")? + 2;
    let end = line[start..].find("*/")? + start;
    u64::from_str_radix(line[start..end].trim(), 16).ok()
}

fn sass_stats_from_json(value: &serde_json::Value) -> SassStats {
    let mut stats = SassStats::default();
    let Some(functions) = value.get(1).and_then(serde_json::Value::as_array) else {
        return stats;
    };
    for function in functions {
        let name = function
            .get("function-name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unnamed>")
            .to_owned();
        let start = function
            .get("start")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let length = function
            .get("length")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let instructions = function
            .get("sass-instructions")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        stats.function_count += 1;
        stats.instruction_count += instructions.len();
        stats.functions.push(SassFunctionStats {
            name,
            start,
            length,
            instruction_count: instructions.len(),
        });
        for instruction in instructions {
            let opcode = instruction
                .get("opcode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("UNKNOWN");
            *stats.opcodes.entry(opcode.to_owned()).or_default() += 1;
            let upper = opcode.to_ascii_uppercase();
            if upper.starts_with("LD") {
                stats.loads += 1;
                if upper.starts_with("LDC") {
                    stats.constant_loads += 1;
                }
                if upper.starts_with("LDL") {
                    stats.spills_load += 1;
                }
            }
            if upper.starts_with("ST") {
                stats.stores += 1;
                if upper.starts_with("STL") {
                    stats.spills_store += 1;
                }
            }
            if upper.starts_with("ATOM") || upper.starts_with("RED") {
                stats.atomics += 1;
            }
            if ["BRA", "BRX", "JMP", "CALL", "RET", "EXIT", "BSSY", "BSYNC"]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
            {
                stats.branches += 1;
            }
            if ["BAR", "MEMBAR", "DEPBAR", "WARPSYNC"]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
            {
                stats.barriers += 1;
            }
            if ["TEX", "TLD", "TXQ", "SULD", "SURG"]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
            {
                stats.textures += 1;
            }
            if instruction.get("predicate").is_some() {
                stats.predicated += 1;
            }
            if instruction
                .get("other-attributes")
                .and_then(|attributes| attributes.get("control-flow"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
            {
                stats.control_flow += 1;
            }
        }
    }
    stats
}

fn parse_registers(line: &str) -> Option<u32> {
    line.split("SHI_REGISTERS=")
        .nth(1)?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn run_nvdisasm(
    tool: &Path,
    args: &[&str],
    cubin: &Path,
) -> std::result::Result<std::process::Output, String> {
    let output = Command::new(tool)
        .args(args)
        .arg(cubin)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", tool.display()))?;
    if output.status.success() {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(format!(
        "{} exited with {}: {}{}",
        tool.display(),
        output.status,
        stderr.trim(),
        if stdout.trim().is_empty() {
            String::new()
        } else {
            format!("\n{}", stdout.trim())
        }
    ))
}

fn discover_nvdisasm(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return require_file(path);
    }
    if let Some(value) = env::var_os("NGFX_NVDISASM") {
        return require_file(Path::new(&value));
    }
    if let Ok(path) = which("nvdisasm") {
        return Ok(path);
    }
    for root in [
        PathBuf::from("/usr/local/cuda/bin"),
        PathBuf::from("/usr/local/cuda-13.0/bin"),
        PathBuf::from("/usr/local/cuda-12.9/bin"),
        PathBuf::from("/usr/local/cuda-12.8/bin"),
    ] {
        let candidate = root.join("nvdisasm");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(Error::Shader(
        "nvdisasm was not found; pass --nvdisasm, set NGFX_NVDISASM, or use --cubin only".into(),
    ))
}

fn require_file(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        Ok(path.to_path_buf())
    } else {
        Err(Error::Shader(format!(
            "required executable was not found: {}",
            path.display()
        )))
    }
}

fn which(name: &str) -> Result<PathBuf> {
    let Some(paths) = env::var_os("PATH") else {
        return Err(Error::Shader(format!("{name} was not found in PATH")));
    };
    for directory in env::split_paths(&paths) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(Error::Shader(format!("{name} was not found in PATH")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_stream_covers_the_validated_capture_set() {
        assert!(BUILTIN_KEYSTREAM.len() >= 239_592);
        assert!(!BUILTIN_KEYSTREAM.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn reused_xor_stream_is_recovered_from_one_known_plaintext() {
        let key = b"known plaintext recovers the reused XOR stream!!";
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(key.iter())
            .map(|(byte, key)| byte ^ key)
            .collect();
        assert_eq!(xor_recover(&ciphertext, plaintext), key[..plaintext.len()]);
    }

    #[test]
    fn lz4_and_simple_obfuscation_decode_to_an_elf_magic() {
        let mut plain = vec![0u8; 512];
        plain[..4].copy_from_slice(b"\x7fELF");
        let key = vec![0x5a; plain.len()];
        let obfuscated_plain: Vec<u8> = plain
            .iter()
            .zip(key.iter())
            .map(|(byte, key)| byte ^ key)
            .collect();
        let compressed = lz4_flex::block::compress(&obfuscated_plain);
        let entry = BlobEntry {
            id: Some(7),
            data: Some(compressed),
            uncompressed_size: Some(plain.len() as u64),
            compression: Some(2),
            obfuscation: Some(2),
        };
        let blob = decode_blob(0, &entry, &key).unwrap();
        assert_eq!(blob.info.kind, BlobKind::Elf);
        assert_eq!(blob.decoded().unwrap(), plain);
    }

    #[test]
    fn source_file_scanner_prefers_shader_extensions() {
        let bytes = b"prefix\0/tmp/atmosphera2/shaders/terrain.frag\0suffix";
        assert_eq!(
            spirv_source_file(bytes).as_deref(),
            Some("/tmp/atmosphera2/shaders/terrain.frag")
        );
        assert_eq!(file_label("/tmp/terrain.frag"), "terrain.frag");
    }

    #[test]
    fn sm_version_formatting_matches_cuda_words() {
        assert_eq!(sm_name(0x0008_0600), "SM86");
        assert_eq!(sm_name(0x000c_0000), "SM120");
        assert_eq!(sm_name(0), "unknown");
    }

    #[test]
    fn register_hint_parses_the_sectioninfo_value() {
        assert_eq!(
            parse_registers(".sectioninfo\t@\"SHI_REGISTERS=107\""),
            Some(107)
        );
        assert_eq!(parse_registers("no register value"), None);
    }
}
