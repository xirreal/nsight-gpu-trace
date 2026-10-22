//! Shader profiler tables: blob decoding, SPIR-V modules, cubin line tables,
//! and the code-block-to-source correlation used by PC sampling.
//!
//! Blobs are LZ4 blocks whose contents are XORed with an original ChaCha20
//! keystream (`OBFUSCATION_SIMPLE`). The 32-byte key is recovered at runtime
//! from the installed WarpViz plugin, like the protobuf descriptors.
//!
//! SASS instructions are classified into Nsight's instruction mix classes
//! (pipe, family, operation) with a table generated from Nsight 2026.3.1.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};

use prost_reflect::DynamicMessage;
use serde::Serialize;

use crate::{
    Error, Result, TraceDocument,
    analysis::{
        enum_name, message_items, message_json, optional_bytes, optional_message, optional_u64,
        u32_items,
    },
    sass_classes::{CLASSES, SM_VERSIONS},
    spirv_opcodes::OPCODES,
};

const SPIRV_MAGIC: u32 = 0x0723_0203;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
/// `spirv-dis` prints five header lines, so instruction `i` sits on line `i + 6`.
pub const SPIRV_FIRST_INSTRUCTION_LINE: u32 = 6;
const SASS_INSTRUCTION_SIZE: u64 = 16;
const MAX_BLOB_UNPACKED: u64 = 1 << 30;
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Instruction mix pipes, indexed by Nsight's pipe code.
const SASS_PIPES: [&str; 21] = [
    "", "ADU", "ALU", "CBU", "FMA", "FP16", "FP64", "IPA", "LDCU", "LSU", "REDUX", "RTCORE", "SCH",
    "SYNCS", "TEX", "TMA", "TMEM", "Tensor", "UDP", "WORKID", "XU",
];

/// Instruction mix families, indexed by Nsight's family code.
const SASS_FAMILIES: [&str; 47] = [
    "",
    "Bit Manipulation",
    "Constant Memory",
    "Control Flow",
    "Data Movement",
    "FP16 Comparison",
    "FP16 Math",
    "FP32 Comparison",
    "FP32 Logic",
    "FP32 Math",
    "FP32 Rounding",
    "FP64 Comparison",
    "FP64 Conversion",
    "FP64 Math",
    "FP64 Rounding",
    "Float Math",
    "Float-To-Float",
    "Float-To-Int",
    "Generic Memory",
    "Global Memory",
    "Int-To-Float",
    "Integer Arithmetic",
    "Integer Comparison",
    "Integer Multiply/Add",
    "Local Memory",
    "Logic Operation",
    "Multicast Memory",
    "NOP",
    "PS Attribute",
    "Performance Monitor",
    "Ray Tracing",
    "Resource Control",
    "Scalar Constant",
    "Shared Memory",
    "Special Function",
    "Special Register",
    "Surface",
    "Sync. Barrier",
    "Tensor",
    "Tensor Descriptor",
    "Tensor Memory",
    "Texture",
    "Texture Memory",
    "Uniform Constant",
    "VTG Attribute",
    "Vector Constant",
    "Warp-Level Primitive",
];

/// Instruction mix operations, indexed by Nsight's operation code.
const SASS_OPERATIONS: [&str; 50] = [
    "",
    "Async Memcpy",
    "Atomic",
    "Bitwise",
    "Branch",
    "Breakpoint",
    "Cache Control",
    "Call",
    "DEPBAR",
    "Discard",
    "ERRBAR",
    "Exit",
    "FP!64->FP!64",
    "FP!64->FP64",
    "FP->INT!64",
    "FP->INT64",
    "FP16",
    "FP32->INT8",
    "FP4",
    "FP64",
    "FP8",
    "Fetch",
    "Fetch w/ Derivatives",
    "Global MEMBAR",
    "INT",
    "INT->FP!64",
    "INT->FP64",
    "INT->INT",
    "INT32->FP32",
    "LDGDEPBAR",
    "LOD",
    "Load",
    "Load 4",
    "MEMBAR",
    "NANOSLEEP",
    "Prefetch",
    "Program Start",
    "Query",
    "Register",
    "Return",
    "SIMT",
    "Shared MEMBAR",
    "Shared Memory",
    "Special",
    "Store",
    "TMA",
    "TMA Memcpy",
    "TMA Prefetch",
    "TMA Reduction",
    "Virtual Resource",
];

/// Nsight's instruction mix class of one SASS instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct InstructionClass {
    pub pipe: &'static str,
    pub family: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<&'static str>,
}

impl InstructionClass {
    /// UI-style name such as `LSU Shared Memory Load`.
    pub fn label(&self) -> String {
        [self.pipe, self.family, self.operation.unwrap_or_default()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Classify a 128-bit SASS instruction for a `cudaSmVersion`, as Nsight's
/// instruction mix does: the key is the 12-bit opcode plus instruction bit 91.
pub fn classify_sass(sm_version: u32, encoding: &[u8]) -> Option<InstructionClass> {
    let column = SM_VERSIONS
        .iter()
        .position(|version| *version == sm_version)?;
    let word = |index: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            encoding.get(index * 4..index * 4 + 4)?.try_into().ok()?,
        ))
    };
    let key = (((word(2)? >> 15) & 0x1000) | (word(0)? & 0xfff)) as u16;
    let packed = CLASSES
        .binary_search_by_key(&key, |entry| entry.0)
        .ok()
        .map(|index| CLASSES[index].1[column])
        .filter(|packed| *packed != 0)?;
    let name = |names: &[&'static str], code: u32| names.get(code as usize).copied();
    let operation = name(&SASS_OPERATIONS, (packed >> 8) & 0xff)?;
    Some(InstructionClass {
        pipe: name(&SASS_PIPES, packed & 0xff)?,
        family: name(&SASS_FAMILIES, packed >> 16)?,
        operation: (!operation.is_empty()).then_some(operation),
    })
}

/// One shader module (IL bytecode) referenced by the shader profiler.
#[derive(Debug, Clone, Serialize)]
pub struct ShaderModule {
    pub device_index: usize,
    pub index: usize,
    pub bytecode_type: Option<String>,
    pub blob_index: Option<usize>,
    /// Bob Jenkins `lookup8` over the bytecode, as shown in the Nsight UI.
    pub hash: Option<String>,
    #[serde(skip)]
    pub hash_value: Option<u64>,
    pub size: Option<usize>,
    /// Main source file name from the first `OpSource`/`DebugSource`.
    pub name: Option<String>,
    #[serde(skip)]
    pub spirv: Option<SpirvModule>,
    pub spirv_summary: Option<SpirvSummary>,
}

/// GPU code of one pipeline stage with its virtual address range.
#[derive(Debug, Clone, Serialize)]
pub struct CodeBlock {
    pub device_index: usize,
    pub index: usize,
    pub address: u64,
    pub size: u64,
    pub shader_type: Option<String>,
    pub origin: Option<String>,
    pub function_groups: Vec<serde_json::Value>,
    /// API pipeline handle of the first function group; the Nsight UI names
    /// shaders by it (`0x000002d9803638d0 - main`).
    pub pipeline: Option<String>,
    pub program_meta: serde_json::Value,
    pub instructions_blob: Option<usize>,
    pub debug_blob: Option<usize>,
    pub function_name: Option<String>,
    pub module_hash: Option<String>,
    #[serde(skip)]
    pub module_hash_value: Option<u64>,
    pub module_index: Option<usize>,
    pub line_table_rows: usize,
    /// `commonProgramMeta.cudaSmVersion`, e.g. 0x80009 for sm_89.
    pub sm_version: Option<u32>,
    /// SASS instructions correlated with a SPIR-V instruction / a source
    /// line / an instruction mix class.
    pub sass_instructions: usize,
    pub sass_with_spirv: usize,
    pub sass_with_source_line: usize,
    pub sass_classified: usize,
    #[serde(skip)]
    pub sass: Vec<u8>,
    /// One entry per 16-byte SASS instruction.
    #[serde(skip)]
    pub instructions: Vec<SassCorrelation>,
}

/// Correlation of one SASS instruction slot.
#[derive(Debug, Clone, Copy, Default)]
pub struct SassCorrelation {
    /// Zero-based SPIR-V instruction index in the code block's module.
    pub spirv_index: Option<u32>,
    /// Index into [`SpirvModule::locations`].
    pub location: Option<u32>,
    pub class: Option<InstructionClass>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpirvSummary {
    pub version: String,
    pub generator: u32,
    pub bound: u32,
    pub instructions: usize,
    pub entry_points: Vec<String>,
    pub sources: Vec<SpirvSource>,
    pub debug_info: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpirvSource {
    pub language: u32,
    pub version: u32,
    pub file: Option<String>,
    pub has_text: bool,
}

/// Source position attached to SPIR-V instructions by `OpLine` or
/// `NonSemantic.Shader.DebugInfo.100` `DebugLine`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone)]
pub struct SpirvInstruction {
    pub opcode: u16,
    pub word_offset: u32,
    pub result_type: Option<u32>,
    pub result_id: Option<u32>,
}

/// Minimal SPIR-V module index: instructions, source locations, and type names.
#[derive(Debug, Clone)]
pub struct SpirvModule {
    pub version: u32,
    pub generator: u32,
    pub bound: u32,
    pub instructions: Vec<SpirvInstruction>,
    pub entry_points: Vec<String>,
    pub sources: Vec<SpirvSource>,
    pub locations: Vec<SourceLocation>,
    /// Index into [`Self::locations`] for every instruction.
    pub instruction_locations: Vec<Option<u32>>,
    pub debug_info: &'static str,
    /// Source named by `DebugCompilationUnit`, which may follow include files.
    main_source: Option<String>,
    type_names: HashMap<u32, String>,
}

impl SpirvModule {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 || !data.len().is_multiple_of(4) {
            return Err(Error::InvalidCapture(
                "SPIR-V module is truncated or not word aligned".into(),
            ));
        }
        let words: Vec<u32> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        if words[0] != SPIRV_MAGIC {
            return Err(Error::InvalidCapture(format!(
                "bad SPIR-V magic {:#x}",
                words[0]
            )));
        }
        let mut module = Self {
            version: words[1],
            generator: words[2],
            bound: words[3],
            instructions: Vec::new(),
            entry_points: Vec::new(),
            sources: Vec::new(),
            locations: Vec::new(),
            instruction_locations: Vec::new(),
            debug_info: "none",
            main_source: None,
            type_names: HashMap::new(),
        };
        let mut strings: HashMap<u32, String> = HashMap::new();
        let mut names: HashMap<u32, String> = HashMap::new();
        let mut constants: HashMap<u32, u32> = HashMap::new();
        let mut debug_sources: HashMap<u32, String> = HashMap::new();
        let mut nonsemantic_sets: Vec<u32> = Vec::new();
        let mut location_ids: HashMap<SourceLocation, u32> = HashMap::new();
        let mut current: Option<u32> = None;
        let mut has_op_line = false;
        let mut has_debug_line = false;
        let mut offset = 5usize;
        while offset < words.len() {
            let word_count = (words[offset] >> 16) as usize;
            let opcode = (words[offset] & 0xffff) as u16;
            if word_count == 0 || offset + word_count > words.len() {
                return Err(Error::InvalidCapture(format!(
                    "invalid SPIR-V instruction length at word {offset}"
                )));
            }
            let operands = &words[offset + 1..offset + word_count];
            let flags = opcode_flags(opcode);
            let mut cursor = 0usize;
            let result_type = (flags & 1 != 0).then(|| operands.get(cursor).copied());
            if result_type.is_some() {
                cursor += 1;
            }
            let result_id = (flags & 2 != 0).then(|| operands.get(cursor).copied());
            let result_type = result_type.flatten();
            let result_id = result_id.flatten();

            match opcode {
                // OpSource
                3 => module.sources.push(SpirvSource {
                    language: operands.first().copied().unwrap_or(0),
                    version: operands.get(1).copied().unwrap_or(0),
                    file: operands.get(2).and_then(|id| strings.get(id)).cloned(),
                    has_text: operands.len() > 3,
                }),
                // OpName
                5 => {
                    if let Some(id) = operands.first() {
                        names.insert(*id, words_to_string(&operands[1..]));
                    }
                }
                // OpString
                7 => {
                    if let Some(id) = operands.first() {
                        strings.insert(*id, words_to_string(&operands[1..]));
                    }
                }
                // OpLine
                8 => {
                    has_op_line = true;
                    if let (Some(file), Some(line)) = (operands.first(), operands.get(1)) {
                        let location = SourceLocation {
                            file: strings
                                .get(file)
                                .cloned()
                                .unwrap_or_else(|| format!("%{file}")),
                            line: *line,
                        };
                        current = Some(intern_location(
                            &mut module.locations,
                            &mut location_ids,
                            location,
                        ));
                    }
                }
                // OpExtInstImport
                11 => {
                    if words_to_string(&operands[1..]).starts_with("NonSemantic.Shader.DebugInfo") {
                        nonsemantic_sets.push(operands[0]);
                    }
                }
                // OpExtInst
                12 if operands.len() >= 4 && nonsemantic_sets.contains(&operands[2]) => {
                    let arguments = &operands[4..];
                    match operands[3] {
                        // DebugCompilationUnit
                        1 => {
                            if let Some(source) = arguments.get(2) {
                                module.main_source = debug_sources.get(source).cloned();
                            }
                        }
                        // DebugSource
                        35 => {
                            if let (Some(id), Some(file)) = (result_id, arguments.first()) {
                                let file = strings.get(file).cloned().unwrap_or_default();
                                module.sources.push(SpirvSource {
                                    language: 0,
                                    version: 0,
                                    file: Some(file.clone()),
                                    has_text: arguments.len() > 1,
                                });
                                debug_sources.insert(id, file);
                            }
                        }
                        // DebugLine
                        103 => {
                            has_debug_line = true;
                            if let (Some(source), Some(line)) =
                                (arguments.first(), arguments.get(1))
                            {
                                let location = SourceLocation {
                                    file: debug_sources.get(source).cloned().unwrap_or_default(),
                                    line: constants.get(line).copied().unwrap_or(0),
                                };
                                current = Some(intern_location(
                                    &mut module.locations,
                                    &mut location_ids,
                                    location,
                                ));
                            }
                        }
                        // DebugNoLine is ignored like OpNoLine below.
                        _ => {}
                    }
                }
                // OpEntryPoint
                15 => module
                    .entry_points
                    .push(words_to_string(operands.get(2..).unwrap_or_default())),
                // OpConstant with a 32-bit literal
                43 => {
                    if let (Some(id), Some(value)) = (result_id, operands.get(2)) {
                        constants.insert(id, *value);
                    }
                }
                _ => {}
            }
            if let Some(id) = result_id
                && let Some(name) = type_name(opcode, operands, &module.type_names, &names)
            {
                module.type_names.insert(id, name);
            }
            // Unlike the SPIR-V rule, Nsight keeps the last line across OpNoLine
            // and OpLabel until the next line or the end of the function; this
            // matches its attribution of samples on OpSelect after OpNoLine and
            // on OpLabel instructions.
            if opcode == 56 {
                current = None;
            }
            module.instructions.push(SpirvInstruction {
                opcode,
                word_offset: offset as u32,
                result_type,
                result_id,
            });
            module.instruction_locations.push(current);
            offset += word_count;
        }
        module.debug_info = match (has_op_line, has_debug_line) {
            (true, true) => "op_line_and_nonsemantic",
            (true, false) => "op_line",
            (false, true) => "nonsemantic_shader_debug_info",
            (false, false) => "none",
        };
        Ok(module)
    }

    pub fn summary(&self) -> SpirvSummary {
        SpirvSummary {
            version: format!(
                "{}.{}",
                (self.version >> 16) & 0xff,
                (self.version >> 8) & 0xff
            ),
            generator: self.generator,
            bound: self.bound,
            instructions: self.instructions.len(),
            entry_points: self.entry_points.clone(),
            sources: self.sources.clone(),
            debug_info: self.debug_info,
        }
    }

    /// Main source file (basename) of the module, if debug info names one.
    pub fn main_source(&self) -> Option<String> {
        self.main_source
            .as_deref()
            .or_else(|| {
                self.sources
                    .iter()
                    .find_map(|source| source.file.as_deref())
            })
            .filter(|file| !file.is_empty())
            .map(file_basename)
    }

    /// `spirv-dis`-style text for one instruction, e.g. `OpLoad %float`.
    pub fn describe(&self, index: usize) -> Option<String> {
        let instruction = self.instructions.get(index)?;
        let mut text = opcode_name(instruction.opcode)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("Op{}", instruction.opcode));
        if let Some(result_type) = instruction.result_type {
            text.push_str(" %");
            text.push_str(
                self.type_names
                    .get(&result_type)
                    .map(String::as_str)
                    .unwrap_or(&result_type.to_string()),
            );
        }
        Some(text)
    }
}

/// Decoded shader profiler data of all devices in a trace.
#[derive(Debug, Clone, Default)]
pub struct ShaderProfile {
    pub modules: Vec<ShaderModule>,
    pub code_blocks: Vec<CodeBlock>,
    pub blob_count: usize,
    pub key_source: Option<String>,
    pub warnings: Vec<String>,
    /// Code block indices sorted by address.
    ranges: Vec<usize>,
}

/// Position of a PC inside the shader profiler tables.
#[derive(Debug, Clone, Copy)]
pub struct CodeLocation {
    pub code_block: usize,
    pub offset: u64,
    pub correlation: SassCorrelation,
}

impl ShaderProfile {
    pub fn from_document(document: &TraceDocument) -> Result<Self> {
        let mut profile = Self::default();
        let mut key: Option<Option<[u8; 32]>> = None;
        for (device_index, device) in message_items(document.message(), "devices")?.enumerate() {
            let Some(report) = optional_message(device, "ShaderProfilerReport")? else {
                continue;
            };
            let blobs = read_blob_entries(report)?;
            profile.blob_count += blobs.len();
            if key.is_none() && blobs.iter().any(|blob| blob.obfuscated) {
                let probes = key_probes(report, &blobs)?;
                let found = extract_blob_key(document.schema_binary(), &probes)?;
                profile.key_source = found
                    .is_some()
                    .then(|| document.schema_binary().display().to_string());
                if found.is_none() {
                    profile.warnings.push(format!(
                        "No blob key in {} decodes this capture's shader blobs.",
                        document.schema_binary().display()
                    ));
                }
                key = Some(found);
            }
            let key = key.flatten();
            let mut decoded: HashMap<usize, Vec<u8>> = HashMap::new();
            let mut decode = |index: usize, warnings: &mut Vec<String>| -> Option<Vec<u8>> {
                if let Some(data) = decoded.get(&index) {
                    return Some(data.clone());
                }
                let blob = blobs.iter().find(|blob| blob.id == index)?;
                match blob.decode(key.as_ref()) {
                    Ok(data) => {
                        decoded.insert(index, data.clone());
                        Some(data)
                    }
                    Err(error) => {
                        warnings.push(format!("blob {index}: {error}"));
                        None
                    }
                }
            };

            let Some(info) = optional_message(report, "pcCountersInfo")? else {
                continue;
            };
            let Some(session) = optional_message(info, "pcSamplingSession")? else {
                continue;
            };
            let groups: Vec<_> = message_items(session, "functionGroups")?
                .map(message_json)
                .collect::<Result<_>>()?;

            let module_base = profile.modules.len();
            for (index, module) in message_items(session, "modules")?.enumerate() {
                let api = optional_message(module, "graphicsAPIModule")?;
                let bytecode_type = api
                    .map(|api| enum_name(api, "bytecodeType"))
                    .transpose()?
                    .flatten();
                let blob_index = api
                    .map(|api| blob_ref(api, "bytecode"))
                    .transpose()?
                    .flatten();
                let data = blob_index.and_then(|blob| decode(blob, &mut profile.warnings));
                let spirv = match (&data, bytecode_type.as_deref()) {
                    (Some(data), Some("ILBytecodeType_SPIRV")) => match SpirvModule::parse(data) {
                        Ok(spirv) => Some(spirv),
                        Err(error) => {
                            profile
                                .warnings
                                .push(format!("module {index} of device {device_index}: {error}"));
                            None
                        }
                    },
                    _ => None,
                };
                let hash_value = data.as_deref().map(lookup8);
                profile.modules.push(ShaderModule {
                    device_index,
                    index,
                    bytecode_type,
                    blob_index,
                    hash: hash_value.map(format_hash),
                    hash_value,
                    size: data.as_ref().map(Vec::len),
                    name: spirv.as_ref().and_then(SpirvModule::main_source),
                    spirv_summary: spirv.as_ref().map(SpirvModule::summary),
                    spirv,
                });
            }
            let device_modules = module_base..profile.modules.len();

            for (index, block) in message_items(session, "codeBlocks")?.enumerate() {
                let Some(instance) = optional_message(block, "shaderInstance")? else {
                    profile.warnings.push(format!(
                        "code block {index} of device {device_index} is not a shader instance"
                    ));
                    continue;
                };
                let range = optional_message(instance, "vaRange")?;
                let address = range.and_then(|range| optional_u64(range, "address"));
                let size = range.and_then(|range| optional_u64(range, "size"));
                let (Some(address), Some(size)) = (address, size) else {
                    profile.warnings.push(format!(
                        "code block {index} of device {device_index} has no VA range"
                    ));
                    continue;
                };
                let instructions_blob = blob_ref(instance, "instructions")?;
                let debug_blob = optional_message(instance, "debugInfo")?
                    .map(|elf| blob_ref(elf, "ref"))
                    .transpose()?
                    .flatten();
                let mut program_meta = serde_json::Map::new();
                for field in [
                    "commonProgramMeta",
                    "computeProgramMeta",
                    "graphicsProgramMeta",
                ] {
                    if let Some(meta) = optional_message(instance, field)? {
                        program_meta.insert(field.into(), message_json(meta)?);
                    }
                }
                let function_groups: Vec<_> = u32_items(instance, "functionGroupIndices")
                    .into_iter()
                    .filter_map(|group| groups.get(group as usize).cloned())
                    .collect();
                // Each group holds one pipeline message, e.g. `computePipeline`.
                let pipeline = function_groups.iter().find_map(|group| {
                    group
                        .as_object()?
                        .values()
                        .find_map(|pipeline| Some(pipeline.get("name")?.as_str()?.to_owned()))
                });
                let sass = instructions_blob
                    .and_then(|blob| decode(blob, &mut profile.warnings))
                    .unwrap_or_default();
                let cubin = debug_blob
                    .and_then(|blob| decode(blob, &mut profile.warnings))
                    .map(|data| Cubin::parse(&data));
                let (line_table, function_name, module_hash_value) = match cubin {
                    Some(Ok(cubin)) => (cubin.line_rows, cubin.function_name, cubin.module_hash),
                    Some(Err(error)) => {
                        profile.warnings.push(format!(
                            "debug info of code block {index} of device {device_index}: {error}"
                        ));
                        (Vec::new(), None, None)
                    }
                    None => (Vec::new(), None, None),
                };
                let module_index = match module_hash_value {
                    Some(hash) => device_modules
                        .clone()
                        .find(|module| profile.modules[*module].hash_value == Some(hash)),
                    None if device_modules.len() == 1 => Some(device_modules.start),
                    None => None,
                };
                if let Some(hash) = module_hash_value
                    && module_index.is_none()
                {
                    profile.warnings.push(format!(
                        "code block {index} of device {device_index} references shader module hash {} that matches no module",
                        format_hash(hash)
                    ));
                }
                let module = module_index.and_then(|module| profile.modules[module].spirv.as_ref());
                let slots = size.div_ceil(SASS_INSTRUCTION_SIZE) as usize;
                let mut instructions = correlate(&line_table, slots, module);
                let sm_version = optional_message(instance, "commonProgramMeta")?
                    .and_then(|meta| optional_u64(meta, "cudaSmVersion"))
                    .and_then(|version| u32::try_from(version).ok());
                if let Some(version) = sm_version {
                    for (item, encoding) in instructions
                        .iter_mut()
                        .zip(sass.chunks(SASS_INSTRUCTION_SIZE as usize))
                    {
                        item.class = classify_sass(version, encoding);
                    }
                }
                profile.code_blocks.push(CodeBlock {
                    device_index,
                    index,
                    address,
                    size,
                    shader_type: enum_name(instance, "type")?,
                    origin: enum_name(instance, "origin")?,
                    function_groups,
                    pipeline,
                    program_meta: program_meta.into(),
                    instructions_blob,
                    debug_blob,
                    function_name,
                    module_hash: module_hash_value.map(format_hash),
                    module_hash_value,
                    module_index,
                    line_table_rows: line_table.len(),
                    sm_version,
                    sass_instructions: instructions.len(),
                    sass_with_spirv: instructions
                        .iter()
                        .filter(|item| item.spirv_index.is_some())
                        .count(),
                    sass_with_source_line: instructions
                        .iter()
                        .filter(|item| item.location.is_some())
                        .count(),
                    sass_classified: instructions
                        .iter()
                        .filter(|item| item.class.is_some())
                        .count(),
                    sass,
                    instructions,
                });
            }
        }
        let mut ranges: Vec<usize> = (0..profile.code_blocks.len()).collect();
        ranges.sort_by_key(|index| profile.code_blocks[*index].address);
        profile.ranges = ranges;
        Ok(profile)
    }

    /// Find the code block and SASS correlation containing a GPU virtual address.
    pub fn locate(&self, pc: u64) -> Option<CodeLocation> {
        let position = self
            .ranges
            .partition_point(|index| self.code_blocks[*index].address <= pc);
        // Overlapping ranges are not expected, but check a few predecessors.
        for candidate in self.ranges[..position].iter().rev().take(4) {
            let block = &self.code_blocks[*candidate];
            let offset = pc - block.address;
            if offset < block.size {
                let correlation = block
                    .instructions
                    .get((offset / SASS_INSTRUCTION_SIZE) as usize)
                    .copied()
                    .unwrap_or_default();
                return Some(CodeLocation {
                    code_block: *candidate,
                    offset,
                    correlation,
                });
            }
        }
        None
    }

    pub fn module_of(&self, block: &CodeBlock) -> Option<&ShaderModule> {
        block.module_index.map(|index| &self.modules[index])
    }

    /// Display name of a code block's shader: source file, else module hash.
    pub fn shader_name(&self, block: &CodeBlock) -> String {
        self.module_of(block)
            .and_then(|module| module.name.clone())
            .or_else(|| block.module_hash.clone())
            .or_else(|| block.function_name.clone())
            .unwrap_or_else(|| format!("code block {}", block.index))
    }
}

fn correlate(rows: &[LineRow], slots: usize, module: Option<&SpirvModule>) -> Vec<SassCorrelation> {
    let mut result = vec![SassCorrelation::default(); slots];
    for (slot, item) in result.iter_mut().enumerate() {
        let address = slot as u64 * SASS_INSTRUCTION_SIZE;
        let position = rows.partition_point(|row| row.address <= address);
        let Some(row) = position.checked_sub(1).map(|index| &rows[index]) else {
            continue;
        };
        if row.end_sequence || row.line < SPIRV_FIRST_INSTRUCTION_LINE {
            continue;
        }
        let index = row.line - SPIRV_FIRST_INSTRUCTION_LINE;
        item.spirv_index = Some(index);
        item.location = module
            .and_then(|module| module.instruction_locations.get(index as usize))
            .copied()
            .flatten();
    }
    result
}

/// One raw shader profiler blob with its declared encoding.
#[derive(Debug, Clone)]
pub struct BlobEntry {
    pub id: usize,
    pub data: Vec<u8>,
    pub uncompressed_size: u64,
    pub compression: Option<String>,
    pub obfuscation: Option<String>,
    pub obfuscated: bool,
}

impl BlobEntry {
    /// Decompress (`COMPRESSION_LZ4`) and then de-obfuscate (`OBFUSCATION_SIMPLE`).
    pub fn decode(&self, key: Option<&[u8; 32]>) -> Result<Vec<u8>> {
        let size = usize::try_from(self.uncompressed_size)
            .ok()
            .filter(|size| (*size as u64) <= MAX_BLOB_UNPACKED)
            .ok_or_else(|| {
                Error::InvalidCapture(format!(
                    "blob declares {} uncompressed bytes",
                    self.uncompressed_size
                ))
            })?;
        let mut data = match self.compression.as_deref() {
            Some("COMPRESSION_LZ4") => {
                lz4_flex::block::decompress(&self.data, size).map_err(|error| {
                    Error::InvalidCapture(format!("LZ4 decompression failed: {error}"))
                })?
            }
            None | Some("COMPRESSION_NONE") => self.data.clone(),
            Some(other) => {
                return Err(Error::InvalidCapture(format!(
                    "unsupported blob compression {other}"
                )));
            }
        };
        if data.len() != size {
            return Err(Error::InvalidCapture(format!(
                "blob has {} bytes; expected {size}",
                data.len()
            )));
        }
        match self.obfuscation.as_deref() {
            Some("OBFUSCATION_SIMPLE") => {
                let key = key.ok_or_else(|| {
                    Error::InvalidCapture("blob is obfuscated and no key was found".into())
                })?;
                apply_keystream(key, &mut data);
            }
            None | Some("OBFUSCATION_NONE") => {}
            Some(other) => {
                return Err(Error::InvalidCapture(format!(
                    "unsupported blob obfuscation {other}"
                )));
            }
        }
        Ok(data)
    }
}

fn read_blob_entries(report: &DynamicMessage) -> Result<Vec<BlobEntry>> {
    let Some(table) = optional_message(report, "blobTable")? else {
        return Ok(Vec::new());
    };
    message_items(table, "blobs")?
        .enumerate()
        .map(|(position, blob)| {
            let obfuscation = enum_name(blob, "obfuscation")?;
            Ok(BlobEntry {
                id: optional_u64(blob, "id").map_or(position, |id| id as usize),
                data: optional_bytes(blob, "data").unwrap_or_default().to_vec(),
                uncompressed_size: optional_u64(blob, "uncompressedSize").unwrap_or(0),
                compression: enum_name(blob, "compression")?,
                obfuscated: obfuscation
                    .as_deref()
                    .is_some_and(|name| name != "OBFUSCATION_NONE"),
                obfuscation,
            })
        })
        .collect()
}

fn blob_ref(message: &DynamicMessage, name: &str) -> Result<Option<usize>> {
    Ok(optional_message(message, name)?
        .and_then(|reference| optional_u64(reference, "idx"))
        .map(|index| index as usize))
}

/// Known plaintext for the first eight bytes of a blob.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyProbe {
    cipher: [u8; 8],
    plain: [u8; 8],
    mask: [u8; 8],
}

impl KeyProbe {
    fn matches(&self, keystream: &[u8]) -> bool {
        (0..8).all(|index| {
            (self.cipher[index] ^ keystream[index]) & self.mask[index]
                == self.plain[index] & self.mask[index]
        })
    }
}

/// Build probes from SPIR-V modules (magic and version zero bytes) and cubins (ELF header).
fn key_probes(report: &DynamicMessage, blobs: &[BlobEntry]) -> Result<Vec<KeyProbe>> {
    let mut wanted: BTreeMap<usize, ([u8; 8], [u8; 8])> = BTreeMap::new();
    let spirv = (
        [0x03, 0x02, 0x23, 0x07, 0x00, 0, 0, 0x00],
        [0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0xff],
    );
    let elf = (
        [0x7f, b'E', b'L', b'F', 2, 1, 1, 0],
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0],
    );
    if let Some(session) = optional_message(report, "pcCountersInfo")?
        .map(|info| optional_message(info, "pcSamplingSession"))
        .transpose()?
        .flatten()
    {
        for module in message_items(session, "modules")? {
            if let Some(api) = optional_message(module, "graphicsAPIModule")?
                && enum_name(api, "bytecodeType")?.as_deref() == Some("ILBytecodeType_SPIRV")
                && let Some(index) = blob_ref(api, "bytecode")?
            {
                wanted.insert(index, spirv);
            }
        }
        for block in message_items(session, "codeBlocks")? {
            if let Some(index) = optional_message(block, "shaderInstance")?
                .map(|instance| optional_message(instance, "debugInfo"))
                .transpose()?
                .flatten()
                .map(|elf| blob_ref(elf, "ref"))
                .transpose()?
                .flatten()
            {
                wanted.insert(index, elf);
            }
        }
    }
    let mut probes = Vec::new();
    for (index, (plain, mask)) in wanted {
        let Some(blob) = blobs
            .iter()
            .find(|blob| blob.id == index && blob.obfuscated)
        else {
            continue;
        };
        let Ok(size) = usize::try_from(blob.uncompressed_size) else {
            continue;
        };
        let data = match blob.compression.as_deref() {
            Some("COMPRESSION_LZ4") => match lz4_flex::block::decompress(&blob.data, size) {
                Ok(data) => data,
                Err(_) => continue,
            },
            _ => blob.data.clone(),
        };
        if let Some(cipher) = data.get(..8) {
            probes.push(KeyProbe {
                cipher: cipher.try_into().unwrap(),
                plain,
                mask,
            });
        }
        if probes.len() == 4 {
            break;
        }
    }
    Ok(probes)
}

/// Recover the blob key from an installed Nsight plugin binary. Every 4-byte
/// aligned 32-byte window with varied bytes is tried as a ChaCha20 key; the
/// first one that decodes all probes to their known plaintext wins.
pub(crate) fn extract_blob_key(binary: &Path, probes: &[KeyProbe]) -> Result<Option<[u8; 32]>> {
    if probes.is_empty() {
        return Ok(None);
    }
    let data = fs::read(binary)?;
    let mut offset = 0usize;
    while offset + 32 <= data.len() {
        let window = &data[offset..offset + 32];
        if distinct_bytes(window) >= 20 {
            let key: [u8; 32] = window.try_into().unwrap();
            let block = chacha20_block(&key, 0);
            if probes.iter().all(|probe| probe.matches(&block)) {
                return Ok(Some(key));
            }
        }
        offset += 4;
    }
    Ok(None)
}

fn distinct_bytes(window: &[u8]) -> u32 {
    let mut seen = [0u64; 4];
    for byte in window {
        seen[(byte >> 6) as usize] |= 1 << (byte & 63);
    }
    seen.iter().map(|bits| bits.count_ones()).sum()
}

/// Original (64-bit counter, 64-bit nonce) ChaCha20 block with a zero nonce.
fn chacha20_block(key: &[u8; 32], counter: u64) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CHACHA_CONSTANTS);
    for (index, word) in key.as_chunks::<4>().0.iter().enumerate() {
        state[4 + index] = u32::from_le_bytes(*word);
    }
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    let mut output = [0u8; 64];
    for (index, word) in working.iter().enumerate() {
        output[index * 4..index * 4 + 4]
            .copy_from_slice(&word.wrapping_add(state[index]).to_le_bytes());
    }
    output
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn apply_keystream(key: &[u8; 32], data: &mut [u8]) {
    for (counter, chunk) in data.chunks_mut(64).enumerate() {
        let block = chacha20_block(key, counter as u64);
        for (byte, stream) in chunk.iter_mut().zip(block) {
            *byte ^= stream;
        }
    }
}

/// Bob Jenkins' 64-bit `lookup8` hash with level 0, Nsight's shader module hash.
pub fn lookup8(data: &[u8]) -> u64 {
    fn mix(mut a: u64, mut b: u64, mut c: u64) -> (u64, u64, u64) {
        a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 43);
        b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 9);
        c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 8);
        a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 38);
        b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 23);
        c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 5);
        a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 35);
        b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 49);
        c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 11);
        a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 12);
        b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 18);
        c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 22);
        (a, b, c)
    }
    let word = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().unwrap());
    let (mut a, mut b, mut c) = (0u64, 0u64, 0x9e37_79b9_7f4a_7c13u64);
    let (chunks, remainder) = data.as_chunks::<24>();
    for chunk in chunks {
        a = a.wrapping_add(word(&chunk[..8]));
        b = b.wrapping_add(word(&chunk[8..16]));
        c = c.wrapping_add(word(&chunk[16..]));
        (a, b, c) = mix(a, b, c);
    }
    // The low byte of `c` is reserved for the length.
    c = c.wrapping_add(data.len() as u64);
    for (index, byte) in remainder.iter().enumerate() {
        let byte = u64::from(*byte);
        match index {
            0..8 => a = a.wrapping_add(byte << (8 * index)),
            8..16 => b = b.wrapping_add(byte << (8 * (index - 8))),
            _ => c = c.wrapping_add(byte << (8 * (index - 15))),
        }
    }
    mix(a, b, c).2
}

pub fn format_hash(hash: u64) -> String {
    format!("{hash:#018x}")
}

#[derive(Debug, Clone, Copy)]
struct LineRow {
    address: u64,
    line: u32,
    end_sequence: bool,
}

/// The parts of a cubin debug-info blob used for correlation.
#[derive(Debug, Clone)]
struct Cubin {
    function_name: Option<String>,
    module_hash: Option<u64>,
    line_rows: Vec<LineRow>,
}

impl Cubin {
    fn parse(data: &[u8]) -> Result<Self> {
        let sections = elf_sections(data)?;
        let function_name = sections
            .iter()
            .find_map(|section| section.name.strip_prefix(".text."))
            .map(str::to_owned);
        let Some(debug_line) = sections
            .iter()
            .find(|section| section.name == ".debug_line")
        else {
            return Ok(Self {
                function_name,
                module_hash: None,
                line_rows: Vec::new(),
            });
        };
        let program = parse_line_program(debug_line.data)?;
        let module_hash = program
            .include_directories
            .iter()
            .find_map(|directory| directory_attribute(directory, "ShaderModuleHash"))
            .and_then(|value| u64::from_str_radix(value, 16).ok());
        Ok(Self {
            function_name,
            module_hash,
            line_rows: program.rows,
        })
    }
}

/// Values in a `"`-separated `key>value` include directory, e.g.
/// `./"stage>cs"fmt>spir"ShaderModuleHash>36cf63efe2e621e`.
fn directory_attribute<'a>(directory: &'a str, key: &str) -> Option<&'a str> {
    directory
        .split('"')
        .filter_map(|pair| pair.split_once('>'))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

struct ElfSection<'a> {
    name: String,
    data: &'a [u8],
}

fn elf_sections(data: &[u8]) -> Result<Vec<ElfSection<'_>>> {
    let invalid = |what: &str| Error::InvalidCapture(format!("invalid cubin: {what}"));
    if data.len() < 64 || &data[..4] != ELF_MAGIC || data[4] != 2 || data[5] != 1 {
        return Err(invalid("not a little-endian ELF64 image"));
    }
    let read_u16 = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(
            data.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        Some(u64::from_le_bytes(
            data.get(offset..offset + 8)?.try_into().ok()?,
        ))
    };
    let section_offset = read_u64(0x28).ok_or_else(|| invalid("header"))? as usize;
    let entry_size = read_u16(0x3a).ok_or_else(|| invalid("header"))? as usize;
    let count = read_u16(0x3c).ok_or_else(|| invalid("header"))? as usize;
    let names_index = read_u16(0x3e).ok_or_else(|| invalid("header"))? as usize;
    if entry_size < 64 {
        return Err(invalid("section header size"));
    }
    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let base = section_offset + index * entry_size;
        let name = read_u32(base).ok_or_else(|| invalid("section header"))?;
        let kind = read_u32(base + 4).ok_or_else(|| invalid("section header"))?;
        let offset = read_u64(base + 0x18).ok_or_else(|| invalid("section header"))? as usize;
        let size = read_u64(base + 0x20).ok_or_else(|| invalid("section header"))? as usize;
        // SHT_NOBITS occupies no file data.
        let body = if kind == 8 {
            &data[0..0]
        } else {
            data.get(offset..offset.saturating_add(size))
                .ok_or_else(|| invalid("section data out of range"))?
        };
        headers.push((name as usize, body));
    }
    let names = headers
        .get(names_index)
        .map(|header| header.1)
        .ok_or_else(|| invalid("section name table"))?;
    Ok(headers
        .into_iter()
        .map(|(name, data)| ElfSection {
            name: names
                .get(name..)
                .and_then(|rest| rest.split(|byte| *byte == 0).next())
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default(),
            data,
        })
        .collect())
}

struct LineProgram {
    include_directories: Vec<String>,
    rows: Vec<LineRow>,
}

/// Decode DWARF 2-4 (32-bit format) line number programs.
fn parse_line_program(section: &[u8]) -> Result<LineProgram> {
    let invalid = |what: &str| Error::InvalidCapture(format!("invalid .debug_line: {what}"));
    let mut reader = Reader {
        data: section,
        offset: 0,
    };
    let mut include_directories = Vec::new();
    let mut rows = Vec::new();
    while reader.offset < section.len() {
        let unit_length = reader.u32().ok_or_else(|| invalid("unit length"))? as usize;
        if unit_length >= 0xffff_fff0 {
            return Err(invalid("64-bit DWARF is not supported"));
        }
        let unit_end = reader.offset + unit_length;
        if unit_end > section.len() {
            return Err(invalid("unit exceeds section"));
        }
        let version = reader.u16().ok_or_else(|| invalid("version"))?;
        if !(2..=4).contains(&version) {
            return Err(invalid(&format!("unsupported version {version}")));
        }
        let header_length = reader.u32().ok_or_else(|| invalid("header length"))? as usize;
        let program_start = reader.offset + header_length;
        let minimum_instruction_length = u64::from(reader.u8().ok_or_else(|| invalid("header"))?);
        if version >= 4 {
            reader.u8().ok_or_else(|| invalid("header"))?;
        }
        reader.u8().ok_or_else(|| invalid("header"))?;
        let line_base = reader.u8().ok_or_else(|| invalid("header"))? as i8;
        let line_range = reader.u8().ok_or_else(|| invalid("header"))?;
        let opcode_base = reader.u8().ok_or_else(|| invalid("header"))?;
        if line_range == 0 || opcode_base == 0 {
            return Err(invalid("header"));
        }
        let standard_lengths: Vec<u8> = (1..opcode_base)
            .map(|_| reader.u8())
            .collect::<Option<_>>()
            .ok_or_else(|| invalid("standard opcode lengths"))?;
        loop {
            let directory = reader.cstr().ok_or_else(|| invalid("include directory"))?;
            if directory.is_empty() {
                break;
            }
            include_directories.push(directory);
        }
        loop {
            let file = reader.cstr().ok_or_else(|| invalid("file name"))?;
            if file.is_empty() {
                break;
            }
            for _ in 0..3 {
                reader.uleb().ok_or_else(|| invalid("file entry"))?;
            }
        }
        reader.offset = program_start;
        let mut address = 0u64;
        let mut line = 1i64;
        while reader.offset < unit_end {
            let opcode = reader.u8().ok_or_else(|| invalid("opcode"))?;
            if opcode >= opcode_base {
                let adjusted = opcode - opcode_base;
                address += u64::from(adjusted / line_range) * minimum_instruction_length;
                line += i64::from(line_base) + i64::from(adjusted % line_range);
                rows.push(line_row(address, line, false));
                continue;
            }
            match opcode {
                0 => {
                    let length = reader.uleb().ok_or_else(|| invalid("extended length"))? as usize;
                    let next = reader.offset + length;
                    match reader.u8().ok_or_else(|| invalid("extended opcode"))? {
                        1 => {
                            rows.push(line_row(address, line, true));
                            address = 0;
                            line = 1;
                        }
                        2 => {
                            address = match length {
                                9 => reader.u64(),
                                5 => reader.u32().map(u64::from),
                                _ => None,
                            }
                            .ok_or_else(|| invalid("set_address"))?;
                        }
                        _ => {}
                    }
                    reader.offset = next;
                }
                1 => rows.push(line_row(address, line, false)),
                2 => {
                    address += reader.uleb().ok_or_else(|| invalid("advance_pc"))?
                        * minimum_instruction_length;
                }
                3 => line += reader.sleb().ok_or_else(|| invalid("advance_line"))?,
                8 => {
                    address +=
                        u64::from((255 - opcode_base) / line_range) * minimum_instruction_length;
                }
                9 => address += u64::from(reader.u16().ok_or_else(|| invalid("fixed_advance_pc"))?),
                _ => {
                    for _ in 0..standard_lengths[usize::from(opcode) - 1] {
                        reader.uleb().ok_or_else(|| invalid("operand"))?;
                    }
                }
            }
        }
        reader.offset = unit_end;
    }
    rows.sort_by_key(|row| (row.address, row.end_sequence));
    Ok(LineProgram {
        include_directories,
        rows,
    })
}

fn line_row(address: u64, line: i64, end_sequence: bool) -> LineRow {
    LineRow {
        address,
        line: u32::try_from(line).unwrap_or(0),
        end_sequence,
    }
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let bytes = self
            .data
            .get(self.offset..self.offset + N)?
            .try_into()
            .ok()?;
        self.offset += N;
        Some(bytes)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_le_bytes)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0i64;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            value |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    value |= -1 << shift;
                }
                return Some(value);
            }
            if shift >= 64 {
                return None;
            }
        }
    }

    fn cstr(&mut self) -> Option<String> {
        let rest = self.data.get(self.offset..)?;
        let end = rest.iter().position(|byte| *byte == 0)?;
        self.offset += end + 1;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }
}

fn intern_location(
    locations: &mut Vec<SourceLocation>,
    ids: &mut HashMap<SourceLocation, u32>,
    location: SourceLocation,
) -> u32 {
    *ids.entry(location.clone()).or_insert_with(|| {
        locations.push(location);
        (locations.len() - 1) as u32
    })
}

fn words_to_string(words: &[u32]) -> String {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub(crate) fn file_basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

pub fn opcode_name(opcode: u16) -> Option<&'static str> {
    OPCODES
        .binary_search_by_key(&opcode, |entry| entry.0)
        .ok()
        .map(|index| OPCODES[index].1)
}

fn opcode_flags(opcode: u16) -> u8 {
    OPCODES
        .binary_search_by_key(&opcode, |entry| entry.0)
        .map(|index| OPCODES[index].2)
        .unwrap_or(0)
}

/// `spirv-dis`-like friendly names for common type declarations.
fn type_name(
    opcode: u16,
    operands: &[u32],
    types: &HashMap<u32, String>,
    names: &HashMap<u32, String>,
) -> Option<String> {
    let lookup = |id: Option<&u32>| -> String {
        id.and_then(|id| types.get(id))
            .cloned()
            .unwrap_or_else(|| "?".into())
    };
    Some(match opcode {
        19 => "void".into(),
        20 => "bool".into(),
        21 => {
            let width = operands.get(1).copied().unwrap_or(32);
            let signed = operands.get(2).copied().unwrap_or(0) != 0;
            match (width, signed) {
                (32, true) => "int".into(),
                (32, false) => "uint".into(),
                (width, true) => format!("int{width}"),
                (width, false) => format!("uint{width}"),
            }
        }
        22 => match operands.get(1).copied().unwrap_or(32) {
            16 => "half".into(),
            32 => "float".into(),
            64 => "double".into(),
            width => format!("float{width}"),
        },
        23 => format!(
            "v{}{}",
            operands.get(2).copied().unwrap_or(0),
            lookup(operands.get(1))
        ),
        24 => format!(
            "mat{}{}",
            operands.get(2).copied().unwrap_or(0),
            lookup(operands.get(1))
        ),
        28 | 29 => format!("_arr_{}", lookup(operands.get(1))),
        30 => names
            .get(operands.first()?)
            .filter(|name| !name.is_empty())
            .cloned()
            .unwrap_or_else(|| "struct".into()),
        32 => format!(
            "_ptr_{}_{}",
            storage_class_name(operands.get(1).copied().unwrap_or(u32::MAX)),
            lookup(operands.get(2))
        ),
        _ => return None,
    })
}

fn storage_class_name(class: u32) -> String {
    match class {
        0 => "UniformConstant".into(),
        1 => "Input".into(),
        2 => "Uniform".into(),
        3 => "Output".into(),
        4 => "Workgroup".into(),
        5 => "CrossWorkgroup".into(),
        6 => "Private".into(),
        7 => "Function".into(),
        9 => "PushConstant".into(),
        11 => "Image".into(),
        12 => "StorageBuffer".into(),
        5349 => "PhysicalStorageBuffer".into(),
        other => format!("StorageClass{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_matches_the_original_variant_test_vector() {
        // draft-agl-tls-chacha20poly1305 / Bernstein reference: zero key, zero nonce.
        let block = chacha20_block(&[0; 32], 0);
        assert_eq!(
            &block[..16],
            &[
                0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
                0xbd, 0x28
            ]
        );
    }

    #[test]
    fn keystream_round_trips_across_blocks() {
        let key: [u8; 32] = std::array::from_fn(|index| index as u8 * 7 + 1);
        let original: Vec<u8> = (0..200u8).collect();
        let mut data = original.clone();
        apply_keystream(&key, &mut data);
        assert_ne!(data, original);
        apply_keystream(&key, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn lookup8_matches_reference_values() {
        // Values from an independent implementation that reproduces the
        // module hashes shown by Nsight Graphics.
        let data: Vec<u8> = (0..50u8).collect();
        assert_eq!(lookup8(b""), 0x8db6_3936_9385_75bf);
        assert_eq!(lookup8(&data[..24]), 0xa753_45f1_96a6_716a);
        assert_eq!(lookup8(&data), 0x10a8_ebdd_00c8_cf10);
    }

    #[test]
    fn sass_classes_use_the_opcode_and_bit_91() {
        let instruction = |low: u64, high: u64| {
            let mut bytes = low.to_le_bytes().to_vec();
            bytes.extend(high.to_le_bytes());
            bytes
        };
        let label = |sm: u32, bytes: &[u8]| classify_sass(sm, bytes).map(|class| class.label());
        let nop = instruction(0x7918, 0x000f_e400_0000_0000);
        let sts = instruction(0x002a_8000_0700_7388, 0x0041_f200_0000_4800);
        let iadd3 = instruction(0x0000_0014_151e_7211, 0x001f_e200_078e_20ff);
        assert_eq!(label(0x80009, &nop).as_deref(), Some("SCH NOP"));
        assert_eq!(
            label(0x80009, &sts).as_deref(),
            Some("LSU Shared Memory Store")
        );
        assert_eq!(
            label(0x80009, &iadd3).as_deref(),
            Some("ALU Integer Arithmetic")
        );
        // Bit 91 selects key 0x1211, which has no class.
        let uniform = instruction(0x7211, 1 << 27);
        assert_eq!(label(0x80009, &uniform), None);
        assert_eq!(label(0x90000, &nop), None);
    }

    #[test]
    fn key_probe_masks_unknown_bytes() {
        let probe = KeyProbe {
            cipher: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
            plain: [0x03, 0x02, 0x23, 0x07, 0, 0, 0, 0],
            mask: [0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0xff],
        };
        let mut stream = [0u8; 64];
        for (byte, (cipher, plain)) in stream.iter_mut().zip(probe.cipher.iter().zip(probe.plain)) {
            *byte = cipher ^ plain;
        }
        stream[5] ^= 0x5a;
        assert!(probe.matches(&stream));
        stream[4] ^= 1;
        assert!(!probe.matches(&stream));
    }

    #[test]
    fn module_hash_comes_from_the_include_directory() {
        let directory = "./\"stage>cs\"fmt>spir\"ShaderModuleHash>36cf63efe2e621e";
        assert_eq!(
            directory_attribute(directory, "ShaderModuleHash"),
            Some("36cf63efe2e621e")
        );
        assert_eq!(directory_attribute(directory, "stage"), Some("cs"));
        assert_eq!(directory_attribute(directory, "missing"), None);
    }

    fn spirv_words(instructions: &[Vec<u32>]) -> Vec<u8> {
        let mut words = vec![SPIRV_MAGIC, 0x0001_0600, 0x0008_000b, 20, 0];
        for instruction in instructions {
            words.extend(instruction);
        }
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn string_operands(text: &str) -> Vec<u32> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect()
    }

    #[test]
    fn op_line_scopes_last_until_the_function_ends() {
        let file = string_operands("C:/shaders/a.comp");
        let mut op_string = vec![((2 + file.len() as u32) << 16) | 7, 1];
        op_string.extend(&file);
        let module = spirv_words(&[
            op_string,
            vec![(3 << 16) | 22, 2, 32],
            vec![(4 << 16) | 8, 1, 42, 3],
            vec![(5 << 16) | 129, 2, 5, 6, 6],
            vec![(1 << 16) | 317],
            vec![(5 << 16) | 129, 2, 10, 5, 5],
            vec![(2 << 16) | 248, 7],
            vec![(5 << 16) | 129, 2, 8, 9, 9],
            vec![(1 << 16) | 56],
            vec![(5 << 16) | 129, 2, 11, 9, 9],
        ]);
        let parsed = SpirvModule::parse(&module).unwrap();
        assert_eq!(parsed.instructions.len(), 10);
        let location = parsed.instruction_locations[3].unwrap();
        assert_eq!(
            parsed.locations[location as usize],
            SourceLocation {
                file: "C:/shaders/a.comp".into(),
                line: 42
            }
        );
        for index in 4..8 {
            assert_eq!(parsed.instruction_locations[index], Some(location));
        }
        assert_eq!(parsed.instruction_locations[8], None);
        assert_eq!(parsed.instruction_locations[9], None);
        assert_eq!(parsed.describe(3).as_deref(), Some("OpFAdd %float"));
    }

    #[test]
    fn line_program_rows_map_to_spirv_instructions() {
        // Minimal DWARF 2 unit: one directory, one file, rows at 0x00 (line 10) and 0x20 (line 12).
        let mut header = Vec::new();
        header.extend([1, 1, 0xfb, 14, 10]);
        header.extend([0, 1, 1, 1, 1, 0, 0, 0, 1]);
        header.extend(b"./\"ShaderModuleHash>abc\0\0");
        header.extend(b"comp.spv\0\x01\0\0\0");
        let mut program = vec![0, 9, 2];
        program.extend(0u64.to_le_bytes());
        program.extend([3, 9, 1]); // advance_line 9 -> 10, copy
        program.extend([2, 0x20, 3, 2, 1]); // advance_pc 0x20, advance_line 2, copy
        program.extend([2, 0x10, 0, 1, 1]); // advance_pc 0x10, end_sequence
        let mut unit = Vec::new();
        unit.extend(2u16.to_le_bytes());
        unit.extend((header.len() as u32).to_le_bytes());
        unit.extend(&header);
        unit.extend(&program);
        let mut section = (unit.len() as u32).to_le_bytes().to_vec();
        section.extend(unit);

        let parsed = parse_line_program(&section).unwrap();
        assert_eq!(parsed.include_directories, ["./\"ShaderModuleHash>abc"]);
        assert_eq!(parsed.rows.len(), 3);
        let slots = correlate(&parsed.rows, 4, None);
        assert_eq!(slots[0].spirv_index, Some(4));
        assert_eq!(slots[1].spirv_index, Some(4));
        assert_eq!(slots[2].spirv_index, Some(6));
        assert_eq!(slots[3].spirv_index, None);
    }
}
