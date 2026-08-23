use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::{Path, PathBuf},
};

use prost::Message;
use prost_reflect::{
    Cardinality, DynamicMessage, FieldDescriptor, Kind, MapKey, ReflectMessage, Value,
};
use prost_types::{FileDescriptorProto, FileDescriptorSet};
use serde::Serialize;
use serde_json::{Map, Number};
use sha2::{Digest, Sha256};

use crate::{
    Error, Result,
    container::{Container, SectionRole},
};

pub const TRACE_MESSAGE: &str = "NV.WarpViz.PbTraceData";
#[cfg(not(target_os = "windows"))]
const SCHEMA_FILENAME: &str = "libWarpVizPlugin.so";
#[cfg(target_os = "windows")]
const SCHEMA_FILENAME: &str = "WarpVizPlugin.dll";
const MAX_DESCRIPTOR_WIRE_SIZE: usize = 4 << 20;

#[derive(Debug, Clone, Copy)]
pub struct QueryOptions {
    pub offset: usize,
    pub limit: usize,
    pub max_depth: usize,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
            max_depth: 6,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaField {
    pub name: String,
    pub json_name: String,
    pub number: u32,
    pub kind: String,
    pub cardinality: String,
    pub oneof: Option<String>,
    pub present: bool,
    pub item_count: Option<usize>,
}

/// Metadata for one populated protobuf `bytes` field.
#[derive(Debug, Clone, Serialize)]
pub struct ByteField {
    pub path: String,
    pub message_type: String,
    pub field_name: String,
    pub field_number: u32,
    pub size: usize,
    pub sha256: String,
    pub preview_hex: String,
}

/// A decoded trace together with its container, raw bytes, and runtime schema.
pub struct TraceDocument {
    container: Container,
    schema_binary: PathBuf,
    descriptor_set: FileDescriptorSet,
    pool: prost_reflect::DescriptorPool,
    raw_protobuf: Vec<u8>,
    message: DynamicMessage,
}

impl std::fmt::Debug for TraceDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TraceDocument")
            .field("container", &self.container)
            .field("schema_binary", &self.schema_binary)
            .field("descriptor_count", &self.descriptor_set.file.len())
            .field("raw_protobuf_size", &self.raw_protobuf.len())
            .finish()
    }
}

impl TraceDocument {
    pub fn open(path: impl AsRef<Path>, schema_binary: Option<&Path>) -> Result<Self> {
        let container = Container::open(path)?;
        Self::from_container(container, schema_binary)
    }

    pub fn from_container(container: Container, schema_binary: Option<&Path>) -> Result<Self> {
        let section = container.section(SectionRole::ProtobufTrace)?;
        let raw_protobuf = container.read_section(section)?;
        let schema_binary = discover_schema_binary(schema_binary)?;
        let descriptor_set = extract_descriptor_set(&schema_binary)?;
        let pool = prost_reflect::DescriptorPool::from_file_descriptor_set(descriptor_set.clone())?;
        let descriptor = pool
            .get_message_by_name(TRACE_MESSAGE)
            .ok_or_else(|| Error::Protobuf(format!("schema does not define {TRACE_MESSAGE}")))?;
        let message = DynamicMessage::decode(descriptor, raw_protobuf.as_slice())?;
        Ok(Self {
            container,
            schema_binary,
            descriptor_set,
            pool,
            raw_protobuf,
            message,
        })
    }

    pub fn container(&self) -> &Container {
        &self.container
    }

    pub fn schema_binary(&self) -> &Path {
        &self.schema_binary
    }

    pub fn descriptor_set(&self) -> &FileDescriptorSet {
        &self.descriptor_set
    }

    pub fn descriptor_set_bytes(&self) -> Vec<u8> {
        self.descriptor_set.encode_to_vec()
    }

    pub fn pool(&self) -> &prost_reflect::DescriptorPool {
        &self.pool
    }

    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw_protobuf
    }

    pub fn message(&self) -> &DynamicMessage {
        &self.message
    }

    /// Return the complete standard ProtoJSON representation of the trace.
    /// Byte fields are base64 encoded. Unknown wire fields remain available in
    /// [`Self::raw_protobuf`] and survive `DynamicMessage` re-encoding.
    pub fn full_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(&self.message)?)
    }

    /// Query a dot-separated field path. Numeric components index lists.
    pub fn query(&self, path: &str, options: QueryOptions) -> Result<serde_json::Value> {
        let resolved = resolve_path(&self.message, path)?;
        Ok(value_to_bounded_json(
            &resolved.value,
            resolved.field.as_ref(),
            0,
            options,
            true,
        ))
    }

    /// Describe all fields of the message at `path`, including empty fields.
    pub fn schema(&self, path: &str) -> Result<Vec<SchemaField>> {
        let resolved = resolve_path(&self.message, path)?;
        let Value::Message(message) = resolved.value else {
            return Err(Error::TracePath(format!(
                "{path:?} resolves to {}, not a message",
                value_kind_name(&resolved.value)
            )));
        };
        let descriptor = message.descriptor();
        Ok(descriptor
            .fields()
            .map(|field| {
                let value = message.get_field(&field);
                SchemaField {
                    name: field.name().to_owned(),
                    json_name: field.json_name().to_owned(),
                    number: field.number(),
                    kind: field_kind_name(&field),
                    cardinality: match field.cardinality() {
                        Cardinality::Optional => "optional",
                        Cardinality::Required => "required",
                        Cardinality::Repeated => "repeated",
                    }
                    .to_owned(),
                    oneof: field.containing_oneof().map(|item| item.name().to_owned()),
                    present: message.has_field(&field),
                    item_count: match value.as_ref() {
                        Value::List(items) => Some(items.len()),
                        Value::Map(items) => Some(items.len()),
                        _ => None,
                    },
                }
            })
            .collect())
    }

    pub fn extract_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let resolved = resolve_path(&self.message, path)?;
        match resolved.value {
            Value::Bytes(bytes) => Ok(bytes.to_vec()),
            value => Err(Error::TracePath(format!(
                "{path:?} resolves to {}, not bytes",
                value_kind_name(&value)
            ))),
        }
    }

    /// Inventory every populated protobuf `bytes` value without copying the
    /// payloads. Paths use the same dot/list-index notation as [`Self::query`].
    pub fn byte_fields(&self) -> Vec<ByteField> {
        let mut fields = Vec::new();
        let mut collect = |field: &ByteField, _data: &[u8]| {
            fields.push(field.clone());
            Ok(())
        };
        visit_message_bytes(&self.message, "", &mut collect)
            .expect("metadata-only byte visitor cannot fail");
        fields
    }

    /// Visit every populated protobuf `bytes` value without materializing a
    /// second copy. This is the lossless extraction path for screenshots,
    /// shader code/debug records, sampling payloads, and future byte fields.
    pub fn visit_bytes(
        &self,
        mut visitor: impl FnMut(&ByteField, &[u8]) -> Result<()>,
    ) -> Result<()> {
        visit_message_bytes(&self.message, "", &mut visitor)
    }

    pub fn unknown_field_count(&self) -> usize {
        count_unknown_fields(&self.message)
    }
}

fn visit_message_bytes(
    message: &DynamicMessage,
    prefix: &str,
    visitor: &mut impl FnMut(&ByteField, &[u8]) -> Result<()>,
) -> Result<()> {
    let message_type = message.descriptor().full_name().to_owned();
    for (field, value) in message.fields() {
        let path = join_path(prefix, field.name());
        visit_value_bytes(value, &field, &message_type, &path, visitor)?;
    }
    Ok(())
}

fn visit_value_bytes(
    value: &Value,
    field: &FieldDescriptor,
    message_type: &str,
    path: &str,
    visitor: &mut impl FnMut(&ByteField, &[u8]) -> Result<()>,
) -> Result<()> {
    match value {
        Value::Bytes(bytes) => {
            let digest = Sha256::digest(bytes);
            visitor(
                &ByteField {
                    path: path.to_owned(),
                    message_type: message_type.to_owned(),
                    field_name: field.name().to_owned(),
                    field_number: field.number(),
                    size: bytes.len(),
                    sha256: hex(&digest),
                    preview_hex: hex(&bytes[..bytes.len().min(32)]),
                },
                bytes,
            )?;
        }
        Value::Message(child) => visit_message_bytes(child, path, visitor)?,
        Value::List(items) => {
            for (index, item) in items.iter().enumerate() {
                visit_value_bytes(
                    item,
                    field,
                    message_type,
                    &join_path(path, &index.to_string()),
                    visitor,
                )?;
            }
        }
        Value::Map(items) => {
            for (key, item) in items {
                visit_value_bytes(
                    item,
                    field,
                    message_type,
                    &join_path(path, &map_key_string(key)),
                    visitor,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn join_path(prefix: &str, component: &str) -> String {
    if prefix.is_empty() {
        component.to_owned()
    } else {
        format!("{prefix}.{component}")
    }
}

pub fn discover_schema_binary(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return require_file(path, "WarpViz schema binary");
    }
    for variable in ["NGFX_SCHEMA_BINARY", "WRPV_SCHEMA_BINARY"] {
        if let Some(value) = env::var_os(variable) {
            return require_file(Path::new(&value), "WarpViz schema binary");
        }
    }

    let roots = nsight_search_roots();
    let mut candidates = Vec::new();
    for root in &roots {
        find_named_file(root, SCHEMA_FILENAME, 8, &mut candidates);
    }
    candidates.sort();
    candidates.pop().ok_or(Error::Discovery {
        kind: "WarpVizPlugin schema binary (set NGFX_SCHEMA_BINARY)",
        searched: roots,
    })
}

pub(crate) fn nsight_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(target_os = "windows")]
    for variable in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(path) = env::var_os(variable) {
            roots.push(PathBuf::from(path).join("NVIDIA Corporation"));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = env::var_os("HOME") {
            roots.push(PathBuf::from(home).join("nvidia"));
        }
        roots.push(PathBuf::from("/opt/nvidia/nsight-graphics"));
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Extract embedded `FileDescriptorProto` records without redistributing
/// NVIDIA's generated schema.
pub fn extract_descriptor_set(binary: &Path) -> Result<FileDescriptorSet> {
    let data = fs::read(binary)?;
    let mut descriptors: HashMap<String, (usize, FileDescriptorProto)> = HashMap::new();
    let mut start = 0usize;
    while start + 3 < data.len() {
        if data[start] != 0x0a {
            start += 1;
            continue;
        }
        let name_len = data[start + 1] as usize;
        let name_start = start + 2;
        let name_end = name_start.saturating_add(name_len);
        if !(1..=127).contains(&name_len)
            || name_end > data.len()
            || !data[name_start..name_end]
                .iter()
                .all(|byte| (0x20..=0x7e).contains(byte))
            || !data[name_start..name_end].ends_with(b".proto")
        {
            start += 1;
            continue;
        }
        let Ok(name) = std::str::from_utf8(&data[name_start..name_end]) else {
            start += 1;
            continue;
        };
        let wire_end = walk_protobuf(&data, start, MAX_DESCRIPTOR_WIRE_SIZE);
        if wire_end <= name_end {
            start += 1;
            continue;
        }
        let minimum = name_end.max(wire_end.saturating_sub(4096));
        let mut chosen = None;
        for candidate_end in (minimum..=wire_end).rev() {
            let Ok(descriptor) = FileDescriptorProto::decode(&data[start..candidate_end]) else {
                continue;
            };
            if descriptor.name.as_deref() == Some(name) {
                chosen = Some((candidate_end - start, descriptor));
                break;
            }
        }
        if let Some(candidate) = chosen {
            let replace = descriptors
                .get(name)
                .is_none_or(|current| current.0 < candidate.0);
            if replace {
                descriptors.insert(name.to_owned(), candidate);
            }
        }
        start += 1;
    }
    if !descriptors.contains_key("WarpViz.proto") {
        return Err(Error::Protobuf(format!(
            "WarpViz.proto descriptor not found in {}",
            binary.display()
        )));
    }
    let mut ordered: BTreeMap<String, FileDescriptorProto> = BTreeMap::new();
    for (name, (_, descriptor)) in descriptors {
        ordered.insert(name, descriptor);
    }
    Ok(FileDescriptorSet {
        file: ordered.into_values().collect(),
    })
}

fn walk_protobuf(data: &[u8], start: usize, cap: usize) -> usize {
    let mut offset = start;
    let end = data.len().min(start.saturating_add(cap));
    while offset < end {
        let Some((tag, tag_size)) = read_varint(data, offset) else {
            break;
        };
        let wire = tag & 7;
        if tag >> 3 == 0 || !matches!(wire, 0 | 1 | 2 | 5) {
            break;
        }
        offset += tag_size;
        match wire {
            0 => {
                let Some((_, size)) = read_varint(data, offset) else {
                    break;
                };
                offset += size;
            }
            1 => offset = offset.saturating_add(8),
            5 => offset = offset.saturating_add(4),
            2 => {
                let Some((length, size)) = read_varint(data, offset) else {
                    break;
                };
                let Ok(length) = usize::try_from(length) else {
                    return start;
                };
                offset = offset.saturating_add(size).saturating_add(length);
            }
            _ => unreachable!(),
        }
        if offset > end {
            return start;
        }
    }
    offset
}

fn read_varint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for count in 0..10 {
        let byte = *data.get(offset + count)?;
        value |= u64::from(byte & 0x7f) << (count * 7);
        if byte & 0x80 == 0 {
            return Some((value, count + 1));
        }
    }
    None
}

struct ResolvedValue {
    value: Value,
    field: Option<FieldDescriptor>,
}

fn resolve_path(root: &DynamicMessage, path: &str) -> Result<ResolvedValue> {
    let mut resolved = ResolvedValue {
        value: Value::Message(root.clone()),
        field: None,
    };
    if path.is_empty() {
        return Ok(resolved);
    }
    for component in path.split('.') {
        if component.is_empty() {
            return Err(Error::TracePath("path contains an empty component".into()));
        }
        resolved = match resolved.value {
            Value::Message(message) => {
                let descriptor = message.descriptor();
                let field = descriptor
                    .get_field_by_name(component)
                    .or_else(|| descriptor.get_field_by_json_name(component))
                    .ok_or_else(|| {
                        Error::TracePath(format!(
                            "message {} has no field {component:?}",
                            descriptor.full_name()
                        ))
                    })?;
                ResolvedValue {
                    value: message.get_field(&field).into_owned(),
                    field: Some(field),
                }
            }
            Value::List(items) => {
                let index = component.parse::<usize>().map_err(|_| {
                    Error::TracePath(format!("list component {component:?} is not an index"))
                })?;
                let value = items.get(index).cloned().ok_or_else(|| {
                    Error::TracePath(format!(
                        "list index {index} out of range (length {})",
                        items.len()
                    ))
                })?;
                ResolvedValue {
                    value,
                    field: resolved.field,
                }
            }
            Value::Map(items) => {
                let key = MapKey::String(component.to_owned());
                let value = items.get(&key).cloned().ok_or_else(|| {
                    Error::TracePath(format!("map has no string key {component:?}"))
                })?;
                ResolvedValue {
                    value,
                    field: resolved.field,
                }
            }
            value => {
                return Err(Error::TracePath(format!(
                    "cannot descend through {} at {component:?}",
                    value_kind_name(&value)
                )));
            }
        };
    }
    Ok(resolved)
}

fn value_to_bounded_json(
    value: &Value,
    field: Option<&FieldDescriptor>,
    depth: usize,
    options: QueryOptions,
    root: bool,
) -> serde_json::Value {
    if depth >= options.max_depth
        && matches!(value, Value::Message(_) | Value::List(_) | Value::Map(_))
    {
        return serde_json::json!({
            "truncated": true,
            "kind": value_kind_name(value),
        });
    }
    match value {
        Value::Bool(value) => (*value).into(),
        Value::I32(value) => (*value).into(),
        Value::I64(value) => (*value).into(),
        Value::U32(value) => (*value).into(),
        Value::U64(value) => (*value).into(),
        Value::F32(value) => float_json(f64::from(*value)),
        Value::F64(value) => float_json(*value),
        Value::String(value) => value.clone().into(),
        Value::Bytes(bytes) => bytes_summary(bytes),
        Value::EnumNumber(number) => enum_json(field, *number),
        Value::Message(message) => {
            let mut result = Map::new();
            for (child_field, child_value) in message.fields() {
                result.insert(
                    child_field.name().to_owned(),
                    value_to_bounded_json(
                        child_value,
                        Some(&child_field),
                        depth + 1,
                        options,
                        false,
                    ),
                );
            }
            let unknown = message.unknown_fields().count();
            if unknown > 0 {
                result.insert("__unknown_field_count".into(), unknown.into());
            }
            result.into()
        }
        Value::List(items) => {
            let offset = if root {
                options.offset.min(items.len())
            } else {
                0
            };
            let limit = options.limit.max(1);
            let stop = items.len().min(offset.saturating_add(limit));
            let values: Vec<_> = items[offset..stop]
                .iter()
                .map(|item| value_to_bounded_json(item, field, depth + 1, options, false))
                .collect();
            if stop < items.len() || offset > 0 {
                serde_json::json!({
                    "items": values,
                    "page": {
                        "offset": offset,
                        "returned": stop - offset,
                        "total": items.len(),
                        "next_offset": (stop < items.len()).then_some(stop),
                    }
                })
            } else {
                values.into()
            }
        }
        Value::Map(items) => {
            let mut ordered: Vec<_> = items.iter().collect();
            ordered.sort_by_key(|(key, _)| map_key_string(key));
            let mut result = Map::new();
            for (key, value) in ordered.into_iter().take(options.limit.max(1)) {
                result.insert(
                    map_key_string(key),
                    value_to_bounded_json(value, field, depth + 1, options, false),
                );
            }
            result.into()
        }
    }
}

fn enum_json(field: Option<&FieldDescriptor>, number: i32) -> serde_json::Value {
    let Some(Kind::Enum(descriptor)) = field.map(FieldDescriptor::kind) else {
        return number.into();
    };
    descriptor
        .get_value(number)
        .map(|value| value.name().to_owned().into())
        .unwrap_or_else(|| number.into())
}

fn float_json(value: f64) -> serde_json::Value {
    Number::from_f64(value)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| {
            if value.is_nan() {
                "NaN".into()
            } else if value.is_sign_positive() {
                "Infinity".into()
            } else {
                "-Infinity".into()
            }
        })
}

fn bytes_summary(bytes: &[u8]) -> serde_json::Value {
    let digest = Sha256::digest(bytes);
    serde_json::json!({
        "size": bytes.len(),
        "sha256": hex(&digest),
        "preview_hex": hex(&bytes[..bytes.len().min(32)]),
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn field_kind_name(field: &FieldDescriptor) -> String {
    let base = match field.kind() {
        Kind::Double => "double".into(),
        Kind::Float => "float".into(),
        Kind::Int32 => "int32".into(),
        Kind::Int64 => "int64".into(),
        Kind::Uint32 => "uint32".into(),
        Kind::Uint64 => "uint64".into(),
        Kind::Sint32 => "sint32".into(),
        Kind::Sint64 => "sint64".into(),
        Kind::Fixed32 => "fixed32".into(),
        Kind::Fixed64 => "fixed64".into(),
        Kind::Sfixed32 => "sfixed32".into(),
        Kind::Sfixed64 => "sfixed64".into(),
        Kind::Bool => "bool".into(),
        Kind::String => "string".into(),
        Kind::Bytes => "bytes".into(),
        Kind::Message(value) => format!("message:{}", value.full_name()),
        Kind::Enum(value) => format!("enum:{}", value.full_name()),
    };
    if field.is_map() {
        format!("map<{base}>")
    } else if field.is_list() {
        format!("list<{base}>")
    } else {
        base
    }
}

fn value_kind_name(value: &Value) -> &'static str {
    match value {
        Value::Bool(_) => "bool",
        Value::I32(_) => "i32",
        Value::I64(_) => "i64",
        Value::U32(_) => "u32",
        Value::U64(_) => "u64",
        Value::F32(_) => "f32",
        Value::F64(_) => "f64",
        Value::String(_) => "string",
        Value::Bytes(_) => "bytes",
        Value::EnumNumber(_) => "enum",
        Value::Message(_) => "message",
        Value::List(_) => "list",
        Value::Map(_) => "map",
    }
}

fn map_key_string(key: &MapKey) -> String {
    match key {
        MapKey::Bool(value) => value.to_string(),
        MapKey::I32(value) => value.to_string(),
        MapKey::I64(value) => value.to_string(),
        MapKey::U32(value) => value.to_string(),
        MapKey::U64(value) => value.to_string(),
        MapKey::String(value) => value.clone(),
    }
}

fn count_unknown_fields(message: &DynamicMessage) -> usize {
    let mut count = message.unknown_fields().count();
    for (_, value) in message.fields() {
        count += match value {
            Value::Message(child) => count_unknown_fields(child),
            Value::List(items) => items
                .iter()
                .map(|item| match item {
                    Value::Message(child) => count_unknown_fields(child),
                    _ => 0,
                })
                .sum(),
            Value::Map(items) => items
                .values()
                .map(|item| match item {
                    Value::Message(child) => count_unknown_fields(child),
                    _ => 0,
                })
                .sum(),
            _ => 0,
        };
    }
    count
}

fn require_file(path: &Path, kind: &'static str) -> Result<PathBuf> {
    let path = path.to_path_buf();
    if path.is_file() {
        Ok(path.canonicalize().unwrap_or(path))
    } else {
        Err(Error::Discovery {
            kind,
            searched: vec![path],
        })
    }
}

pub(crate) fn find_named_file(
    root: &Path,
    filename: &str,
    depth: usize,
    output: &mut Vec<PathBuf>,
) {
    if depth == 0 || !root.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == filename) && path.is_file() {
            output.push(path);
        } else if path.is_dir() {
            find_named_file(&path, filename, depth - 1, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_reader_rejects_truncation() {
        assert_eq!(read_varint(&[0xac, 0x02], 0), Some((300, 2)));
        assert_eq!(read_varint(&[0x80], 0), None);
    }

    #[test]
    fn finds_platform_schema_binary() {
        let root = tempfile::tempdir().unwrap();
        let plugin = root
            .path()
            .join("Nsight Graphics 2026.3")
            .join("Plugins")
            .join("WarpVizPlugin")
            .join(SCHEMA_FILENAME);
        fs::create_dir_all(plugin.parent().unwrap()).unwrap();
        fs::write(&plugin, b"schema").unwrap();

        let mut found = Vec::new();
        find_named_file(root.path(), SCHEMA_FILENAME, 6, &mut found);
        assert_eq!(found, vec![plugin]);
    }
}
