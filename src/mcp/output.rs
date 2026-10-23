//! Keep evidence out of the transcript until a caller selects it.

use std::{cmp::Ordering, collections::VecDeque, fs, path::PathBuf};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{integer, page, serialized_len, tool_success};

pub(super) const DEFAULT_BYTES: usize = 12 * 1024;
const MAX_BYTES: usize = 64 * 1024;
const STORE_BYTES: usize = 64 * 1024 * 1024;
const RESULT_BYTES: usize = 16 * 1024 * 1024;
const STORE_COUNT: usize = 16;

pub(super) struct ResultStore {
    entries: VecDeque<(String, Vec<u8>)>,
    bytes: usize,
    disk_dir: Option<PathBuf>,
}

impl Default for ResultStore {
    fn default() -> Self {
        let disk_dir = result_cache_dir()
            .filter(|path| fs::create_dir_all(path).is_ok())
            .map(|path| path.join("results"))
            .filter(|path| fs::create_dir_all(path).is_ok());
        Self::new(disk_dir)
    }
}

impl ResultStore {
    fn new(disk_dir: Option<PathBuf>) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            disk_dir,
        }
    }

    pub(super) fn insert(&mut self, value: &Value) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        if bytes.len() > RESULT_BYTES {
            return Err(
                "result exceeds 16 MiB; narrow the queries or use the CLI for bulk data".into(),
            );
        }
        let id = format!("{:x}", Sha256::digest(&bytes));
        if let Some(dir) = &self.disk_dir {
            let path = dir.join(format!("{id}.json"));
            if !path.is_file() {
                let _ = fs::write(path, &bytes);
            }
        }
        if self.entries.iter().any(|(key, _)| key == &id) {
            return Ok(id);
        }
        while self.entries.len() >= STORE_COUNT || self.bytes + bytes.len() > STORE_BYTES {
            if let Some((_, old)) = self.entries.pop_front() {
                self.bytes -= old.len();
            }
        }
        self.bytes += bytes.len();
        self.entries.push_back((id.clone(), bytes));
        Ok(id)
    }

    pub(super) fn get(&self, id: &str) -> Result<Value, String> {
        if let Some((_, bytes)) = self.entries.iter().find(|(key, _)| key == id) {
            return serde_json::from_slice(bytes).map_err(|error| error.to_string());
        }
        if let Some(dir) = &self.disk_dir {
            let path = dir.join(format!("{id}.json"));
            if let Ok(bytes) = fs::read(path) {
                return serde_json::from_slice(&bytes).map_err(|error| error.to_string());
            }
        }
        Err("result_id is unknown or expired; rerun the original capture query".to_owned())
    }
}

fn result_cache_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("NGFX_RESULT_CACHE") {
        return Some(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(path).join("ngfx-trace"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home).join(".cache").join("ngfx-trace"));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(local).join("ngfx-trace"));
    }
    None
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    #[default]
    Table,
    Json,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct View {
    pub(super) path: String,
    pub(super) select: Vec<String>,
    entries: bool,
    filter: Vec<Filter>,
    sort_by: Option<String>,
    descending: bool,
    offset: usize,
    limit: usize,
    format: Format,
}

impl Default for View {
    fn default() -> Self {
        Self {
            path: String::new(),
            select: Vec::new(),
            entries: false,
            filter: Vec::new(),
            sort_by: None,
            descending: true,
            offset: 0,
            limit: 20,
            format: Format::Table,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    path: String,
    op: Operator,
    value: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operator {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
}

impl View {
    pub(super) fn parse(arguments: &Map<String, Value>) -> Result<(Self, usize), String> {
        let view: Self = arguments
            .get("view")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|error| format!("view: {error}"))?
            .unwrap_or_default();
        let budget = integer(arguments, "max_bytes", DEFAULT_BYTES)?;
        if !(1024..=MAX_BYTES).contains(&budget) {
            return Err(format!("max_bytes must be between 1024 and {MAX_BYTES}"));
        }
        if !(1..=100).contains(&view.limit) || view.select.len() > 32 || view.filter.len() > 8 {
            return Err("view allows 1..100 rows, up to 32 selected fields and 8 filters".into());
        }
        for path in std::iter::once(&view.path)
            .chain(&view.select)
            .chain(view.sort_by.iter())
            .chain(view.filter.iter().map(|filter| &filter.path))
        {
            validate_pointer(path)?;
        }
        for filter in &view.filter {
            if filter.value.is_array() || filter.value.is_object() {
                return Err("filter values must be scalars".into());
            }
            if matches!(filter.op, Operator::Contains) && !filter.value.is_string() {
                return Err("contains requires a string value".into());
            }
        }
        Ok((view, budget))
    }
}

fn validate_pointer(path: &str) -> Result<(), String> {
    if path.len() > 2048 || (!path.is_empty() && !path.starts_with('/')) {
        return Err(
            "view paths must be JSON Pointers (empty or starting with /), at most 2048 bytes"
                .into(),
        );
    }
    let mut chars = path.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return Err("JSON Pointer escapes must be ~0 or ~1".into());
        }
    }
    Ok(())
}

fn pointer_child(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn project(value: &Value, fields: &[String]) -> Result<Value, String> {
    if fields.is_empty() {
        return Ok(value.clone());
    }
    fields
        .iter()
        .map(|path| {
            value
                .pointer(path)
                .cloned()
                .map(|value| (path.clone(), value))
                .ok_or_else(|| {
                    format!(
                        "selected field {path:?} is absent; inspect the row before selecting fields"
                    )
                })
        })
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}

/// Object previews use readable field names, while row projections retain the
/// exact JSON Pointer so callers can distinguish `/a/value` from `/b/value`.
fn project_friendly(value: &Value, fields: &[String]) -> Result<Value, String> {
    if fields.is_empty() {
        return Ok(value.clone());
    }
    let mut used = std::collections::BTreeSet::new();
    let mut projected = Map::new();
    for path in fields {
        let value = value.pointer(path).cloned().ok_or_else(|| {
            format!("selected field {path:?} is absent; inspect the row before selecting fields")
        })?;
        let mut key = path
            .rsplit('/')
            .next()
            .filter(|key| !key.is_empty())
            .unwrap_or(path)
            .replace("~1", "/")
            .replace("~0", "~");
        if !used.insert(key.clone()) {
            key = path.clone();
            used.insert(key.clone());
        }
        projected.insert(key, value);
    }
    Ok(Value::Object(projected))
}

// Preserve integer timestamp/index ordering above f64's exact integer range.
fn compare(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            let integer = |n: &serde_json::Number| {
                n.as_i64()
                    .map(i128::from)
                    .or_else(|| n.as_u64().map(i128::from))
            };
            let integer_float = |i: i128, f: f64| {
                i.cmp(&(f as i128))
                    .then_with(|| 0.0_f64.partial_cmp(&f.fract()).unwrap())
            };
            match (integer(a), integer(b)) {
                (Some(a), Some(b)) => Some(a.cmp(&b)),
                (Some(a), None) => Some(integer_float(a, b.as_f64()?)),
                (None, Some(b)) => Some(integer_float(b, a.as_f64()?).reverse()),
                (None, None) => a.as_f64()?.partial_cmp(&b.as_f64()?),
            }
        }
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

fn matches(row: &Value, filter: &Filter) -> bool {
    let Some(value) = row.pointer(&filter.path) else {
        return false;
    };
    let ordering = compare(value, &filter.value);
    let equal = value == &filter.value || ordering == Some(Ordering::Equal);
    match filter.op {
        Operator::Eq => equal,
        Operator::Ne => !equal,
        Operator::Gt => ordering == Some(Ordering::Greater),
        Operator::Ge => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
        Operator::Lt => ordering == Some(Ordering::Less),
        Operator::Le => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
        Operator::Contains => value
            .as_str()
            .zip(filter.value.as_str())
            .is_some_and(|(value, needle)| value.contains(needle)),
    }
}

/// Reversible column factoring. Only identical object shapes become tables:
/// absent fields must not be silently turned into null measurements.
fn compact(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let rows = items.iter().map(compact).collect::<Vec<_>>();
            table(&rows, None).unwrap_or(Value::Array(rows))
        }
        Value::Object(items) => {
            let values = items.values().map(compact).collect::<Vec<_>>();
            if let Some(table) = table(&values, Some(items.keys().cloned().collect())) {
                return table;
            }
            Value::Object(items.keys().cloned().zip(values).collect())
        }
        _ => value.clone(),
    }
}

fn table(rows: &[Value], keys: Option<Vec<String>>) -> Option<Value> {
    if rows.len() < 2 {
        return None;
    }
    let first = rows[0].as_object()?;
    if first.is_empty()
        || !rows.iter().all(|row| {
            row.as_object()
                .is_some_and(|row| row.keys().eq(first.keys()))
        })
    {
        return None;
    }
    let mut result = json!({
        "columns": first.keys().collect::<Vec<_>>(),
        "rows": rows.iter().map(|row| row.as_object().unwrap().values().collect::<Vec<_>>()).collect::<Vec<_>>(),
    });
    let original = if let Some(keys) = keys {
        let original = Value::Object(keys.iter().cloned().zip(rows.iter().cloned()).collect());
        result["keys"] = json!(keys);
        original
    } else {
        Value::Array(rows.to_vec())
    };
    (serialized_len(&result) < serialized_len(&original)).then_some(result)
}

fn reference(path: &str, value: &Value) -> Value {
    let (kind, count) = match value {
        Value::Object(fields) => ("object", fields.len()),
        Value::Array(items) => ("array", items.len()),
        Value::String(text) => ("string", text.chars().count()),
        _ => ("scalar", 1),
    };
    json!({ "$ref": path, "type": kind, "count": count })
}

/// The budget covers the actual JSON-RPC response, including legacy escaping.
/// Omitted values always point into the immutable, unformatted saved result.
pub(super) fn response(
    id: Value,
    result_id: &str,
    result: &Value,
    view: &View,
    budget: usize,
    modern: bool,
) -> Result<Value, String> {
    let target = result
        .pointer(&view.path)
        .ok_or_else(|| "view.path does not exist in the saved result".to_owned())?;
    let encode = |data: &Value, paging: &Value, omitted: bool| {
        let mut value = json!({
            "result_id": result_id,
            "path": view.path,
            "data": match view.format { Format::Table => compact(data), Format::Json => data.clone() },
        });
        if !paging.is_null() {
            value["page"] = paging.clone();
        }
        if omitted {
            value["omitted"] = json!(
                "Use query_result with this result_id and a $ref as view.path; paths address the saved JSON before table formatting. Narrow select or increase max_bytes if a row cannot fit."
            );
        }
        tool_success(id.clone(), value, modern)
    };

    let entries = if view.entries {
        Some(
            target
                .as_object()
                .ok_or("entries requires an object at view.path")?
                .iter()
                .map(|(key, value)| json!({ "key": key, "value": value }))
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    if let Some(items) = entries.as_ref().or_else(|| target.as_array()) {
        let mut rows = items
            .iter()
            .enumerate()
            .filter(|(_, row)| view.filter.iter().all(|filter| matches(row, filter)))
            .collect::<Vec<_>>();
        if let Some(path) = &view.sort_by {
            // A mixed-type order is ambiguous and can violate sort transitivity.
            let mut value_type = None;
            for (_, row) in &rows {
                let value = row.pointer(path).filter(|value| !value.is_null());
                if let Some(value) = value {
                    let kind = match value {
                        Value::Number(_) => 0,
                        Value::String(_) => 1,
                        Value::Bool(_) => 2,
                        _ => return Err("sort_by must select scalar values".into()),
                    };
                    if value_type
                        .replace(kind)
                        .is_some_and(|previous| previous != kind)
                    {
                        return Err("sort_by values must have a consistent type".into());
                    }
                }
            }
            rows.sort_by(|(_, a), (_, b)| {
                let a = a.pointer(path).filter(|v| !v.is_null());
                let b = b.pointer(path).filter(|v| !v.is_null());
                match (a, b) {
                    (Some(a), Some(b)) => {
                        let order = compare(a, b).unwrap_or(Ordering::Equal);
                        if view.descending {
                            order.reverse()
                        } else {
                            order
                        }
                    }
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    _ => Ordering::Equal,
                }
            });
        }
        let start = view.offset.min(rows.len());
        let stop = start.saturating_add(view.limit).min(rows.len());
        let mut data = rows[start..stop]
            .iter()
            .map(|(_, row)| project(row, &view.select))
            .collect::<Result<Vec<_>, _>>()?;
        loop {
            let paging = page(start, start + data.len(), rows.len());
            let response = encode(&json!(data), &paging, false);
            if serialized_len(&response) <= budget {
                return Ok(response);
            }
            if data.pop().is_none() {
                break;
            }
            if data.is_empty() && start < rows.len() {
                let (index, row) = rows[start];
                let key = if view.entries {
                    row["key"].as_str().unwrap().to_owned()
                } else {
                    index.to_string()
                };
                let original = if view.entries { &row["value"] } else { row };
                let data = reference(&pointer_child(&view.path, &key), original);
                let response = encode(&data, &page(start, start, rows.len()), true);
                if serialized_len(&response) <= budget {
                    return Ok(response);
                }
                break;
            }
        }
    } else {
        if !view.filter.is_empty() || view.sort_by.is_some() || view.offset != 0 {
            return Err("filter, sort_by and offset require an array at view.path".into());
        }
        let mut data = if view.path.is_empty() {
            project_friendly(target, &view.select)?
        } else {
            project(target, &view.select)?
        };
        let mut omitted = false;
        let mut replaced: Vec<String> = Vec::new();
        // ponytail: cap subtree replacements at 32; use entries for wider maps.
        for _ in 0..32 {
            let response = encode(&data, &Value::Null, omitted);
            if serialized_len(&response) <= budget {
                return Ok(response);
            }
            let largest = data.as_object().and_then(|fields| {
                fields
                    .iter()
                    .filter(|(key, _)| !replaced.contains(*key))
                    .max_by_key(|(_, value)| serialized_len(value))
                    .map(|(key, value)| (key.clone(), value.clone()))
            });
            let Some((key, value)) = largest else { break };
            let path = if view.select.is_empty() {
                pointer_child(&view.path, &key)
            } else {
                format!("{}{key}", view.path)
            };
            let reference = reference(&path, &value);
            if serialized_len(&reference) >= serialized_len(&value) {
                break;
            }
            data[&key] = reference;
            replaced.push(key);
            omitted = true;
        }
    }
    let response = encode(&reference(&view.path, target), &Value::Null, true);
    if serialized_len(&response) <= budget {
        Ok(response)
    } else {
        Err("response metadata exceeds max_bytes; shorten view paths or increase the budget".into())
    }
}

pub(super) fn schema() -> Value {
    json!({
        "type": "object",
        "description": "Select saved JSON before formatting. Filter/sort run before paging; select runs last. Paths are JSON Pointers, relative to each row for select/filter/sort. Tables factor repeated fields into columns/rows; keys identifies object-map rows.",
        "properties": {
            "path": {"type": "string", "default": ""},
            "select": {"type": "array", "items": {"type": "string"}, "maxItems": 32},
            "entries": {"type": "boolean", "default": false, "description": "View an object map as key/value rows, e.g. sort metric summaries by /value/mean."},
            "filter": {"type": "array", "maxItems": 8, "items": {
                "type": "object", "properties": {
                    "path": {"type": "string"},
                    "op": {"enum": ["eq", "ne", "gt", "ge", "lt", "le", "contains"]},
                    "value": {"type": ["string", "number", "boolean", "null"]}
                }, "required": ["path", "op", "value"], "additionalProperties": false
            }},
            "sort_by": {"type": "string"},
            "descending": {"type": "boolean", "default": true},
            "offset": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            "format": {"enum": ["table", "json"], "default": "table"}
        },
        "additionalProperties": false
    })
}

pub(super) fn add_schema(schema: &mut Value, detailed: bool) {
    // Describe the shared view language once in the catalog; runtime validation
    // is identical on every tool, including clients that do not check schemas.
    schema["properties"]["view"] = if detailed {
        self::schema()
    } else {
        json!({
            "type": "object", "description": "Optional query_result view (path, select, entries, filter, sort_by, descending, offset, limit, format); overrides the default preview."
        })
    };
    schema["properties"]["max_bytes"] = json!({
        "type": "integer", "minimum": 1024, "maximum": MAX_BYTES, "default": DEFAULT_BYTES,
        "description": "Budget for the entire JSON-RPC reply in UTF-8 bytes, including escaping. Omitted evidence remains available through result_id."
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(value: Value) -> (View, usize) {
        View::parse(value.as_object().unwrap()).unwrap()
    }

    fn payload(response: &Value, modern: bool) -> Value {
        if modern {
            response["result"]["structuredContent"].clone()
        } else {
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap()
        }
    }

    #[test]
    fn selection_filters_and_sorts_before_paging_without_rounding_or_filling_nulls() {
        let values = json!({ "items": [
            {"id": "small", "time": 9007199254740992_u64, "coverage": 100, "mean": 0},
            {"id": "large", "time": 9007199254740993_u64, "coverage": 100, "mean": null},
            {"id": "ignored", "time": u64::MAX, "coverage": 0, "mean": 1},
            {"id": "unavailable", "time": null, "coverage": 100, "mean": null}
        ]});
        let (view, budget) = options(json!({ "view": {
            "path": "/items", "filter": [{"path": "/coverage", "op": "ge", "value": 50}],
            "sort_by": "/time", "select": ["/id", "/mean"], "limit": 1, "format": "json"
        }}));
        let first = payload(
            &response(json!(1), "saved", &values, &view, budget, true).unwrap(),
            true,
        );
        assert_eq!(first["data"], json!([{ "/id": "large", "/mean": null }]));
        assert_eq!(first["page"]["total"], 3);
        assert_eq!(first["page"]["next_offset"], 1);
        assert_eq!(
            compare(&json!(9007199254740993_u64), &json!(9007199254740992_f64)),
            Some(Ordering::Greater)
        );
        assert_eq!(compare(&json!(-1), &json!(-1.5)), Some(Ordering::Greater));
        assert_eq!(
            compare(&json!(u64::MAX), &json!(1e100)),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare(&json!(i64::MIN), &json!(u64::MAX)),
            Some(Ordering::Less)
        );
        let mapped = json!({ "a": {"mean": null}, "b": {"mean": 0}, "c": {"mean": 10} });
        let (map_view, budget) = options(json!({"view": {
            "entries": true, "sort_by": "/value/mean", "select": ["/key", "/value/mean"],
            "limit": 1, "format": "json"
        }}));
        let top = payload(
            &response(json!(1), "saved", &mapped, &map_view, budget, true).unwrap(),
            true,
        );
        assert_eq!(top["data"], json!([{ "/key": "c", "/value/mean": 10 }]));
        assert_eq!(top["page"]["total"], 3);
        let missing = View {
            select: vec!["/missing".into()],
            ..view
        };
        assert!(
            response(json!(1), "saved", &values, &missing, budget, true)
                .unwrap_err()
                .contains("absent")
        );
        for invalid in [
            json!({"view": {"path": "items"}}),
            json!({"view": {"path": "/bad~2"}}),
            json!({"view": {"limit": 0}}),
            json!({"max_bytes": 1023}),
            json!({"view": {"typo": true}}),
            json!({"view": {"filter": [{"path": "/x", "op": "contains", "value": 1}]}}),
        ] {
            assert!(View::parse(invalid.as_object().unwrap()).is_err());
        }
    }

    #[test]
    fn byte_budget_pages_without_skips_and_retains_oversized_evidence() {
        let value = json!({ "escaped/key~": (0..100).map(|id| json!({
            "id": id, "label": "\"\\\n🦀".repeat(20), "precision": "bucket_shared", "mean": null
        })).collect::<Vec<_>>() });
        let mut store = ResultStore::default();
        let saved = store.insert(&value).unwrap();
        for modern in [true, false] {
            let (mut view, budget) = options(json!({ "max_bytes": 1024, "view": {
                "path": "/escaped~1key~0", "limit": 100, "format": "json"
            }}));
            let mut ids = Vec::new();
            loop {
                let reply = response(json!(1), &saved, &value, &view, budget, modern).unwrap();
                assert!(serialized_len(&reply) <= budget);
                let result = payload(&reply, modern);
                let rows = result["data"].as_array().unwrap();
                assert!(!rows.is_empty());
                ids.extend(rows.iter().map(|row| row["id"].as_u64().unwrap()));
                let Some(next) = result["page"]["next_offset"].as_u64() else {
                    break;
                };
                view.offset = next as usize;
            }
            assert_eq!(ids, (0..100).collect::<Vec<_>>());
            let (view, budget) = options(json!({ "max_bytes": 1024 }));
            let reply = response(json!(1), &saved, &value, &view, budget, modern).unwrap();
            assert!(serialized_len(&reply) <= budget);
            assert_eq!(
                payload(&reply, modern)["data"]["escaped/key~"]["$ref"],
                "/escaped~1key~0"
            );
        }
        assert_eq!(store.get(&saved).unwrap(), value);
        let huge = json!([{"label": "x".repeat(100_000), "mean": 0}]);
        let (view, budget) = options(json!({"max_bytes": 1024}));
        let reply = payload(
            &response(json!(1), "saved", &huge, &view, budget, true).unwrap(),
            true,
        );
        assert_eq!(reply["page"]["returned"], 0);
        assert_eq!(reply["page"]["next_offset"], 0);
        assert_eq!(reply["data"]["$ref"], "/0");
    }

    #[test]
    fn tables_preserve_shapes_nulls_and_exact_numbers() {
        let values = json!(
            (0..40)
                .map(|i| json!({
                    "timestamp_ns": u64::MAX - i, "coverage_pct": 100, "mean": null,
                    "precision": "bucket_shared", "warnings": ["whole bucket only"]
                }))
                .collect::<Vec<_>>()
        );
        let table = compact(&values);
        let columns = table["columns"].as_array().unwrap();
        let restored = table["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                Value::Object(
                    columns
                        .iter()
                        .zip(row.as_array().unwrap())
                        .map(|(key, value)| (key.as_str().unwrap().to_owned(), value.clone()))
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(json!(restored), values);
        assert!(serialized_len(&table) < serialized_len(&values) * 2 / 3);
        let heterogeneous = json!([{"mean": null}, {}]);
        assert_eq!(compact(&heterogeneous), heterogeneous);
        let mapped = json!({"a": values[0], "b": values[1], "c": values[2]});
        assert_eq!(compact(&mapped)["keys"], json!(["a", "b", "c"]));
    }

    #[test]
    fn result_store_deduplicates_bounds_storage_and_expires_without_aliasing() {
        let mut store = ResultStore::new(None);
        let first = store.insert(&json!({"capture": "a"})).unwrap();
        assert_eq!(first, store.insert(&json!({"capture": "a"})).unwrap());
        assert_eq!(store.entries.len(), 1);
        for i in 0..STORE_COUNT {
            store.insert(&json!({"capture": i})).unwrap();
        }
        assert_eq!(store.entries.len(), STORE_COUNT);
        assert!(store.get(&first).unwrap_err().contains("expired"));
        assert_eq!(
            store.bytes,
            store
                .entries
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>()
        );
        assert!(store.insert(&json!("x".repeat(RESULT_BYTES))).is_err());
        assert!(ResultStore::new(None).get(&first).is_err());
        assert_eq!(first, store.insert(&json!({"capture": "a"})).unwrap());

        let directory = tempfile::tempdir().unwrap();
        let mut persistent = ResultStore::new(Some(directory.path().to_path_buf()));
        let id = persistent.insert(&json!({"persisted": true})).unwrap();
        let reader = ResultStore::new(Some(directory.path().to_path_buf()));
        assert_eq!(reader.get(&id).unwrap(), json!({"persisted": true}));
    }

    #[test]
    fn repeated_metric_followups_have_a_measured_context_budget() {
        // Synthetic workload: 8 scoped evaluations, 24 metric summaries each.
        // Compare the old complete replies with one preview and 8 selected views.
        let report = json!({ "results": (0..8).map(|scope| json!({
            "scope": { "id": format!("debug:{scope}"), "precision": "bucket_shared", "warnings": [] },
            "summary": (0..24).map(|metric| (format!("unit__metric_{metric:02}.avg.pct_of_peak_sustained_elapsed"), json!({
                "valid_samples": 100, "selected_samples": 100, "coverage_pct": 100.0,
                "mean": 70.0, "min": 20.0, "max": 90.0, "p50": 65.0, "p95": 85.0,
                "sum": 7000.0, "min_range_index": 12, "max_range_index": 90
            }))).collect::<Map<_, _>>()
        })).collect::<Vec<_>>() });
        let mut store = ResultStore::default();
        let saved = store.insert(&report).unwrap();
        for modern in [true, false] {
            let baseline = serialized_len(&tool_success(json!(1), report.clone(), modern));
            let preview_view = View {
                path: "/results".into(),
                ..View::default()
            };
            let preview = response(
                json!(1),
                &saved,
                &report,
                &preview_view,
                DEFAULT_BYTES,
                modern,
            )
            .unwrap();
            let mut total = serialized_len(&preview);
            for scope in 0..8 {
                let (view, budget) = options(json!({ "view": {
                    "path": format!("/results/{scope}"),
                    "select": ["/scope", "/summary/unit__metric_00.avg.pct_of_peak_sustained_elapsed"]
                }}));
                let reply = response(json!(1), &saved, &report, &view, budget, modern).unwrap();
                let result = payload(&reply, modern);
                assert!(result.get("omitted").is_none());
                assert_eq!(result["data"]["/scope"]["precision"], "bucket_shared");
                total += serialized_len(&reply);
            }
            eprintln!(
                "synthetic metric workflow modern={modern}: complete replies={baseline} bytes, preview + 8 selected replies={total} bytes"
            );
            assert!(total < baseline / 2);
        }
    }
}
