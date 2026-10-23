//! Lightweight per-action state evidence.
//!
//! This reconstructs observed binds, barriers, and state-change counts between
//! actions from the captured API calls. It is not a full API state tracker and
//! does not infer pipeline semantics that the capture does not contain.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{Analysis, ApiCall, CallKind};

#[derive(Debug, Clone, Serialize)]
pub struct BoundObject {
    pub role: String,
    pub name: String,
    pub handle: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BarrierEvidence {
    pub global_index: usize,
    pub call: String,
    pub src_stage: Option<String>,
    pub dst_stage: Option<String>,
    pub src_access: Option<String>,
    pub dst_access: Option<String>,
    pub barrier_objects: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionState {
    pub global_index: usize,
    pub device_index: usize,
    pub queue_index: usize,
    pub stream_index: usize,
    pub call_index: usize,
    pub name: String,
    pub kind: CallKind,
    pub bound_pipeline: Option<String>,
    pub bound_shaders: Vec<String>,
    pub bound_descriptor_sets: Vec<String>,
    pub bindings: Vec<BoundObject>,
    pub workload: BTreeMap<String, u64>,
    pub barriers_since_previous: usize,
    pub barrier_events: Vec<BarrierEvidence>,
    pub binding_events_since_previous: usize,
    pub state_changes_since_previous: usize,
}

#[derive(Debug, Default)]
struct StreamState {
    pipeline: Option<String>,
    shaders: BTreeSet<String>,
    descriptor_sets: BTreeSet<String>,
    bindings: Vec<BoundObject>,
    barriers: usize,
    barrier_events: Vec<BarrierEvidence>,
    binding_events: usize,
}

impl Analysis {
    /// Return observed state for every draw/dispatch/copy/clear/present call.
    /// Bindings and barrier counts are the events since the previous action on
    /// the same command stream.
    pub fn action_states(&self) -> Vec<ActionState> {
        let mut streams: BTreeMap<(usize, usize, usize), StreamState> = BTreeMap::new();
        let mut result = Vec::new();
        for call in self.calls() {
            let state = streams
                .entry((call.device_index, call.queue_index, call.stream_index))
                .or_default();
            if is_action(call.kind) {
                result.push(snapshot(call, state));
                state.barriers = 0;
                state.barrier_events.clear();
                state.binding_events = 0;
                state.bindings.clear();
                continue;
            }
            let lower = call.name.to_ascii_lowercase();
            if is_barrier(&lower) {
                state.barriers += 1;
                state.barrier_events.push(barrier_evidence(call));
                if state.barrier_events.len() > 8 {
                    state.barrier_events.remove(0);
                }
                continue;
            }
            if !is_binding(&lower) {
                continue;
            }
            state.binding_events += 1;
            let handles = extract_handles(&call.arguments);
            if is_pipeline_bind(&lower) {
                if let Some(handle) = handles.last() {
                    state.pipeline = Some(handle.clone());
                    state.bindings.push(BoundObject {
                        role: "pipeline".into(),
                        name: call.name.clone(),
                        handle: handle.clone(),
                    });
                }
            } else if is_shader_bind(&lower) {
                for handle in handles {
                    state.shaders.insert(handle.clone());
                    state.bindings.push(BoundObject {
                        role: "shader".into(),
                        name: call.name.clone(),
                        handle,
                    });
                }
            } else if is_descriptor_bind(&lower) {
                for handle in handles {
                    state.descriptor_sets.insert(handle.clone());
                    state.bindings.push(BoundObject {
                        role: "descriptor_set".into(),
                        name: call.name.clone(),
                        handle,
                    });
                }
            } else {
                for handle in handles {
                    state.bindings.push(BoundObject {
                        role: "binding".into(),
                        name: call.name.clone(),
                        handle,
                    });
                }
            }
        }
        result
    }
}

fn is_action(kind: CallKind) -> bool {
    matches!(
        kind,
        CallKind::Draw | CallKind::Dispatch | CallKind::Copy | CallKind::Clear | CallKind::Present
    )
}

fn is_barrier(name: &str) -> bool {
    name.contains("barrier") || name.contains("memorybarrier") || name == "glfence"
}

fn is_binding(name: &str) -> bool {
    name.contains("bind")
        || name.contains("attach")
        || name.contains("useprogram")
        || name.contains("use_program")
        || name.contains("setpipeline")
        || name.contains("set_pipeline")
}

fn is_pipeline_bind(name: &str) -> bool {
    name.contains("bindpipeline")
        || name.contains("use_program")
        || name.contains("useprogram")
        || name.contains("bindprogram")
        || name.contains("bind_program")
        || name.contains("setpipeline")
}

fn is_shader_bind(name: &str) -> bool {
    name.contains("bindshader") || name.contains("attachshader") || name.contains("shaderobjects")
}

fn is_descriptor_bind(name: &str) -> bool {
    name.contains("descriptorset")
        || name.contains("descriptor_set")
        || name.contains("binddescriptor")
}

fn snapshot(call: &ApiCall, state: &StreamState) -> ActionState {
    ActionState {
        global_index: call.global_index,
        device_index: call.device_index,
        queue_index: call.queue_index,
        stream_index: call.stream_index,
        call_index: call.call_index,
        name: call.name.clone(),
        kind: call.kind,
        bound_pipeline: state.pipeline.clone(),
        bound_shaders: state.shaders.iter().cloned().collect(),
        bound_descriptor_sets: state.descriptor_sets.iter().cloned().collect(),
        bindings: state.bindings.clone(),
        workload: workload(call),
        barriers_since_previous: state.barriers,
        barrier_events: state.barrier_events.clone(),
        binding_events_since_previous: state.binding_events,
        state_changes_since_previous: state.barriers + state.binding_events,
    }
}

fn workload(call: &ApiCall) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::new();
    for argument in &call.arguments {
        collect_workload(argument, &mut result);
    }
    result
}

fn collect_workload(value: &serde_json::Value, output: &mut BTreeMap<String, u64>) {
    match value {
        serde_json::Value::Object(object) => {
            if let (Some(name), Some(value)) = (
                object.get("name").and_then(serde_json::Value::as_str),
                numeric_value(object),
            ) && workload_key(name)
            {
                output.entry(name.to_ascii_lowercase()).or_insert(value);
            }
            for value in object.values() {
                collect_workload(value, output);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_workload(value, output);
            }
        }
        _ => {}
    }
}

fn numeric_value(object: &serde_json::Map<String, serde_json::Value>) -> Option<u64> {
    for field in ["uint32Value", "int32Value", "uint64Value", "int64Value"] {
        if let Some(value) = object.get(field) {
            if let Some(value) = value.get("value").and_then(serde_json::Value::as_u64) {
                return Some(value);
            }
            if let Some(value) = value.get("value").and_then(serde_json::Value::as_str)
                && let Ok(value) = value.parse()
            {
                return Some(value);
            }
        }
    }
    None
}

fn workload_key(name: &str) -> bool {
    matches!(
        name,
        "indexCount"
            | "vertexCount"
            | "instanceCount"
            | "groupCountX"
            | "groupCountY"
            | "groupCountZ"
            | "width"
            | "height"
            | "depth"
            | "layerCount"
            | "sampleCount"
            | "count"
            | "first"
            | "mode"
            | "indices"
            | "numIndices"
            | "baseVertex"
            | "baseInstance"
    )
}

fn barrier_evidence(call: &ApiCall) -> BarrierEvidence {
    let mut evidence = BarrierEvidence {
        global_index: call.global_index,
        call: call.name.clone(),
        src_stage: None,
        dst_stage: None,
        src_access: None,
        dst_access: None,
        barrier_objects: 0,
    };
    for argument in &call.arguments {
        collect_barrier(argument, &mut evidence);
    }
    evidence
}

fn collect_barrier(value: &serde_json::Value, evidence: &mut BarrierEvidence) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(name) = object.get("name").and_then(serde_json::Value::as_str) {
                let text = object_text(object);
                match name {
                    "srcStageMask" => {
                        evidence.barrier_objects += 1;
                        evidence.src_stage = evidence.src_stage.take().or(text);
                    }
                    "dstStageMask" => {
                        evidence.dst_stage = evidence.dst_stage.take().or(text);
                    }
                    "srcAccessMask" => {
                        evidence.src_access = evidence.src_access.take().or(text);
                    }
                    "dstAccessMask" => {
                        evidence.dst_access = evidence.dst_access.take().or(text);
                    }
                    _ => {}
                }
            }
            for value in object.values() {
                collect_barrier(value, evidence);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_barrier(value, evidence);
            }
        }
        _ => {}
    }
}

fn object_text(object: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    for field in ["uint64Value", "uint32Value", "int32Value", "int64Value"] {
        if let Some(inner) = object.get(field)
            && let Some(text) = scalar_text(inner)
        {
            return Some(text);
        }
    }
    None
}

fn scalar_text(value: &serde_json::Value) -> Option<String> {
    value
        .get("displayString")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            value.get("value").and_then(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_u64().map(|value| value.to_string()))
            })
        })
}

fn extract_handles(values: &[serde_json::Value]) -> Vec<String> {
    let mut handles = Vec::new();
    for value in values {
        collect_handles(value, &mut handles);
    }
    handles.truncate(64);
    handles
}

fn collect_handles(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(handle) = object
                .get("handleValue")
                .and_then(|value| value.get("handle"))
                .and_then(serde_json::Value::as_str)
                && !handle.is_empty()
                && handle != "0"
                && handle != "VK_NULL_HANDLE"
                && handle != "0x0000000000000000"
            {
                output.push(handle.to_owned());
            }
            for value in object.values() {
                collect_handles(value, output);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_handles(value, output);
            }
        }
        _ => {}
    }
}
