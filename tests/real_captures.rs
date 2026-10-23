//! Integration evidence over real `.ngfx-gputrace` files.
//!
//! These tests are ignored by default because captures and the matching Nsight
//! installation are environment-specific. They are not smoke tests: each one
//! asserts invariants that synthetic fixtures cannot exercise, including real
//! metric evaluation, timing-bucket validity, shader/cubin decode, SASS stats,
//! and side-by-side comparison.
//!
//! Run with:
//! `NGFX_TEST_CAPTURE_DIR=/path/to/captures cargo test --test real_captures -- --ignored --nocapture`

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use nsight_gpu_trace::{
    Analysis, AnalysisOptions, CompareOptions, McpServer, ScopeKind, TimelineOptions,
    TraceDocument, compare_captures, disassemble,
    shader::{BUILTIN_KEYSTREAM, BlobKind, ShaderCatalog, recover_keystream},
};
use serde_json::json;

fn capture_paths() -> Vec<PathBuf> {
    if let Ok(list) = env::var("NGFX_TEST_CAPTURES") {
        return list
            .split([',', ':'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    let directory = env::var("NGFX_TEST_CAPTURE_DIR").unwrap_or_else(|_| {
        panic!(
            "set NGFX_TEST_CAPTURE_DIR to a directory of .ngfx-gputrace files, or NGFX_TEST_CAPTURES to a list"
        )
    });
    let mut paths: Vec<_> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("cannot read {directory}: {error}"))
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "ngfx-gputrace")
        })
        .collect();
    paths.sort();
    paths
}

fn open(path: &Path) -> Analysis {
    Analysis::open(path, AnalysisOptions::default())
        .unwrap_or_else(|error| panic!("cannot open {}: {error}", path.display()))
}

#[test]
#[ignore = "requires real .ngfx-gputrace captures and a matching Nsight installation"]
fn real_capture_evidence_is_consistent() {
    let paths = capture_paths();
    assert!(!paths.is_empty(), "no captures were found");
    let mut checked_metrics = 0usize;
    let mut checked_shaders = 0usize;
    let mut checked_actions = 0usize;
    let mut workload_evidence = false;

    for path in &paths {
        let mut analysis = open(path);
        assert!(
            !analysis.calls().is_empty(),
            "{} has no indexed API calls",
            path.display()
        );
        assert!(
            !analysis.timing_buckets().is_empty(),
            "{} has no timing buckets",
            path.display()
        );
        for bucket in analysis.timing_buckets() {
            if let Some((start, end)) = bucket.interval() {
                assert!(
                    start > 0,
                    "{} bucket {} has a zero start",
                    path.display(),
                    bucket.index
                );
                assert!(
                    end > start,
                    "{} bucket {} has a non-increasing interval",
                    path.display(),
                    bucket.index
                );
                assert_eq!(
                    end - start,
                    bucket
                        .stages
                        .iter()
                        .find(|stage| stage.stage == "PB_PIPELINE_STAGE_BOTTOM_OF_PIPE")
                        .or_else(|| bucket.stages.first())
                        .unwrap()
                        .duration_ns
                );
            }
        }

        let quality = analysis.quality().expect("quality evidence");
        assert_ne!(
            quality.status,
            nsight_gpu_trace::QualityStatus::Unknown,
            "{} produced no quality checks",
            path.display()
        );

        let timeline = analysis.timeline(TimelineOptions { min_gap_ns: 1_000 });
        if let Some(duration) = timeline.duration_ns {
            assert!(
                duration > 0,
                "{} has a zero timeline duration",
                path.display()
            );
        }
        assert!(
            !timeline.lanes.is_empty(),
            "{} has no timeline lanes",
            path.display()
        );
        assert!(
            timeline.parallelism.is_some_and(|value| value >= 1.0),
            "{} has impossible stream parallelism",
            path.display()
        );
        for lane in &timeline.lanes {
            assert_eq!(
                lane.gap_ns,
                lane.last_ns
                    .saturating_sub(lane.first_ns)
                    .saturating_sub(lane.busy_ns)
            );
        }

        let states = analysis.action_states();
        if analysis.calls().iter().any(|call| {
            matches!(
                call.kind,
                nsight_gpu_trace::CallKind::Draw | nsight_gpu_trace::CallKind::Dispatch
            )
        }) {
            assert!(
                !states.is_empty(),
                "{} has draw/dispatch calls but no action state",
                path.display()
            );
            workload_evidence |= states.iter().any(|state| !state.workload.is_empty());
            for state in &states {
                for barrier in &state.barrier_events {
                    assert!(
                        barrier.barrier_objects > 0,
                        "{} barrier event has no parsed barrier object",
                        path.display()
                    );
                    assert!(
                        barrier.src_stage.is_some() || barrier.dst_stage.is_some(),
                        "{} barrier event has no stage masks",
                        path.display()
                    );
                }
            }
            checked_actions += states.len();
        }

        if quality.counters.available {
            let scan = analysis.scan_all_metrics().expect("complete metric scan");
            assert!(
                scan.selected_samples > 0,
                "{} has no metric samples",
                path.display()
            );
            assert!(
                scan.timestamped_samples > 0,
                "{} has no timestamped metric samples",
                path.display()
            );
            assert!(
                scan.sample_duration_ns > 0,
                "{} has a zero metric window",
                path.display()
            );
            assert!(
                scan.metrics.iter().any(|metric| metric.valid_samples > 0),
                "{} collected no evaluable metrics",
                path.display()
            );
            for metric in scan
                .metrics
                .iter()
                .filter(|metric| metric.valid_samples > 0)
            {
                if let (Some(mean), Some(p95)) = (metric.time_weighted_mean, metric.p95) {
                    assert!(mean.is_finite() && p95.is_finite());
                }
                if let Some(ratio) = metric.burst_ratio {
                    assert!(ratio.is_finite() && ratio >= 0.0);
                }
                checked_metrics += 1;
            }
        }

        let catalog = analysis.shader_catalog().expect("shader catalog");
        for device in &catalog.devices {
            for shader in &device.shaders {
                if let Some(occupancy) = &shader.occupancy {
                    assert!(occupancy.estimated_occupancy_pct.is_some());
                }
                if shader.cubin_sha256.is_some() {
                    checked_shaders += 1;
                }
            }
        }
        if let Some(shader) = catalog.shaders().next() {
            let cubin = catalog
                .cubin(shader.device_index, shader.index)
                .expect("decoded cubin");
            let disassembly = disassemble(&cubin, None).expect("nvdisasm");
            assert!(
                disassembly.stats.instruction_count > 0,
                "{} shader {} produced no structured SASS",
                path.display(),
                shader.index
            );
            assert_eq!(disassembly.stats_source, "nvdisasm_json");
            assert_eq!(
                disassembly.stats.instruction_count,
                disassembly
                    .stats
                    .functions
                    .iter()
                    .map(|function| function.instruction_count)
                    .sum::<usize>()
            );
            assert!(
                disassembly.stats.source_line_count > 0,
                "{} shader {} has no SASS source-line mapping",
                path.display(),
                shader.index
            );
            assert!(
                disassembly
                    .stats
                    .source_lines
                    .iter()
                    .any(|line| line.instruction_count > 0)
            );
        }
    }

    assert!(checked_metrics > 0, "no real metric evidence was checked");
    assert!(
        checked_shaders > 0,
        "no real shader/cubin evidence was checked"
    );
    assert!(checked_actions > 0, "no real action state was checked");
    assert!(
        workload_evidence,
        "no capture produced draw/dispatch workload evidence"
    );
}

#[test]
#[ignore = "requires at least two comparable .ngfx-gputrace captures"]
fn real_captures_compare_with_evidence() {
    let paths = capture_paths();
    assert!(paths.len() >= 2, "comparison needs at least two captures");
    let mut baseline = open(&paths[0]);
    let mut candidate = open(&paths[1]);
    let options = CompareOptions {
        top: 20,
        scope_kind: None,
        scope_pattern: None,
        include_shaders: true,
        scope_metrics: Vec::new(),
    };
    let comparison =
        compare_captures(&mut baseline, &mut candidate, &options).expect("capture comparison");
    assert!(
        comparison
            .metric_summary
            .get("common_metrics")
            .copied()
            .unwrap_or(0)
            > 0,
        "the captures share no metrics"
    );
    assert!(
        !comparison.metrics.is_empty(),
        "the comparison returned no metric deltas"
    );
    for metric in &comparison.metrics {
        assert!(metric.baseline.valid_samples > 0);
        assert!(metric.candidate.valid_samples > 0);
        if let Some((low, high)) = metric.mean_delta_ci95 {
            assert!(low <= high, "reversed confidence interval");
            assert!(metric.bootstrap_iterations > 0);
        }
    }
    assert!(
        comparison.scope_kind.is_some(),
        "no scope family was selected"
    );
    assert!(
        !comparison.scopes.is_empty(),
        "no matched scopes were compared"
    );
    for scope in &comparison.scopes {
        assert!(
            scope.duration_delta_ns.is_some(),
            "scope {} had no duration delta",
            scope.label
        );
    }
    let has_shader_records = baseline
        .shader_catalog()
        .map(|catalog| catalog.shaders().count())
        .unwrap_or(0)
        > 0
        && candidate
            .shader_catalog()
            .map(|catalog| catalog.shaders().count())
            .unwrap_or(0)
            > 0;
    if has_shader_records {
        assert!(
            !comparison.shaders.is_empty(),
            "captures contain shaders but the comparison returned none"
        );
    }
    assert!(
        matches!(
            comparison.scope_kind,
            Some(
                ScopeKind::DebugGroup
                    | ScopeKind::Frame
                    | ScopeKind::TimingBucket
                    | ScopeKind::NvtxRange
                    | ScopeKind::Action
            )
        ),
        "unexpected scope family"
    );
}

#[test]
#[ignore = "requires real .ngfx-gputrace captures and a matching Nsight installation"]
fn real_mcp_surface_returns_quality_and_comparison_evidence() {
    let paths = capture_paths();
    assert!(
        paths.len() >= 2,
        "MCP comparison needs at least two captures"
    );
    let server = McpServer::new(AnalysisOptions::default());
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2025-06-18" }
    });
    assert!(server.handle(&initialize).is_some());

    let analyze = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "analyze_capture",
            "arguments": {
                "capture": paths[0].display().to_string(),
                "top": 3,
                "max_bytes": 65536,
                "view": {
                    "format": "json",
                    "select": [
                        "/quality/status",
                        "/quality/environment/gpu",
                        "/timeline/frame_summary",
                        "/timeline/parallelism",
                        "/diagnostics/activity",
                        "/regions/items",
                        "/representative_metrics/names"
                    ]
                }
            }
        }
    });
    let response = server.handle(&analyze).expect("analyze response");
    let payload = response["result"]["content"][0]["text"]
        .as_str()
        .map(|text| serde_json::from_str::<serde_json::Value>(text).unwrap())
        .unwrap_or_else(|| response["result"]["structuredContent"].clone());
    assert!(payload["result_id"].is_string());
    assert!(
        matches!(
            payload["data"]["status"].as_str().unwrap_or(""),
            "pass" | "warn"
        ),
        "unexpected quality status: {payload}"
    );
    assert!(
        payload["data"]["parallelism"]
            .as_f64()
            .is_some_and(|value| value >= 1.0)
    );
    assert_eq!(
        payload["data"]["frame_summary"]["count"]
            .as_u64()
            .unwrap_or(0),
        1
    );
    let regions = payload["data"]["items"].as_array().unwrap();
    assert!(!regions.is_empty());
    assert!(
        regions[0]["selection"]["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    let scope_id = regions[0]["scope_id"].as_str().unwrap().to_owned();
    let metric = payload["data"]["names"]
        .as_array()
        .unwrap()
        .first()
        .and_then(|value| value.as_str())
        .unwrap()
        .to_owned();

    let evidence = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "query_capture",
            "arguments": {
                "capture": paths[0].display().to_string(),
                "queries": [
                    { "type": "scope_evidence", "scope": scope_id, "metrics": [metric.clone()], "action_limit": 2 },
                    { "type": "frame_series", "metrics": [metric], "limit": 2 }
                ],
                "max_bytes": 65536,
                "view": { "format": "json", "path": "/results" }
            }
        }
    });
    let response = server.handle(&evidence).expect("evidence response");
    let payload = response["result"]["content"][0]["text"]
        .as_str()
        .map(|text| serde_json::from_str::<serde_json::Value>(text).unwrap())
        .unwrap_or_else(|| response["result"]["structuredContent"].clone());
    let results = payload["data"].as_array().expect("batch results");
    assert_eq!(results.len(), 2);
    let scope_evidence = &results[0]["data"];
    assert!(scope_evidence["scope"]["id"].is_string());
    assert!(scope_evidence["metrics"]["summary"].is_object());
    assert!(scope_evidence["actions"].is_array());
    let frame_series = &results[1]["data"];
    assert!(frame_series["frames"]["items"].is_array());

    let compare = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "compare_captures",
            "arguments": {
                "baseline": paths[0].display().to_string(),
                "candidate": paths[1].display().to_string(),
                "top": 8,
                "max_bytes": 65536,
                "view": {
                    "format": "json",
                    "select": ["/comparability", "/metric_summary", "/metrics", "/scopes"]
                }
            }
        }
    });
    let response = server.handle(&compare).expect("compare response");
    assert!(
        !response["result"]["isError"].as_bool().unwrap_or(false),
        "compare tool returned an error: {response}"
    );
    let payload = response["result"]["content"][0]["text"]
        .as_str()
        .map(|text| serde_json::from_str::<serde_json::Value>(text).unwrap())
        .unwrap_or_else(|| response["result"]["structuredContent"].clone());
    assert!(
        payload["data"]["metric_summary"]["common_metrics"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert!(!payload["data"]["metrics"].as_array().unwrap().is_empty());
    assert!(!payload["data"]["scopes"].as_array().unwrap().is_empty());
}

#[test]
#[ignore = "requires real captures with Shader Profiler blobs"]
fn real_shader_keystream_is_static_across_captures() {
    let paths = capture_paths();
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut audited = 0usize;
    let mut keys = Vec::new();
    for path in &paths {
        let document = TraceDocument::open(path, None)
            .unwrap_or_else(|error| panic!("cannot open {}: {error}", path.display()));
        let catalog = ShaderCatalog::open(&document, BUILTIN_KEYSTREAM, "builtin")
            .unwrap_or_else(|error| panic!("cannot decode {}: {error}", path.display()));
        let simple = catalog
            .devices
            .iter()
            .flat_map(|device| &device.blobs)
            .filter(|blob| blob.obfuscation == "simple")
            .count();
        if simple == 0 {
            continue;
        }
        assert_eq!(
            catalog
                .devices
                .iter()
                .flat_map(|device| &device.blobs)
                .filter(|blob| blob.obfuscation == "simple" && blob.error.is_some())
                .count(),
            0,
            "{} did not decode with the built-in stream",
            path.display()
        );
        let mut spirv = None;
        for device in &catalog.devices {
            for blob in &device.blobs {
                if blob.kind != BlobKind::Spirv {
                    continue;
                }
                if let Ok(decoded) = catalog
                    .blob(device.device_index, blob.index)
                    .and_then(|blob| blob.decoded())
                    && decoded.starts_with(&[0x03, 0x02, 0x23, 0x07])
                {
                    spirv = Some(decoded.to_vec());
                    break;
                }
            }
            if spirv.is_some() {
                break;
            }
        }
        let Some(spirv) = spirv else {
            panic!(
                "{} has shader blobs but no decoded SPIR-V plaintext",
                path.display()
            );
        };
        let plaintext = directory.path().join(format!("known-{audited}.spv"));
        fs::write(&plaintext, &spirv).expect("write known plaintext");
        let (key, label) = recover_keystream(&document, &plaintext)
            .unwrap_or_else(|error| panic!("cannot recover {}: {error}", path.display()));
        let common = key.len().min(BUILTIN_KEYSTREAM.len());
        assert_eq!(
            key[..common],
            BUILTIN_KEYSTREAM[..common],
            "{} recovered a different stream ({label})",
            path.display()
        );
        let recovered = ShaderCatalog::open(&document, &key, "recovered")
            .unwrap_or_else(|error| panic!("cannot re-decode {}: {error}", path.display()));
        assert_eq!(
            recovered
                .devices
                .iter()
                .flat_map(|device| &device.blobs)
                .filter(|blob| blob.obfuscation == "simple" && blob.error.is_some())
                .count(),
            0,
            "{} failed re-decode with its own recovered stream",
            path.display()
        );
        keys.push(key);
        audited += 1;
    }
    assert!(audited > 0, "no capture contained shader blobs");
    let first = keys.first().unwrap();
    for key in &keys {
        let common = key.len().min(first.len());
        assert_eq!(
            key[..common],
            first[..common],
            "captures recovered different keystream prefixes"
        );
    }
}
