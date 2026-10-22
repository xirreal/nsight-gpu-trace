//! Reusable access to NVIDIA Nsight Graphics GPU Trace (`.ngfx-gputrace`) files.
//!
//! The crate has five layers:
//! - [`container`] validates and decompresses the WRPV v10 container.
//! - [`trace`] decodes every protobuf field with descriptors from Nsight's
//!   installed WarpViz plugin binary.
//! - [`perfworks`] discovers and evaluates arbitrary metrics from the embedded
//!   PerfWorks counter-data image.
//! - [`analysis`] indexes calls, timestamps, frames, markers, and exact scopes.
//! - [`diagnostics`] builds optional heuristic views over complete metric scans.
//! - [`shader_profiler`] decodes shader profiler blobs, SPIR-V modules, and
//!   cubin line tables.
//! - [`pc_sampling`] decodes real-time shader profiler PC samples and
//!   attributes them to shaders, SASS, SPIR-V, and source lines.
//!
//! Raw container, protobuf, and metric APIs remain public; higher-level views
//! never replace unavailable values with zero or hide timing ambiguity.

pub mod analysis;
pub mod container;
pub mod diagnostics;
mod error;
pub mod mcp;
pub mod pc_sampling;
pub mod perfworks;
mod sass_classes;
pub mod shader_profiler;
mod spirv_opcodes;
pub mod trace;

pub use analysis::{
    Analysis, AnalysisOptions, ApiCall, CallKind, DebugGroup, Frame, MetricStatistic,
    MetricStatistics, NvtxRange, RankedScope, Scope, ScopeKind, ScopeMetricAggregation,
    ScopeMetricSummary, ScopeRanking, ScopedMetrics, TimestampBoundary, TimingBucket,
};
pub use container::{Chunk, Container, Section, SectionRole};
pub use diagnostics::{
    DiagnosticFinding, DiagnosticSeverity, MetricCategorySummary, TopDownReport, top_down_report,
};
pub use error::{Error, Result};
pub use mcp::McpServer;
pub use pc_sampling::{
    Hotspot, HotspotGrouping, HotspotReport, PcSample, PcSampling, PcSamplingSummary, SampleKind,
    SampleRecord, SampleType, TpcCounterRange, WarpWeightedCount, WarpWeightedSummary,
};
pub use perfworks::{
    CounterImage, CounterImageInfo, MetricAvailability, MetricBase, MetricCatalog,
    MetricDescriptor, MetricEvaluation, MetricKind, MetricSample, MetricScan, MetricsApi,
    PerfWorks, SampleInfo,
};
pub use shader_profiler::{
    CodeBlock, InstructionClass, ShaderModule, ShaderProfile, SpirvModule, classify_sass,
};
pub use trace::{ByteField, QueryOptions, SchemaField, TraceDocument};
