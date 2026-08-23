//! Dynamic bindings for the PerfWorks host evaluator shipped with Nsight.
//!
//! This module does not link to or redistribute NVIDIA code. Callers provide a
//! matching PerfWorks host library, which is loaded at runtime.

use std::{
    collections::BTreeMap,
    env,
    ffi::{CStr, CString, c_char, c_void},
    fs::File,
    io::{Seek, SeekFrom, Write},
    mem::{offset_of, size_of},
    path::{Path, PathBuf},
    ptr,
};

use libloading::{Library, Symbol};
use memmap2::{MmapMut, MmapOptions};
use serde::Serialize;

use crate::{
    Error, Result,
    container::{Container, SectionRole},
    trace::{find_named_file, nsight_search_roots},
};

#[cfg(not(target_os = "windows"))]
const NVPERF_FILENAME: &str = "libnvperf_grfx_host.so";
#[cfg(target_os = "windows")]
const NVPERF_FILENAME: &str = "nvperf_grfx_host.dll";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricsApi {
    D3d12,
    Vulkan,
    OpenGl,
    Device,
    Egl,
    VulkanSc,
    Cuda,
}

impl MetricsApi {
    pub fn from_trace_name(value: &str) -> Option<Self> {
        match value {
            "PB_API_D3D12" => Some(Self::D3d12),
            "PB_API_VULKAN" => Some(Self::Vulkan),
            "PB_API_OPENGL" => Some(Self::OpenGl),
            "PB_API_DEVICE" => Some(Self::Device),
            "PB_API_OPENGLES" => Some(Self::Egl),
            "PB_API_VULKANSC" => Some(Self::VulkanSc),
            "PB_API_CUDA" => Some(Self::Cuda),
            _ => None,
        }
    }

    fn evaluator_prefix(self) -> &'static str {
        match self {
            Self::D3d12 => "D3D12",
            Self::Vulkan => "VK",
            Self::OpenGl => "OpenGL",
            Self::Device => "Device",
            Self::Egl => "EGL",
            Self::VulkanSc => "VKSC",
            Self::Cuda => "CUDA",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Counter,
    Ratio,
    Throughput,
}

impl MetricKind {
    fn from_raw(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Counter),
            1 => Ok(Self::Ratio),
            2 => Ok(Self::Throughput),
            _ => Err(Error::PerfWorks(format!("unknown metric type {value}"))),
        }
    }

    fn raw(self) -> u8 {
        match self {
            Self::Counter => 0,
            Self::Ratio => 1,
            Self::Throughput => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricBase {
    pub name: String,
    pub kind: MetricKind,
    pub index: usize,
}

impl MetricBase {
    /// A representative, directly evaluable form suitable for checking
    /// whether this metric base was collected in a counter image.
    pub fn canonical_evaluation_name(&self) -> String {
        match self.kind {
            MetricKind::Counter => format!("{}.avg", self.name),
            MetricKind::Ratio => format!("{}.ratio", self.name),
            MetricKind::Throughput => {
                format!("{}.avg.pct_of_peak_sustained_elapsed", self.name)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricCatalog {
    pub chip_name: String,
    pub metrics: Vec<MetricBase>,
    pub supported_submetrics: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dimension {
    pub name: String,
    pub plural_name: String,
    pub exponent: i8,
    pub raw_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricDescriptor {
    pub requested_name: String,
    pub base_name: String,
    pub kind: MetricKind,
    pub metric_index: usize,
    pub rollup: Option<String>,
    pub submetric: String,
    pub description: Option<String>,
    pub hardware_unit: Option<String>,
    pub hardware_unit_id: u64,
    pub supported_rollups: Vec<String>,
    pub supported_submetrics: Vec<String>,
    pub counter_components: Vec<String>,
    pub throughput_components: Vec<String>,
    pub dimensions: Vec<Dimension>,
    pub raw_dependencies: Vec<String>,
    pub optional_raw_dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampleInfo {
    pub range_index: usize,
    pub timestamp_start_ns: u64,
    pub timestamp_end_ns: u64,
    pub timestamp_valid: bool,
    pub duration_ns: Option<u64>,
    pub trigger_count: u32,
    pub complete: bool,
    pub descriptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeriodicSamplerInfo {
    pub total_ranges: usize,
    pub populated_ranges: usize,
    pub completed_ranges: usize,
    pub timestamp_span_ns: Option<u64>,
    pub first_sample: Option<SampleInfo>,
    pub last_sample: Option<SampleInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CounterImageInfo {
    pub image_size: usize,
    pub chip_name: String,
    pub num_ranges: usize,
    pub periodic_sampler: PeriodicSamplerInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricSample {
    pub range_index: usize,
    pub timestamp_start_ns: u64,
    pub timestamp_end_ns: u64,
    pub time_ns: Option<u64>,
    pub duration_ns: Option<u64>,
    pub complete: bool,
    pub values: BTreeMap<String, Option<f64>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricEvaluation {
    pub metrics: Vec<String>,
    pub samples: Vec<MetricSample>,
}

/// Capture-wide availability and distribution of one canonical metric form.
#[derive(Debug, Clone, Serialize)]
pub struct MetricAvailability {
    pub base_name: String,
    pub metric_name: String,
    pub kind: MetricKind,
    pub valid_samples: usize,
    pub selected_samples: usize,
    pub sample_coverage_pct: f64,
    pub nonzero_samples: usize,
    pub sample_mean: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricScan {
    pub chip_name: String,
    pub sample_start: usize,
    pub sample_stop: usize,
    pub selected_samples: usize,
    pub metrics: Vec<MetricAvailability>,
}

/// A disk-backed, memory-mapped PerfWorks `LOPDATA` image.
pub struct CounterImage {
    backing: File,
    mapping: MmapMut,
    pub section_index: usize,
    pub outer_chunk_count: usize,
}

impl std::fmt::Debug for CounterImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CounterImage")
            .field("size", &self.mapping.len())
            .field("section_index", &self.section_index)
            .field("outer_chunk_count", &self.outer_chunk_count)
            .finish()
    }
}

impl CounterImage {
    pub fn from_container(container: &Container) -> Result<Self> {
        let section = container.section(SectionRole::CounterData)?;
        let mut backing = tempfile::tempfile()?;
        for chunk in &section.chunks {
            let data = container.read_chunk(chunk)?;
            if chunk.index == 0 && !data.starts_with(b"LOPDATA\0") {
                return Err(Error::InvalidCapture(
                    "counter section does not begin with LOPDATA".into(),
                ));
            }
            backing.write_all(&data)?;
        }
        if backing.stream_position()? != section.unpacked_size {
            return Err(Error::InvalidCapture(
                "materialized counter image has an unexpected size".into(),
            ));
        }
        backing.flush()?;
        backing.seek(SeekFrom::Start(0))?;
        // SAFETY: the temporary file remains owned by CounterImage for at least
        // as long as the mapping, and no code truncates or replaces it.
        let mapping = unsafe { MmapOptions::new().map_copy(&backing)? };
        Ok(Self {
            backing,
            mapping,
            section_index: section.index,
            outer_chunk_count: section.chunks.len(),
        })
    }

    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.mapping
    }

    fn pointer(&self) -> *const u8 {
        self.mapping.as_ptr()
    }

    pub fn backing_file(&self) -> &File {
        &self.backing
    }
}

/// Runtime handle for the NVIDIA PerfWorks host library.
pub struct PerfWorks {
    path: PathBuf,
    library: Library,
}

impl std::fmt::Debug for PerfWorks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PerfWorks")
            .field("path", &self.path)
            .finish()
    }
}

impl PerfWorks {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = discover_nvperf_library(path)?;
        // SAFETY: loading an explicit native library is inherently unsafe. We
        // resolve only known C ABI entry points and keep Library alive while
        // any evaluator pointer can exist.
        let library = unsafe { Library::new(&path)? };
        let host = Self { path, library };
        let mut params = NvInitializeHost {
            struct_size: field_end::<NvInitializeHost>(
                offset_of!(NvInitializeHost, p_priv),
                size_of::<*mut c_void>(),
            ),
            p_priv: ptr::null_mut(),
        };
        host.call(b"NVPW_InitializeHost\0", &mut params)?;
        Ok(host)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn inspect(&self, image: &CounterImage) -> Result<CounterImageInfo> {
        let chip_name = self.chip_name(image)?;
        let mut ranges = NvNumRanges {
            struct_size: field_end::<NvNumRanges>(
                offset_of!(NvNumRanges, num_ranges),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            num_ranges: 0,
        };
        self.call(b"NVPW_CounterData_GetNumRanges\0", &mut ranges)?;
        let mut periodic = NvPeriodicInfo {
            struct_size: field_end::<NvPeriodicInfo>(
                offset_of!(NvPeriodicInfo, completed_ranges),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            image_size: image.len(),
            total_ranges: 0,
            populated_ranges: 0,
            completed_ranges: 0,
        };
        self.call(b"NVPW_PeriodicSampler_CounterData_GetInfo\0", &mut periodic)?;
        let first_sample = if periodic.populated_ranges > 0 {
            Some(self.sample_info(image, 0)?)
        } else {
            None
        };
        let last_sample = if periodic.populated_ranges > 1 {
            Some(self.sample_info(image, periodic.populated_ranges - 1)?)
        } else {
            first_sample.clone()
        };
        let span_start = match &first_sample {
            Some(sample) if sample.timestamp_valid => Some(sample.timestamp_start_ns),
            Some(_) if periodic.populated_ranges > 1 => {
                let second = self.sample_info(image, 1)?;
                second.timestamp_valid.then_some(second.timestamp_start_ns)
            }
            _ => None,
        };
        let timestamp_span_ns = span_start.and_then(|start| {
            last_sample
                .as_ref()
                .filter(|sample| sample.timestamp_end_ns >= start)
                .map(|sample| sample.timestamp_end_ns - start)
        });
        Ok(CounterImageInfo {
            image_size: image.len(),
            chip_name,
            num_ranges: ranges.num_ranges,
            periodic_sampler: PeriodicSamplerInfo {
                total_ranges: periodic.total_ranges,
                populated_ranges: periodic.populated_ranges,
                completed_ranges: periodic.completed_ranges,
                timestamp_span_ns,
                first_sample,
                last_sample,
            },
        })
    }

    pub fn sample_info(&self, image: &CounterImage, range_index: usize) -> Result<SampleInfo> {
        let mut timing = NvSampleTime {
            struct_size: field_end::<NvSampleTime>(
                offset_of!(NvSampleTime, timestamp_end),
                size_of::<u64>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            range_index,
            timestamp_start: 0,
            timestamp_end: 0,
        };
        self.call(
            b"NVPW_PeriodicSampler_CounterData_GetSampleTime\0",
            &mut timing,
        )?;
        let mut trigger = NvTriggerCount {
            struct_size: field_end::<NvTriggerCount>(
                offset_of!(NvTriggerCount, trigger_count),
                size_of::<u32>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            image_size: image.len(),
            range_index,
            trigger_count: 0,
        };
        self.call(
            b"NVPW_PeriodicSampler_CounterData_GetTriggerCount\0",
            &mut trigger,
        )?;
        let mut complete = NvIsComplete {
            struct_size: field_end::<NvIsComplete>(
                offset_of!(NvIsComplete, is_complete),
                size_of::<u8>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            image_size: image.len(),
            range_index,
            is_complete: 0,
        };
        self.call(
            b"NVPW_PeriodicSampler_CounterData_IsDataComplete\0",
            &mut complete,
        )?;
        let mut descriptions = NvRangeDescriptions {
            struct_size: field_end::<NvRangeDescriptions>(
                offset_of!(NvRangeDescriptions, descriptions),
                size_of::<*mut *const c_char>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            range_index,
            num_descriptions: 0,
            descriptions: ptr::null_mut(),
        };
        self.call(
            b"NVPW_CounterData_GetRangeDescriptions\0",
            &mut descriptions,
        )?;
        let mut pointers = vec![ptr::null(); descriptions.num_descriptions];
        if !pointers.is_empty() {
            descriptions.descriptions = pointers.as_mut_ptr();
            self.call(
                b"NVPW_CounterData_GetRangeDescriptions\0",
                &mut descriptions,
            )?;
        }
        let timestamp_valid =
            timing.timestamp_start != 0 && timing.timestamp_end >= timing.timestamp_start;
        Ok(SampleInfo {
            range_index,
            timestamp_start_ns: timing.timestamp_start,
            timestamp_end_ns: timing.timestamp_end,
            timestamp_valid,
            duration_ns: timestamp_valid.then_some(timing.timestamp_end - timing.timestamp_start),
            trigger_count: trigger.trigger_count,
            complete: complete.is_complete != 0,
            descriptions: pointers.into_iter().filter_map(c_string).collect(),
        })
    }

    pub fn metric_catalog(&self, api: MetricsApi, chip_name: &str) -> Result<MetricCatalog> {
        let evaluator = self.evaluator(api, chip_name)?;
        let mut metrics = Vec::new();
        let mut supported_submetrics = BTreeMap::new();
        for kind in [
            MetricKind::Counter,
            MetricKind::Ratio,
            MetricKind::Throughput,
        ] {
            metrics.extend(evaluator.metric_names(kind)?);
            supported_submetrics.insert(
                metric_kind_name(kind).to_owned(),
                evaluator.supported_submetrics(kind)?,
            );
        }
        Ok(MetricCatalog {
            chip_name: chip_name.to_owned(),
            metrics,
            supported_submetrics,
        })
    }

    pub fn describe_metric(
        &self,
        api: MetricsApi,
        chip_name: &str,
        metric_name: &str,
    ) -> Result<MetricDescriptor> {
        let evaluator = self.evaluator(api, chip_name)?;
        evaluator.describe(metric_name)
    }

    pub fn evaluate(
        &self,
        api: MetricsApi,
        image: &CounterImage,
        metric_names: &[String],
        start: usize,
        stop: Option<usize>,
    ) -> Result<MetricEvaluation> {
        if metric_names.is_empty() {
            return Err(Error::PerfWorks("at least one metric is required".into()));
        }
        let info = self.inspect(image)?;
        let first = start.min(info.periodic_sampler.populated_ranges);
        let final_index = stop
            .unwrap_or(info.periodic_sampler.populated_ranges)
            .clamp(first, info.periodic_sampler.populated_ranges);
        let evaluator = self.evaluator(api, &info.chip_name)?;
        let c_names: Vec<_> = metric_names
            .iter()
            .map(|name| {
                CString::new(name.as_str())
                    .map_err(|_| Error::PerfWorks(format!("metric name contains NUL: {name:?}")))
            })
            .collect::<Result<_>>()?;
        let mut requests = Vec::with_capacity(c_names.len());
        for (name, c_name) in metric_names.iter().zip(&c_names) {
            requests.push(evaluator.convert_metric(name, c_name)?);
        }
        evaluator.set_device_attributes(image)?;
        let mut values = vec![0.0f64; requests.len()];
        let mut samples = Vec::with_capacity(final_index - first);
        let mut origin = None;
        for range_index in first..final_index {
            let sample = self.sample_info(image, range_index)?;
            if origin.is_none() && sample.timestamp_valid {
                origin = Some(sample.timestamp_start_ns);
            }
            let mut params = NvEvaluateMetrics {
                struct_size: field_end::<NvEvaluateMetrics>(
                    offset_of!(NvEvaluateMetrics, values),
                    size_of::<*mut f64>(),
                ),
                p_priv: ptr::null_mut(),
                evaluator: evaluator.pointer,
                requests: requests.as_ptr(),
                request_count: requests.len(),
                request_size: metric_request_size(),
                request_stride: size_of::<NvMetricRequest>(),
                counter_data: image.pointer(),
                counter_data_size: image.len(),
                range_index,
                isolated: 1,
                values: values.as_mut_ptr(),
            };
            self.call(b"NVPW_MetricsEvaluator_EvaluateToGpuValues\0", &mut params)?;
            let values = metric_names
                .iter()
                .cloned()
                .zip(
                    values
                        .iter()
                        .map(|value| value.is_finite().then_some(*value)),
                )
                .collect();
            samples.push(MetricSample {
                range_index,
                timestamp_start_ns: sample.timestamp_start_ns,
                timestamp_end_ns: sample.timestamp_end_ns,
                time_ns: origin
                    .filter(|_| sample.timestamp_valid)
                    .map(|origin| sample.timestamp_start_ns - origin),
                duration_ns: sample.duration_ns,
                complete: sample.complete,
                values,
            });
        }
        Ok(MetricEvaluation {
            metrics: metric_names.to_vec(),
            samples,
        })
    }

    /// Evaluate one canonical form of each metric base in a single pass.
    /// Finite zeroes count as collected values; unavailable values do not.
    pub fn scan(
        &self,
        api: MetricsApi,
        image: &CounterImage,
        metric_bases: &[MetricBase],
        start: usize,
        stop: Option<usize>,
    ) -> Result<MetricScan> {
        let info = self.inspect(image)?;
        let first = start.min(info.periodic_sampler.populated_ranges);
        let final_index = stop
            .unwrap_or(info.periodic_sampler.populated_ranges)
            .clamp(first, info.periodic_sampler.populated_ranges);
        if metric_bases.is_empty() {
            return Ok(MetricScan {
                chip_name: info.chip_name,
                sample_start: first,
                sample_stop: final_index,
                selected_samples: final_index - first,
                metrics: Vec::new(),
            });
        }

        let evaluator = self.evaluator(api, &info.chip_name)?;
        let names: Vec<_> = metric_bases
            .iter()
            .map(MetricBase::canonical_evaluation_name)
            .collect();
        let c_names: Vec<_> = names
            .iter()
            .map(|name| {
                CString::new(name.as_str())
                    .map_err(|_| Error::PerfWorks(format!("metric name contains NUL: {name:?}")))
            })
            .collect::<Result<_>>()?;
        let requests = names
            .iter()
            .zip(&c_names)
            .map(|(name, c_name)| evaluator.convert_metric(name, c_name))
            .collect::<Result<Vec<_>>>()?;
        evaluator.set_device_attributes(image)?;

        #[derive(Clone, Copy)]
        struct Accumulator {
            valid: usize,
            nonzero: usize,
            sum: f64,
            min: f64,
            max: f64,
        }
        let mut accumulators = vec![
            Accumulator {
                valid: 0,
                nonzero: 0,
                sum: 0.0,
                min: f64::INFINITY,
                max: f64::NEG_INFINITY,
            };
            requests.len()
        ];
        let mut values = vec![f64::NAN; requests.len()];
        for range_index in first..final_index {
            values.fill(f64::NAN);
            let mut params = NvEvaluateMetrics {
                struct_size: field_end::<NvEvaluateMetrics>(
                    offset_of!(NvEvaluateMetrics, values),
                    size_of::<*mut f64>(),
                ),
                p_priv: ptr::null_mut(),
                evaluator: evaluator.pointer,
                requests: requests.as_ptr(),
                request_count: requests.len(),
                request_size: metric_request_size(),
                request_stride: size_of::<NvMetricRequest>(),
                counter_data: image.pointer(),
                counter_data_size: image.len(),
                range_index,
                isolated: 1,
                values: values.as_mut_ptr(),
            };
            self.call(b"NVPW_MetricsEvaluator_EvaluateToGpuValues\0", &mut params)?;
            for (value, accumulator) in values.iter().zip(&mut accumulators) {
                if value.is_finite() {
                    accumulator.valid += 1;
                    accumulator.nonzero += usize::from(*value != 0.0);
                    accumulator.sum += value;
                    accumulator.min = accumulator.min.min(*value);
                    accumulator.max = accumulator.max.max(*value);
                }
            }
        }

        let selected_samples = final_index - first;
        let metrics = metric_bases
            .iter()
            .zip(names)
            .zip(accumulators)
            .map(|((base, metric_name), accumulator)| MetricAvailability {
                base_name: base.name.clone(),
                metric_name,
                kind: base.kind,
                valid_samples: accumulator.valid,
                selected_samples,
                sample_coverage_pct: if selected_samples == 0 {
                    0.0
                } else {
                    100.0 * accumulator.valid as f64 / selected_samples as f64
                },
                nonzero_samples: accumulator.nonzero,
                sample_mean: (accumulator.valid > 0)
                    .then_some(accumulator.sum / accumulator.valid as f64),
                min: (accumulator.valid > 0).then_some(accumulator.min),
                max: (accumulator.valid > 0).then_some(accumulator.max),
            })
            .collect();
        Ok(MetricScan {
            chip_name: info.chip_name,
            sample_start: first,
            sample_stop: final_index,
            selected_samples,
            metrics,
        })
    }

    fn chip_name(&self, image: &CounterImage) -> Result<String> {
        let mut params = NvChipName {
            struct_size: field_end::<NvChipName>(
                offset_of!(NvChipName, chip_name),
                size_of::<*const c_char>(),
            ),
            p_priv: ptr::null_mut(),
            image: image.pointer(),
            image_size: image.len(),
            chip_name: ptr::null(),
        };
        self.call(b"NVPW_CounterData_GetChipName\0", &mut params)?;
        c_string(params.chip_name)
            .ok_or_else(|| Error::PerfWorks("counter image has no chip name".into()))
    }

    fn evaluator(&self, api: MetricsApi, chip_name: &str) -> Result<Evaluator<'_>> {
        let chip_name = CString::new(chip_name)
            .map_err(|_| Error::PerfWorks("chip name contains NUL".into()))?;
        let calculate_symbol = format!(
            "NVPW_{}_MetricsEvaluator_CalculateScratchBufferSize\0",
            api.evaluator_prefix()
        );
        let initialize_symbol = format!(
            "NVPW_{}_MetricsEvaluator_Initialize\0",
            api.evaluator_prefix()
        );
        let mut calculate = NvMetricsScratch {
            struct_size: field_end::<NvMetricsScratch>(
                offset_of!(NvMetricsScratch, counter_availability),
                size_of::<*const u8>(),
            ),
            p_priv: ptr::null_mut(),
            chip_name: chip_name.as_ptr(),
            scratch_size: 0,
            counter_availability: ptr::null(),
        };
        self.call(calculate_symbol.as_bytes(), &mut calculate)?;
        let mut scratch = vec![0u8; calculate.scratch_size];
        let mut initialize = NvMetricsInitialize {
            struct_size: field_end::<NvMetricsInitialize>(
                offset_of!(NvMetricsInitialize, counter_data_size),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            scratch: scratch.as_mut_ptr(),
            scratch_size: scratch.len(),
            chip_name: chip_name.as_ptr(),
            counter_availability: ptr::null(),
            counter_availability_size: 0,
            evaluator: ptr::null_mut(),
            counter_data: ptr::null(),
            counter_data_size: 0,
        };
        self.call(initialize_symbol.as_bytes(), &mut initialize)?;
        if initialize.evaluator.is_null() {
            return Err(Error::PerfWorks(
                "PerfWorks returned an empty metrics evaluator".into(),
            ));
        }
        Ok(Evaluator {
            host: self,
            pointer: initialize.evaluator,
            _scratch: scratch,
        })
    }

    fn call<P>(&self, symbol: &[u8], params: &mut P) -> Result<()> {
        let status = self.try_call(symbol, params)?;
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(symbol, status))
        }
    }

    fn try_call<P>(&self, symbol: &[u8], params: &mut P) -> Result<i32> {
        type Function<P> = unsafe extern "C" fn(*mut P) -> i32;
        // SAFETY: symbol names and parameter layouts mirror the PerfWorks host
        // API. The Symbol cannot outlive self.library and is called immediately.
        unsafe {
            let function: Symbol<'_, Function<P>> = self.library.get(symbol)?;
            Ok(function(params))
        }
    }
}

struct Evaluator<'a> {
    host: &'a PerfWorks,
    pointer: *mut c_void,
    _scratch: Vec<u8>,
}

impl Evaluator<'_> {
    fn metric_names(&self, kind: MetricKind) -> Result<Vec<MetricBase>> {
        let mut params = NvMetricNames {
            struct_size: field_end::<NvMetricNames>(
                offset_of!(NvMetricNames, count),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            metric_type: kind.raw(),
            names: ptr::null(),
            name_offsets: ptr::null(),
            count: 0,
        };
        self.host
            .call(b"NVPW_MetricsEvaluator_GetMetricNames\0", &mut params)?;
        if params.count > 0 && (params.names.is_null() || params.name_offsets.is_null()) {
            return Err(Error::PerfWorks(
                "metric catalog returned null storage".into(),
            ));
        }
        let mut result = Vec::with_capacity(params.count);
        for index in 0..params.count {
            // SAFETY: PerfWorks owns both arrays for the evaluator lifetime and
            // reports count entries.
            let offset = unsafe { *params.name_offsets.add(index) };
            let name = c_string(unsafe { params.names.add(offset) })
                .ok_or_else(|| Error::PerfWorks(format!("metric {kind:?}:{index} has no name")))?;
            result.push(MetricBase { name, kind, index });
        }
        Ok(result)
    }

    fn supported_submetrics(&self, kind: MetricKind) -> Result<Vec<String>> {
        let mut params = NvSupportedSubmetrics {
            struct_size: field_end::<NvSupportedSubmetrics>(
                offset_of!(NvSupportedSubmetrics, count),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            metric_type: kind.raw(),
            submetrics: ptr::null(),
            count: 0,
        };
        self.host.call(
            b"NVPW_MetricsEvaluator_GetSupportedSubmetrics\0",
            &mut params,
        )?;
        if params.count > 0 && params.submetrics.is_null() {
            return Err(Error::PerfWorks(
                "supported submetrics returned null storage".into(),
            ));
        }
        // SAFETY: pointer and count are owned by the evaluator and validated above.
        let values = unsafe { std::slice::from_raw_parts(params.submetrics, params.count) };
        Ok(values
            .iter()
            .map(|value| submetric_name(*value).to_owned())
            .collect())
    }

    fn convert_metric(&self, display_name: &str, name: &CString) -> Result<NvMetricRequest> {
        let mut request = NvMetricRequest::default();
        let mut params = NvConvertMetric {
            struct_size: field_end::<NvConvertMetric>(
                offset_of!(NvConvertMetric, request_size),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            metric_name: name.as_ptr(),
            request: &mut request,
            request_size: metric_request_size(),
        };
        let status = self.host.try_call(
            b"NVPW_MetricsEvaluator_ConvertMetricNameToMetricEvalRequest\0",
            &mut params,
        )?;
        if status != 0 {
            return Err(Error::PerfWorks(format!(
                "unsupported metric {display_name:?}: {} ({status})",
                status_name(status)
            )));
        }
        Ok(request)
    }

    fn set_device_attributes(&self, image: &CounterImage) -> Result<()> {
        let mut params = NvSetDeviceAttributes {
            struct_size: field_end::<NvSetDeviceAttributes>(
                offset_of!(NvSetDeviceAttributes, counter_data_size),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            counter_data: image.pointer(),
            counter_data_size: image.len(),
        };
        self.host
            .call(b"NVPW_MetricsEvaluator_SetDeviceAttributes\0", &mut params)
    }

    fn describe(&self, requested_name: &str) -> Result<MetricDescriptor> {
        let c_name = CString::new(requested_name)
            .map_err(|_| Error::PerfWorks("metric name contains NUL".into()))?;
        let request = self.convert_metric(requested_name, &c_name)?;
        let kind = MetricKind::from_raw(request.metric_type)?;
        let all_names = self.metric_names(kind)?;
        let base_name = all_names
            .get(request.metric_index)
            .map(|item| item.name.clone())
            .ok_or_else(|| Error::PerfWorks("metric request index is out of catalog".into()))?;
        let (description, hardware_unit_id, counter_indices, throughput_indices) = match kind {
            MetricKind::Counter => {
                let mut params = NvCounterProperties {
                    struct_size: field_end::<NvCounterProperties>(
                        offset_of!(NvCounterProperties, hardware_unit),
                        size_of::<u32>(),
                    ),
                    p_priv: ptr::null_mut(),
                    evaluator: self.pointer,
                    metric_index: request.metric_index,
                    description: ptr::null(),
                    hardware_unit: 0,
                };
                self.host
                    .call(b"NVPW_MetricsEvaluator_GetCounterProperties\0", &mut params)?;
                (
                    c_string(params.description),
                    u64::from(params.hardware_unit),
                    Vec::new(),
                    Vec::new(),
                )
            }
            MetricKind::Ratio => {
                let mut params = NvRatioProperties {
                    struct_size: field_end::<NvRatioProperties>(
                        offset_of!(NvRatioProperties, hardware_unit),
                        size_of::<u64>(),
                    ),
                    p_priv: ptr::null_mut(),
                    evaluator: self.pointer,
                    metric_index: request.metric_index,
                    description: ptr::null(),
                    hardware_unit: 0,
                };
                self.host.call(
                    b"NVPW_MetricsEvaluator_GetRatioMetricProperties\0",
                    &mut params,
                )?;
                (
                    c_string(params.description),
                    params.hardware_unit,
                    Vec::new(),
                    Vec::new(),
                )
            }
            MetricKind::Throughput => {
                let mut params = NvThroughputProperties {
                    struct_size: field_end::<NvThroughputProperties>(
                        offset_of!(NvThroughputProperties, subthroughput_indices),
                        size_of::<*const usize>(),
                    ),
                    p_priv: ptr::null_mut(),
                    evaluator: self.pointer,
                    metric_index: request.metric_index,
                    description: ptr::null(),
                    hardware_unit: 0,
                    counter_count: 0,
                    counter_indices: ptr::null(),
                    subthroughput_count: 0,
                    subthroughput_indices: ptr::null(),
                };
                self.host.call(
                    b"NVPW_MetricsEvaluator_GetThroughputMetricProperties\0",
                    &mut params,
                )?;
                (
                    c_string(params.description),
                    u64::from(params.hardware_unit),
                    copy_usize_slice(params.counter_indices, params.counter_count),
                    copy_usize_slice(params.subthroughput_indices, params.subthroughput_count),
                )
            }
        };
        let hardware_unit = u32::try_from(hardware_unit_id)
            .ok()
            .and_then(|unit| self.hardware_unit_name(unit).ok().flatten());
        let counter_names = if kind == MetricKind::Throughput {
            self.metric_names(MetricKind::Counter)?
        } else {
            Vec::new()
        };
        let throughput_names = if kind == MetricKind::Throughput {
            all_names.clone()
        } else {
            Vec::new()
        };
        Ok(MetricDescriptor {
            requested_name: requested_name.to_owned(),
            base_name,
            kind,
            metric_index: request.metric_index,
            rollup: (kind != MetricKind::Ratio).then(|| rollup_name(request.rollup).to_owned()),
            submetric: submetric_name(request.submetric).to_owned(),
            description,
            hardware_unit,
            hardware_unit_id,
            supported_rollups: if kind == MetricKind::Ratio {
                Vec::new()
            } else {
                ["avg", "max", "min", "sum"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            },
            supported_submetrics: self.supported_submetrics(kind)?,
            counter_components: counter_indices
                .into_iter()
                .filter_map(|index| counter_names.get(index).map(|item| item.name.clone()))
                .collect(),
            throughput_components: throughput_indices
                .into_iter()
                .filter_map(|index| throughput_names.get(index).map(|item| item.name.clone()))
                .collect(),
            dimensions: self.dimensions(&request)?,
            raw_dependencies: self.raw_dependencies(&request, false)?,
            optional_raw_dependencies: self.raw_dependencies(&request, true)?,
        })
    }

    fn hardware_unit_name(&self, unit: u32) -> Result<Option<String>> {
        let mut params = NvHardwareUnitName {
            struct_size: field_end::<NvHardwareUnitName>(
                offset_of!(NvHardwareUnitName, name),
                size_of::<*const c_char>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            hardware_unit: unit,
            name: ptr::null(),
        };
        self.host
            .call(b"NVPW_MetricsEvaluator_HwUnitToString\0", &mut params)?;
        Ok(c_string(params.name))
    }

    fn dimensions(&self, request: &NvMetricRequest) -> Result<Vec<Dimension>> {
        let mut params = NvMetricDimensions {
            struct_size: field_end::<NvMetricDimensions>(
                offset_of!(NvMetricDimensions, dimension_size),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            request,
            request_size: metric_request_size(),
            dimensions: ptr::null_mut(),
            count: 0,
            dimension_size: dimension_factor_size(),
        };
        self.host
            .call(b"NVPW_MetricsEvaluator_GetMetricDimUnits\0", &mut params)?;
        let mut dimensions = vec![NvDimensionFactor::default(); params.count];
        if !dimensions.is_empty() {
            params.dimensions = dimensions.as_mut_ptr();
            self.host
                .call(b"NVPW_MetricsEvaluator_GetMetricDimUnits\0", &mut params)?;
        }
        dimensions
            .into_iter()
            .map(|factor| {
                let mut name = NvDimensionName {
                    struct_size: field_end::<NvDimensionName>(
                        offset_of!(NvDimensionName, plural),
                        size_of::<*const c_char>(),
                    ),
                    p_priv: ptr::null_mut(),
                    evaluator: self.pointer,
                    dimension: factor.dimension,
                    singular: ptr::null(),
                    plural: ptr::null(),
                };
                self.host
                    .call(b"NVPW_MetricsEvaluator_DimUnitToString\0", &mut name)?;
                Ok(Dimension {
                    name: c_string(name.singular)
                        .unwrap_or_else(|| format!("dimension_{}", factor.dimension)),
                    plural_name: c_string(name.plural)
                        .unwrap_or_else(|| format!("dimension_{}", factor.dimension)),
                    exponent: factor.exponent,
                    raw_id: factor.dimension,
                })
            })
            .collect()
    }

    fn raw_dependencies(&self, request: &NvMetricRequest, optional: bool) -> Result<Vec<String>> {
        let mut params = NvRawDependencies {
            struct_size: field_end::<NvRawDependencies>(
                offset_of!(NvRawDependencies, optional_count),
                size_of::<usize>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
            requests: request,
            request_count: 1,
            request_size: metric_request_size(),
            request_stride: size_of::<NvMetricRequest>(),
            dependencies: ptr::null_mut(),
            dependency_count: 0,
            optional_dependencies: ptr::null_mut(),
            optional_count: 0,
        };
        self.host.call(
            b"NVPW_MetricsEvaluator_GetMetricRawDependencies\0",
            &mut params,
        )?;
        let mut required = vec![ptr::null(); params.dependency_count];
        let mut optional_values = vec![ptr::null(); params.optional_count];
        params.dependencies = required.as_mut_ptr();
        params.optional_dependencies = optional_values.as_mut_ptr();
        if !required.is_empty() || !optional_values.is_empty() {
            self.host.call(
                b"NVPW_MetricsEvaluator_GetMetricRawDependencies\0",
                &mut params,
            )?;
        }
        Ok((if optional { optional_values } else { required })
            .into_iter()
            .filter_map(c_string)
            .collect())
    }
}

impl Drop for Evaluator<'_> {
    fn drop(&mut self) {
        let mut params = NvDestroyMetrics {
            struct_size: field_end::<NvDestroyMetrics>(
                offset_of!(NvDestroyMetrics, evaluator),
                size_of::<*mut c_void>(),
            ),
            p_priv: ptr::null_mut(),
            evaluator: self.pointer,
        };
        let _ = self
            .host
            .call(b"NVPW_MetricsEvaluator_Destroy\0", &mut params);
    }
}

pub fn discover_nvperf_library(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return require_nvperf(path);
    }
    for variable in ["NGFX_NVPERF_LIBRARY", "WRPV_NVPERF_LIBRARY"] {
        if let Some(value) = env::var_os(variable) {
            return require_nvperf(Path::new(&value));
        }
    }
    let roots = nsight_search_roots();
    let mut candidates = Vec::new();
    for root in &roots {
        find_named_file(root, NVPERF_FILENAME, 7, &mut candidates);
    }
    candidates.sort();
    candidates.pop().ok_or(Error::Discovery {
        kind: "PerfWorks host library (set NGFX_NVPERF_LIBRARY)",
        searched: roots,
    })
}

fn require_nvperf(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        Ok(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
    } else {
        Err(Error::Discovery {
            kind: "PerfWorks host library",
            searched: vec![path.to_path_buf()],
        })
    }
}

fn field_end<T>(offset: usize, field_size: usize) -> usize {
    let _ = std::marker::PhantomData::<T>;
    offset + field_size
}

fn metric_request_size() -> usize {
    offset_of!(NvMetricRequest, submetric) + size_of::<u16>()
}

fn dimension_factor_size() -> usize {
    offset_of!(NvDimensionFactor, exponent) + size_of::<i8>()
}

fn c_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: PerfWorks returns null-terminated strings valid for the current call/evaluator.
    Some(
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn copy_usize_slice(pointer: *const usize, count: usize) -> Vec<usize> {
    if pointer.is_null() || count == 0 {
        Vec::new()
    } else {
        // SAFETY: PerfWorks returned this pointer with `count` entries.
        unsafe { std::slice::from_raw_parts(pointer, count) }.to_vec()
    }
}

fn metric_kind_name(kind: MetricKind) -> &'static str {
    match kind {
        MetricKind::Counter => "counter",
        MetricKind::Ratio => "ratio",
        MetricKind::Throughput => "throughput",
    }
}

fn rollup_name(value: u8) -> &'static str {
    match value {
        0 => "avg",
        1 => "max",
        2 => "min",
        3 => "sum",
        _ => "unknown",
    }
}

fn submetric_name(value: u16) -> &'static str {
    match value {
        0 => "none",
        1 => "peak_sustained",
        2 => "peak_sustained_active",
        3 => "peak_sustained_active_per_second",
        4 => "peak_sustained_elapsed",
        5 => "peak_sustained_elapsed_per_second",
        6 => "peak_sustained_frame",
        7 => "peak_sustained_frame_per_second",
        8 => "peak_sustained_region",
        9 => "peak_sustained_region_per_second",
        10 => "per_cycle_active",
        11 => "per_cycle_elapsed",
        12 => "per_cycle_in_frame",
        13 => "per_cycle_in_region",
        14 => "per_second",
        15 => "pct_of_peak_sustained_active",
        16 => "pct_of_peak_sustained_elapsed",
        17 => "pct_of_peak_sustained_frame",
        18 => "pct_of_peak_sustained_region",
        19 => "max_rate",
        20 => "pct",
        21 => "ratio",
        _ => "unknown",
    }
}

fn status_error(symbol: &[u8], status: i32) -> Error {
    let symbol = std::str::from_utf8(symbol)
        .unwrap_or("PerfWorks function")
        .trim_end_matches('\0');
    Error::PerfWorks(format!(
        "{symbol} failed: {} ({status})",
        status_name(status)
    ))
}

fn status_name(status: i32) -> &'static str {
    match status {
        0 => "success",
        1 => "error",
        2 => "internal_error",
        3 => "not_initialized",
        4 => "not_loaded",
        5 => "function_not_found",
        6 => "not_supported",
        7 => "not_implemented",
        8 => "invalid_argument",
        11 => "out_of_memory",
        14 => "unsupported_gpu",
        15 => "insufficient_driver_version",
        17 => "insufficient_privilege",
        20 => "resource_unavailable",
        22 => "insufficient_space",
        23 => "object_mismatch",
        25 => "profiling_not_allowed",
        _ => "unknown",
    }
}

#[repr(C)]
struct NvInitializeHost {
    struct_size: usize,
    p_priv: *mut c_void,
}

#[repr(C)]
struct NvChipName {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    image_size: usize,
    chip_name: *const c_char,
}

#[repr(C)]
struct NvNumRanges {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    num_ranges: usize,
}

#[repr(C)]
struct NvPeriodicInfo {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    image_size: usize,
    total_ranges: usize,
    populated_ranges: usize,
    completed_ranges: usize,
}

#[repr(C)]
struct NvSampleTime {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    range_index: usize,
    timestamp_start: u64,
    timestamp_end: u64,
}

#[repr(C)]
struct NvTriggerCount {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    image_size: usize,
    range_index: usize,
    trigger_count: u32,
}

#[repr(C)]
struct NvIsComplete {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    image_size: usize,
    range_index: usize,
    is_complete: u8,
}

#[repr(C)]
struct NvRangeDescriptions {
    struct_size: usize,
    p_priv: *mut c_void,
    image: *const u8,
    range_index: usize,
    num_descriptions: usize,
    descriptions: *mut *const c_char,
}

#[repr(C)]
struct NvMetricsScratch {
    struct_size: usize,
    p_priv: *mut c_void,
    chip_name: *const c_char,
    scratch_size: usize,
    counter_availability: *const u8,
}

#[repr(C)]
struct NvMetricsInitialize {
    struct_size: usize,
    p_priv: *mut c_void,
    scratch: *mut u8,
    scratch_size: usize,
    chip_name: *const c_char,
    counter_availability: *const u8,
    counter_availability_size: usize,
    evaluator: *mut c_void,
    counter_data: *const u8,
    counter_data_size: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct NvMetricRequest {
    metric_index: usize,
    metric_type: u8,
    rollup: u8,
    submetric: u16,
}

#[repr(C)]
struct NvMetricNames {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    metric_type: u8,
    names: *const c_char,
    name_offsets: *const usize,
    count: usize,
}

#[repr(C)]
struct NvConvertMetric {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    metric_name: *const c_char,
    request: *mut NvMetricRequest,
    request_size: usize,
}

#[repr(C)]
struct NvSetDeviceAttributes {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    counter_data: *const u8,
    counter_data_size: usize,
}

#[repr(C)]
struct NvEvaluateMetrics {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    requests: *const NvMetricRequest,
    request_count: usize,
    request_size: usize,
    request_stride: usize,
    counter_data: *const u8,
    counter_data_size: usize,
    range_index: usize,
    isolated: u8,
    values: *mut f64,
}

#[repr(C)]
struct NvDestroyMetrics {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
}

#[repr(C)]
struct NvSupportedSubmetrics {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    metric_type: u8,
    submetrics: *const u16,
    count: usize,
}

#[repr(C)]
struct NvCounterProperties {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    metric_index: usize,
    description: *const c_char,
    hardware_unit: u32,
}

#[repr(C)]
struct NvRatioProperties {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    metric_index: usize,
    description: *const c_char,
    hardware_unit: u64,
}

#[repr(C)]
struct NvThroughputProperties {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    metric_index: usize,
    description: *const c_char,
    hardware_unit: u32,
    counter_count: usize,
    counter_indices: *const usize,
    subthroughput_count: usize,
    subthroughput_indices: *const usize,
}

#[repr(C)]
struct NvHardwareUnitName {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    hardware_unit: u32,
    name: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct NvDimensionFactor {
    dimension: u32,
    exponent: i8,
}

#[repr(C)]
struct NvMetricDimensions {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    request: *const NvMetricRequest,
    request_size: usize,
    dimensions: *mut NvDimensionFactor,
    count: usize,
    dimension_size: usize,
}

#[repr(C)]
struct NvDimensionName {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    dimension: u32,
    singular: *const c_char,
    plural: *const c_char,
}

#[repr(C)]
struct NvRawDependencies {
    struct_size: usize,
    p_priv: *mut c_void,
    evaluator: *mut c_void,
    requests: *const NvMetricRequest,
    request_count: usize,
    request_size: usize,
    request_stride: usize,
    dependencies: *mut *const c_char,
    dependency_count: usize,
    optional_dependencies: *mut *const c_char,
    optional_count: usize,
}
