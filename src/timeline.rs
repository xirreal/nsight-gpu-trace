//! Queue-lane timing evidence derived from timestamp buckets and frames.
//!
//! This module reports gaps, overlap, and frame pacing. It deliberately does
//! not label a gap as a cause or choose an optimization.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{Analysis, Frame};

#[derive(Debug, Clone, Copy, Default)]
pub struct TimelineOptions {
    /// Gaps shorter than this are omitted from the lane and global gap lists.
    pub min_gap_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineInterval {
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
    pub bucket_index: usize,
    pub first_call_index: usize,
    pub next_call_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineGap {
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineLane {
    pub device_index: usize,
    pub queue_index: usize,
    pub stream_index: usize,
    pub first_ns: u64,
    pub last_ns: u64,
    pub busy_ns: u64,
    pub gap_ns: u64,
    pub intervals: Vec<TimelineInterval>,
    pub gaps: Vec<TimelineGap>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FramePacing {
    pub id: String,
    pub kind: String,
    pub index: usize,
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
    pub gap_since_previous_ns: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FrameSummary {
    pub count: usize,
    pub presented: usize,
    pub application: usize,
    pub span_ns: Option<u64>,
    pub duration_p50_ns: Option<u64>,
    pub duration_p95_ns: Option<u64>,
    pub duration_max_ns: Option<u64>,
    pub gap_p50_ns: Option<u64>,
    pub gap_p95_ns: Option<u64>,
    pub gap_max_ns: Option<u64>,
    pub frames_per_second: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub duration_ns: Option<u64>,
    pub summed_busy_ns: u64,
    pub union_busy_ns: u64,
    pub overlap_ns: u64,
    /// Summed lane busy time divided by the union of all busy intervals.
    /// `1.0` means no stream overlap; values above `1.0` mean concurrent work.
    pub parallelism: Option<f64>,
    pub lanes: Vec<TimelineLane>,
    pub global_gaps: Vec<TimelineGap>,
    pub longest_global_gap: Option<TimelineGap>,
    pub frames: Vec<FramePacing>,
    pub frame_summary: FrameSummary,
}

impl Analysis {
    pub fn timeline(&self, options: TimelineOptions) -> Timeline {
        let mut grouped: BTreeMap<(usize, usize, usize), Vec<&crate::TimingBucket>> =
            BTreeMap::new();
        for bucket in self.timing_buckets() {
            grouped
                .entry((bucket.device_index, bucket.queue_index, bucket.stream_index))
                .or_default()
                .push(bucket);
        }

        let mut lanes = Vec::new();
        let mut all_intervals = Vec::new();
        for ((device_index, queue_index, stream_index), buckets) in grouped {
            let mut intervals: Vec<TimelineInterval> = buckets
                .into_iter()
                .filter_map(|bucket| {
                    bucket
                        .interval()
                        .filter(|(start, end)| end > start)
                        .map(|(start, end)| TimelineInterval {
                            start_ns: start,
                            end_ns: end,
                            duration_ns: end - start,
                            bucket_index: bucket.index,
                            first_call_index: bucket.first_global_call_index,
                            next_call_index: bucket.next_global_call_index,
                        })
                })
                .collect();
            intervals.sort_by_key(|interval| (interval.start_ns, interval.end_ns));
            if intervals.is_empty() {
                continue;
            }
            let first_ns = intervals.first().unwrap().start_ns;
            let last_ns = intervals
                .iter()
                .map(|interval| interval.end_ns)
                .max()
                .unwrap();
            let (busy_ns, gaps) = gaps_for_intervals(
                intervals
                    .iter()
                    .map(|interval| (interval.start_ns, interval.end_ns)),
                options.min_gap_ns,
            );
            all_intervals.extend(
                intervals
                    .iter()
                    .map(|interval| (interval.start_ns, interval.end_ns)),
            );
            lanes.push(TimelineLane {
                device_index,
                queue_index,
                stream_index,
                first_ns,
                last_ns,
                busy_ns,
                gap_ns: last_ns.saturating_sub(first_ns).saturating_sub(busy_ns),
                intervals,
                gaps,
            });
        }

        let summed_busy_ns = lanes.iter().map(|lane| lane.busy_ns).sum();
        let merged = merge_intervals(all_intervals);
        let union_busy_ns: u64 = merged.iter().map(|(start, end)| end - start).sum();
        let global_gaps = merged
            .windows(2)
            .filter_map(|pair| {
                let start = pair[0].1;
                let end = pair[1].0;
                (end > start && end - start >= options.min_gap_ns).then_some(TimelineGap {
                    start_ns: start,
                    end_ns: end,
                    duration_ns: end - start,
                })
            })
            .collect::<Vec<_>>();
        let longest_global_gap = global_gaps
            .iter()
            .max_by_key(|gap| gap.duration_ns)
            .cloned();

        let mut frames: Vec<FramePacing> = self
            .frames()
            .iter()
            .map(|frame| frame_pacing(frame, None))
            .collect();
        frames.sort_by_key(|frame| (frame.start_ns, frame.end_ns, frame.id.clone()));
        for index in 1..frames.len() {
            let gap = frames[index]
                .start_ns
                .saturating_sub(frames[index - 1].end_ns);
            frames[index].gap_since_previous_ns = Some(gap);
        }
        let frame_summary = summarize_frames(&frames);

        let mut start_ns = merged.first().map(|(start, _)| *start);
        let mut end_ns = merged.last().map(|(_, end)| *end);
        if let Some(first_frame) = frames.first() {
            start_ns = Some(start_ns.map_or(first_frame.start_ns, |value| {
                value.min(first_frame.start_ns)
            }));
        }
        if let Some(last_frame) = frames.last() {
            end_ns = Some(end_ns.map_or(last_frame.end_ns, |value| value.max(last_frame.end_ns)));
        }
        let duration_ns = start_ns.zip(end_ns).map(|(start, end)| end - start);
        let parallelism =
            (union_busy_ns > 0).then_some(summed_busy_ns as f64 / union_busy_ns as f64);

        Timeline {
            start_ns,
            end_ns,
            duration_ns,
            summed_busy_ns,
            union_busy_ns,
            overlap_ns: summed_busy_ns.saturating_sub(union_busy_ns),
            parallelism,
            lanes,
            global_gaps,
            longest_global_gap,
            frames,
            frame_summary,
        }
    }
}

fn frame_pacing(frame: &Frame, gap: Option<u64>) -> FramePacing {
    FramePacing {
        id: frame.id.clone(),
        kind: frame.kind.clone(),
        index: frame.index,
        start_ns: frame.start_ns,
        end_ns: frame.end_ns,
        duration_ns: frame.duration_ns,
        gap_since_previous_ns: gap,
    }
}

fn gaps_for_intervals(
    intervals: impl IntoIterator<Item = (u64, u64)>,
    min_gap_ns: u64,
) -> (u64, Vec<TimelineGap>) {
    let merged = merge_intervals(intervals);
    let busy_ns = merged.iter().map(|(start, end)| end - start).sum();
    let gaps = merged
        .windows(2)
        .filter_map(|pair| {
            let start = pair[0].1;
            let end = pair[1].0;
            (end > start && end - start >= min_gap_ns).then_some(TimelineGap {
                start_ns: start,
                end_ns: end,
                duration_ns: end - start,
            })
        })
        .collect();
    (busy_ns, gaps)
}

fn merge_intervals(intervals: impl IntoIterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut sorted: Vec<_> = intervals.into_iter().filter(|(s, e)| e > s).collect();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

fn summarize_frames(frames: &[FramePacing]) -> FrameSummary {
    let durations: Vec<u64> = frames.iter().map(|frame| frame.duration_ns).collect();
    let gaps: Vec<u64> = frames
        .iter()
        .filter_map(|frame| frame.gap_since_previous_ns)
        .collect();
    let span_ns = frames
        .first()
        .zip(frames.last())
        .map(|(first, last)| last.end_ns.saturating_sub(first.start_ns));
    FrameSummary {
        count: frames.len(),
        presented: frames
            .iter()
            .filter(|frame| frame.kind == "presented")
            .count(),
        application: frames
            .iter()
            .filter(|frame| frame.kind == "application")
            .count(),
        span_ns,
        duration_p50_ns: percentile(&durations, 0.50),
        duration_p95_ns: percentile(&durations, 0.95),
        duration_max_ns: durations.iter().max().copied(),
        gap_p50_ns: percentile(&gaps, 0.50),
        gap_p95_ns: percentile(&gaps, 0.95),
        gap_max_ns: gaps.iter().max().copied(),
        frames_per_second: span_ns.and_then(|span| {
            (span > 0).then_some(frames.len() as f64 * 1_000_000_000.0 / span as f64)
        }),
    }
}

fn percentile(values: &[u64], fraction: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let position = (sorted.len() - 1) as f64 * fraction;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        Some(sorted[lower])
    } else {
        let interpolated = sorted[lower] as f64
            + (sorted[upper] as f64 - sorted[lower] as f64) * (position - lower as f64);
        Some(interpolated.round() as u64)
    }
}
