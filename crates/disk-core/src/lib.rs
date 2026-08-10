//! Shared disk scanning engine used by the CLI, TUI, and desktop application.

mod model;
mod platform;
mod scanner;

pub use model::{
    EntryKind, Node, NodeId, ScanErrorSample, ScanProgress, ScanResult, ScanSummary, SizeMetric,
    format_bytes,
};
pub use scanner::{CancellationToken, ScanConfig, ScanFailure, scan};
