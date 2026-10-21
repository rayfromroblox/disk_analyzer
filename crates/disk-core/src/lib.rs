//! Shared disk scanning engine used by the web server, CLI, and TUI.

mod model;
mod platform;
mod scanner;

pub use model::{
    EntryKind, Node, NodeId, ScanErrorSample, ScanProgress, ScanResult, ScanSummary, SizeMetric,
    format_bytes,
};
pub use scanner::{CancellationToken, ScanConfig, ScanFailure, scan};
