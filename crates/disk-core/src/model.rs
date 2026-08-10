use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

pub type NodeId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

impl EntryKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMetric {
    Logical,
    Allocated,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: NodeId,
    pub parent_id: Option<NodeId>,
    #[serde(skip)]
    pub(crate) raw_name: OsString,
    pub name: String,
    pub kind: EntryKind,
    pub logical_size: u64,
    pub allocated_size: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub modified_unix_ms: Option<u64>,
    pub hidden: bool,
    pub is_symlink: bool,
    pub mount_point: bool,
    pub hard_link_duplicate: bool,
}

impl Node {
    pub fn size(&self, metric: SizeMetric) -> u64 {
        match metric {
            SizeMetric::Logical => self.logical_size,
            SizeMetric::Allocated => self.allocated_size,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanErrorSample {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub current_path: String,
    pub canceled: bool,
    pub finished: bool,
}

impl ScanProgress {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            files: 0,
            directories: 0,
            symlinks: 0,
            logical_bytes: 0,
            allocated_bytes: 0,
            errors: 0,
            elapsed_ms: 0,
            current_path: root.to_string_lossy().into_owned(),
            canceled: false,
            finished: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub root: String,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub other_entries: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub errors: u64,
    pub hard_link_duplicates: u64,
    pub elapsed_ms: u64,
    pub canceled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    #[serde(skip)]
    pub(crate) root_path: PathBuf,
    pub root_id: NodeId,
    pub summary: ScanSummary,
    pub nodes: Vec<Node>,
    pub error_samples: Vec<ScanErrorSample>,
    #[serde(skip)]
    pub(crate) children: Vec<Vec<NodeId>>,
}

impl ScanResult {
    pub(crate) fn new(
        root_path: PathBuf,
        root_id: NodeId,
        summary: ScanSummary,
        nodes: Vec<Node>,
        error_samples: Vec<ScanErrorSample>,
    ) -> Self {
        let mut children = vec![Vec::new(); nodes.len()];
        for node in &nodes {
            if let Some(parent_id) = node.parent_id
                && let Some(bucket) = children.get_mut(parent_id as usize)
            {
                bucket.push(node.id);
            }
        }

        Self {
            root_path,
            root_id,
            summary,
            nodes,
            error_samples,
            children,
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id as usize)
    }

    pub fn children_of(&self, id: NodeId) -> impl Iterator<Item = &Node> {
        self.children
            .get(id as usize)
            .into_iter()
            .flatten()
            .filter_map(|child_id| self.node(*child_id))
    }

    pub fn path_for(&self, id: NodeId) -> Option<PathBuf> {
        if id == self.root_id {
            return Some(self.root_path.clone());
        }

        let mut names = Vec::new();
        let mut cursor = self.node(id)?;
        let mut remaining = self.nodes.len();

        while cursor.id != self.root_id && remaining > 0 {
            names.push(cursor.raw_name.clone());
            cursor = self.node(cursor.parent_id?)?;
            remaining -= 1;
        }

        if cursor.id != self.root_id {
            return None;
        }

        let mut path = self.root_path.clone();
        for name in names.iter().rev() {
            path.push(name);
        }
        Some(path)
    }

    pub fn display_path(&self, id: NodeId) -> Option<String> {
        self.path_for(id)
            .map(|path| path.to_string_lossy().into_owned())
    }

    pub fn largest(&self, kind: Option<EntryKind>, metric: SizeMetric, limit: usize) -> Vec<&Node> {
        let mut nodes: Vec<_> = self
            .nodes
            .iter()
            .filter(|node| node.id != self.root_id)
            .filter(|node| kind.is_none_or(|wanted| node.kind == wanted))
            .collect();
        nodes.sort_unstable_by(|left, right| {
            right
                .size(metric)
                .cmp(&left.size(metric))
                .then_with(|| left.name.cmp(&right.name))
        });
        nodes.truncate(limit);
        nodes
    }

    pub fn elapsed(&self) -> Duration {
        Duration::from_millis(self.summary.elapsed_ms)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_format_uses_iec_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MiB");
    }
}
