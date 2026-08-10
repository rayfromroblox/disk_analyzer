use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jwalk::{Parallelism, WalkDir};
use thiserror::Error;

use crate::model::{
    EntryKind, Node, NodeId, ScanErrorSample, ScanProgress, ScanResult, ScanSummary,
};
use crate::platform::{FileIdentity, allocated_size, device_id, file_identity};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub root: PathBuf,
    /// Zero selects a conservative automatic value. One forces serial traversal.
    pub threads: usize,
    pub follow_symlinks: bool,
    pub stay_on_filesystem: bool,
    pub deduplicate_hard_links: bool,
    pub max_error_samples: usize,
    pub progress_interval: Duration,
}

impl ScanConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            threads: 0,
            follow_symlinks: false,
            stay_on_filesystem: true,
            deduplicate_hard_links: true,
            max_error_samples: 100,
            progress_interval: Duration::from_millis(125),
        }
    }

    fn worker_count(&self) -> usize {
        if self.threads > 0 {
            return self.threads.clamp(1, 64);
        }
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(2)
            .clamp(2, 8)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Error)]
pub enum ScanFailure {
    #[error("cannot inspect scan root {path}: {source}")]
    InvalidRoot {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("scan root disappeared before it could be read: {0}")]
    MissingRoot(String),
}

#[derive(Default)]
struct Counters {
    files: u64,
    directories: u64,
    symlinks: u64,
    other: u64,
    logical_bytes: u64,
    allocated_bytes: u64,
    errors: u64,
    hard_link_duplicates: u64,
}

impl Counters {
    fn progress(&self, started: Instant, current_path: String, canceled: bool) -> ScanProgress {
        ScanProgress {
            files: self.files,
            directories: self.directories,
            symlinks: self.symlinks,
            logical_bytes: self.logical_bytes,
            allocated_bytes: self.allocated_bytes,
            errors: self.errors,
            elapsed_ms: duration_ms(started.elapsed()),
            current_path,
            canceled,
            finished: false,
        }
    }
}

pub fn scan<F>(
    config: ScanConfig,
    cancellation: CancellationToken,
    mut on_progress: F,
) -> Result<ScanResult, ScanFailure>
where
    F: FnMut(&ScanProgress),
{
    let root = absolute_path(&config.root);
    let root_link_metadata =
        fs::symlink_metadata(&root).map_err(|source| ScanFailure::InvalidRoot {
            path: root.to_string_lossy().into_owned(),
            source,
        })?;
    if !root.exists() && !root_link_metadata.file_type().is_symlink() {
        return Err(ScanFailure::MissingRoot(
            root.to_string_lossy().into_owned(),
        ));
    }
    let root_is_symlink = root_link_metadata.file_type().is_symlink();
    let root_metadata = if root_is_symlink && config.follow_symlinks {
        fs::metadata(&root).map_err(|source| ScanFailure::InvalidRoot {
            path: root.to_string_lossy().into_owned(),
            source,
        })?
    } else {
        root_link_metadata
    };

    let started = Instant::now();
    let mut last_progress = started;
    let root_device = device_id(&root, &root_metadata);
    let mut counters = Counters::default();
    let mut nodes = Vec::new();
    let mut paths = HashMap::<PathBuf, NodeId>::new();
    let mut identities = HashSet::<FileIdentity>::new();
    let mut error_samples = Vec::new();
    let mut current_path = root.to_string_lossy().into_owned();

    on_progress(&ScanProgress::new(&root));

    let root_node = create_node(
        0,
        None,
        &root,
        &root,
        &root_metadata,
        root_is_symlink,
        &config,
        root_device,
        &mut identities,
        &mut counters,
    );
    nodes.push(root_node);
    paths.insert(root.clone(), 0);

    let parallelism = match config.worker_count() {
        1 => Parallelism::Serial,
        workers => Parallelism::RayonNewPool(workers),
    };

    let callback_cancel = cancellation.clone();
    let stay_on_filesystem = config.stay_on_filesystem;
    let follow_symlinks = config.follow_symlinks;
    let mut walker = WalkDir::new(&root)
        .min_depth(1)
        .skip_hidden(false)
        .follow_links(follow_symlinks)
        .parallelism(parallelism);

    walker = walker.process_read_dir(move |_depth, _path, _state, entries| {
        if callback_cancel.is_cancelled() {
            entries.clear();
            return;
        }
        if !stay_on_filesystem || root_device.is_none() {
            return;
        }

        for entry in entries.iter_mut().filter_map(|result| result.as_mut().ok()) {
            if !entry.file_type().is_dir() {
                continue;
            }
            let path = entry.path();
            let metadata = if follow_symlinks {
                fs::metadata(&path)
            } else {
                fs::symlink_metadata(&path)
            };
            if let Ok(metadata) = metadata
                && device_id(&path, &metadata) != root_device
            {
                entry.read_children_path = None;
            }
        }
    });

    for item in walker {
        if cancellation.is_cancelled() && !nodes.is_empty() {
            break;
        }

        let entry = match item {
            Ok(entry) => entry,
            Err(error) => {
                record_error(
                    &mut counters,
                    &mut error_samples,
                    config.max_error_samples,
                    error.path().unwrap_or(&root),
                    error.to_string(),
                );
                continue;
            }
        };

        let path = entry.path();
        current_path = path.to_string_lossy().into_owned();
        let link_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                record_error(
                    &mut counters,
                    &mut error_samples,
                    config.max_error_samples,
                    &path,
                    error.to_string(),
                );
                continue;
            }
        };
        let is_symlink = link_metadata.file_type().is_symlink();
        let metadata = if is_symlink && config.follow_symlinks {
            match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    record_error(
                        &mut counters,
                        &mut error_samples,
                        config.max_error_samples,
                        &path,
                        error.to_string(),
                    );
                    continue;
                }
            }
        } else {
            link_metadata
        };

        let parent_id = path.parent().and_then(|parent| paths.get(parent)).copied();
        let id = nodes.len() as NodeId;
        let node = create_node(
            id,
            parent_id,
            &path,
            &root,
            &metadata,
            is_symlink,
            &config,
            root_device,
            &mut identities,
            &mut counters,
        );
        nodes.push(node);
        paths.insert(path, id);

        if last_progress.elapsed() >= config.progress_interval {
            on_progress(&counters.progress(
                started,
                current_path.clone(),
                cancellation.is_cancelled(),
            ));
            last_progress = Instant::now();
        }
    }

    aggregate_directories(&mut nodes);
    let root_id = *paths.get(&root).unwrap_or(&0);
    let root_node = &nodes[root_id as usize];
    let canceled = cancellation.is_cancelled();
    let elapsed_ms = duration_ms(started.elapsed());
    let summary = ScanSummary {
        root: root.to_string_lossy().into_owned(),
        files: counters.files,
        directories: counters.directories,
        symlinks: counters.symlinks,
        other_entries: counters.other,
        logical_bytes: root_node.logical_size,
        allocated_bytes: root_node.allocated_size,
        errors: counters.errors,
        hard_link_duplicates: counters.hard_link_duplicates,
        elapsed_ms,
        canceled,
    };
    let result = ScanResult::new(root, root_id, summary, nodes, error_samples);

    on_progress(&ScanProgress {
        files: counters.files,
        directories: counters.directories,
        symlinks: counters.symlinks,
        logical_bytes: result.summary.logical_bytes,
        allocated_bytes: result.summary.allocated_bytes,
        errors: counters.errors,
        elapsed_ms,
        current_path,
        canceled,
        finished: true,
    });
    Ok(result)
}

fn aggregate_directories(nodes: &mut [Node]) {
    for index in (0..nodes.len()).rev() {
        let Some(parent_id) = nodes[index].parent_id else {
            continue;
        };
        let child_logical = nodes[index].logical_size;
        let child_allocated = nodes[index].allocated_size;
        let child_files = nodes[index].file_count;
        let child_directories =
            nodes[index].directory_count + u64::from(nodes[index].kind == EntryKind::Directory);
        if let Some(parent) = nodes.get_mut(parent_id as usize) {
            parent.logical_size = parent.logical_size.saturating_add(child_logical);
            parent.allocated_size = parent.allocated_size.saturating_add(child_allocated);
            parent.file_count = parent.file_count.saturating_add(child_files);
            parent.directory_count = parent.directory_count.saturating_add(child_directories);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn create_node(
    id: NodeId,
    parent_id: Option<NodeId>,
    path: &Path,
    root: &Path,
    metadata: &fs::Metadata,
    is_symlink: bool,
    config: &ScanConfig,
    root_device: Option<u64>,
    identities: &mut HashSet<FileIdentity>,
    counters: &mut Counters,
) -> Node {
    let kind = classify(metadata, is_symlink, config.follow_symlinks);
    let raw_name = if path == root {
        root.file_name()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| OsString::from(root.to_string_lossy().as_ref()))
    } else {
        path.file_name()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| OsString::from("?"))
    };

    let mut logical = match kind {
        EntryKind::Directory => 0,
        _ => metadata.len(),
    };
    let mut allocated = allocated_size(path, metadata);
    let mut hard_link_duplicate = false;
    if kind == EntryKind::File
        && config.deduplicate_hard_links
        && let Some(identity) = file_identity(path, metadata)
        && !identities.insert(identity)
    {
        allocated = 0;
        hard_link_duplicate = true;
        counters.hard_link_duplicates += 1;
    }

    // A followed directory symlink represents its target, while descendant entries carry the
    // target content sizes. The link itself therefore contributes no logical content bytes.
    if is_symlink && config.follow_symlinks && kind == EntryKind::Directory {
        logical = 0;
    }

    let mount_point = kind == EntryKind::Directory
        && path != root
        && root_device.is_some()
        && device_id(path, metadata) != root_device;
    let hidden = raw_name.to_string_lossy().starts_with('.');
    let modified_unix_ms = modified_ms(metadata.modified().ok());

    match kind {
        EntryKind::File => {
            counters.files += 1;
            counters.logical_bytes = counters.logical_bytes.saturating_add(logical);
            counters.allocated_bytes = counters.allocated_bytes.saturating_add(allocated);
        }
        EntryKind::Directory => {
            counters.directories += 1;
            counters.allocated_bytes = counters.allocated_bytes.saturating_add(allocated);
        }
        EntryKind::Symlink => {
            counters.symlinks += 1;
            counters.logical_bytes = counters.logical_bytes.saturating_add(logical);
            counters.allocated_bytes = counters.allocated_bytes.saturating_add(allocated);
        }
        EntryKind::Other => {
            counters.other += 1;
            counters.logical_bytes = counters.logical_bytes.saturating_add(logical);
            counters.allocated_bytes = counters.allocated_bytes.saturating_add(allocated);
        }
    }

    Node {
        id,
        parent_id,
        raw_name: raw_name.clone(),
        name: raw_name.to_string_lossy().into_owned(),
        kind,
        logical_size: logical,
        allocated_size: allocated,
        file_count: u64::from(kind == EntryKind::File),
        directory_count: 0,
        modified_unix_ms,
        hidden,
        is_symlink,
        mount_point,
        hard_link_duplicate,
    }
}

fn classify(metadata: &fs::Metadata, is_symlink: bool, followed_symlinks: bool) -> EntryKind {
    if is_symlink && !followed_symlinks {
        EntryKind::Symlink
    } else if metadata.is_file() {
        EntryKind::File
    } else if metadata.is_dir() {
        EntryKind::Directory
    } else {
        EntryKind::Other
    }
}

fn record_error(
    counters: &mut Counters,
    samples: &mut Vec<ScanErrorSample>,
    max_samples: usize,
    path: &Path,
    message: String,
) {
    counters.errors += 1;
    if samples.len() < max_samples {
        samples.push(ScanErrorSample {
            path: path.to_string_lossy().into_owned(),
            message,
        });
    }
}

fn modified_ms(modified: Option<SystemTime>) -> Option<u64> {
    modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(duration_ms)
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn absolute_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };

    // Remove `.` components without resolving symlinks or changing the meaning of `..`.
    absolute
        .components()
        .filter(|component| !matches!(component, std::path::Component::CurDir))
        .collect()
}
