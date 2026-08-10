#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::process::Command;

use disk_core::{
    CancellationToken, EntryKind, Node, NodeId, ScanConfig, ScanErrorSample, ScanProgress,
    ScanResult, ScanSummary, SizeMetric, scan,
};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

#[derive(Default)]
struct ScanManager {
    inner: Arc<Mutex<ScanState>>,
}

#[derive(Default)]
struct ScanState {
    next_id: u64,
    active_id: Option<u64>,
    running: bool,
    cancellation: Option<CancellationToken>,
    progress: Option<ScanProgress>,
    result: Option<Arc<ScanResult>>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartScanRequest {
    path: String,
    threads: usize,
    follow_symlinks: bool,
    stay_on_filesystem: bool,
    deduplicate_hard_links: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanIdRequest {
    scan_id: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeRequest {
    scan_id: u64,
    node_id: NodeId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChildrenRequest {
    scan_id: u64,
    parent_id: NodeId,
    metric: MetricRequest,
    sort: SortRequest,
    descending: bool,
    query: String,
    offset: usize,
    limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LargestRequest {
    scan_id: u64,
    kind: EntryKindRequest,
    metric: MetricRequest,
    limit: usize,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MetricRequest {
    Logical,
    Allocated,
}

impl From<MetricRequest> for SizeMetric {
    fn from(value: MetricRequest) -> Self {
        match value {
            MetricRequest::Logical => Self::Logical,
            MetricRequest::Allocated => Self::Allocated,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SortRequest {
    Size,
    Name,
    Files,
    Directories,
    Modified,
    Kind,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EntryKindRequest {
    File,
    Directory,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanStatus {
    scan_id: u64,
    phase: &'static str,
    progress: Option<ScanProgress>,
    summary: Option<ScanSummary>,
    root_id: Option<NodeId>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeView {
    id: NodeId,
    parent_id: Option<NodeId>,
    name: String,
    path: String,
    kind: EntryKind,
    logical_size: u64,
    allocated_size: u64,
    file_count: u64,
    directory_count: u64,
    modified_unix_ms: Option<u64>,
    hidden: bool,
    is_symlink: bool,
    mount_point: bool,
    hard_link_duplicate: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChildPage {
    parent: NodeView,
    items: Vec<NodeView>,
    total: usize,
    offset: usize,
    limit: usize,
}

#[tauri::command]
fn default_path() -> String {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .to_string_lossy()
        .into_owned()
}

#[tauri::command]
fn choose_directory(current: Option<String>) -> Option<String> {
    let mut dialog = rfd::FileDialog::new().set_title("Choose a directory to analyze");
    if let Some(current) = current.filter(|path| !path.trim().is_empty()) {
        dialog = dialog.set_directory(current);
    }
    dialog
        .pick_folder()
        .map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
fn start_scan(request: StartScanRequest, manager: State<'_, ScanManager>) -> Result<u64, String> {
    let path = request.path.trim();
    if path.is_empty() {
        return Err("Choose a directory before starting a scan.".to_owned());
    }

    let mut config = ScanConfig::new(path);
    config.threads = request.threads;
    config.follow_symlinks = request.follow_symlinks;
    config.stay_on_filesystem = request.stay_on_filesystem;
    config.deduplicate_hard_links = request.deduplicate_hard_links;

    let cancellation = CancellationToken::new();
    let scan_id = {
        let mut state = manager
            .inner
            .lock()
            .map_err(|_| "scan state lock was poisoned".to_owned())?;
        if let Some(previous) = state.cancellation.take() {
            previous.cancel();
        }
        state.next_id = state.next_id.saturating_add(1).max(1);
        let id = state.next_id;
        state.active_id = Some(id);
        state.running = true;
        state.cancellation = Some(cancellation.clone());
        state.progress = None;
        state.result = None;
        state.error = None;
        id
    };

    let shared = Arc::clone(&manager.inner);
    std::thread::spawn(move || {
        let progress_state = Arc::clone(&shared);
        let result = scan(config, cancellation, move |progress| {
            if let Ok(mut state) = progress_state.lock()
                && state.active_id == Some(scan_id)
            {
                state.progress = Some(progress.clone());
            }
        });

        if let Ok(mut state) = shared.lock()
            && state.active_id == Some(scan_id)
        {
            state.running = false;
            state.cancellation = None;
            match result {
                Ok(result) => state.result = Some(Arc::new(result)),
                Err(error) => state.error = Some(error.to_string()),
            }
        }
    });

    Ok(scan_id)
}

#[tauri::command]
fn cancel_scan(request: ScanIdRequest, manager: State<'_, ScanManager>) -> Result<(), String> {
    let state = manager
        .inner
        .lock()
        .map_err(|_| "scan state lock was poisoned".to_owned())?;
    ensure_scan_id(&state, request.scan_id)?;
    if let Some(cancellation) = &state.cancellation {
        cancellation.cancel();
    }
    Ok(())
}

#[tauri::command]
fn scan_status(
    request: ScanIdRequest,
    manager: State<'_, ScanManager>,
) -> Result<ScanStatus, String> {
    let state = manager
        .inner
        .lock()
        .map_err(|_| "scan state lock was poisoned".to_owned())?;
    ensure_scan_id(&state, request.scan_id)?;
    let phase = if state.running {
        "scanning"
    } else if state.error.is_some() {
        "error"
    } else if state.result.is_some() {
        "complete"
    } else {
        "idle"
    };
    Ok(ScanStatus {
        scan_id: request.scan_id,
        phase,
        progress: state.progress.clone(),
        summary: state.result.as_ref().map(|result| result.summary.clone()),
        root_id: state.result.as_ref().map(|result| result.root_id),
        error: state.error.clone(),
    })
}

#[tauri::command]
fn get_children(
    request: ChildrenRequest,
    manager: State<'_, ScanManager>,
) -> Result<ChildPage, String> {
    let result = result_for(&manager, request.scan_id)?;
    let parent = result
        .node(request.parent_id)
        .ok_or_else(|| "directory no longer exists in this scan".to_owned())?;
    if parent.kind != EntryKind::Directory {
        return Err("selected entry is not a directory".to_owned());
    }

    let metric: SizeMetric = request.metric.into();
    let query = request.query.to_lowercase();
    let mut children: Vec<&Node> = result
        .children_of(request.parent_id)
        .filter(|node| query.is_empty() || node.name.to_lowercase().contains(&query))
        .collect();
    children.sort_unstable_by(|left, right| {
        let ordering = match request.sort {
            SortRequest::Size => left.size(metric).cmp(&right.size(metric)),
            SortRequest::Name => left.name.to_lowercase().cmp(&right.name.to_lowercase()),
            SortRequest::Files => left.file_count.cmp(&right.file_count),
            SortRequest::Directories => left.directory_count.cmp(&right.directory_count),
            SortRequest::Modified => left.modified_unix_ms.cmp(&right.modified_unix_ms),
            SortRequest::Kind => left.kind.label().cmp(right.kind.label()),
        };
        let ordering = if request.descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });

    let total = children.len();
    let offset = request.offset.min(total);
    let limit = request.limit.clamp(1, 1_000);
    let items = children
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|node| node_view(&result, node))
        .collect();
    Ok(ChildPage {
        parent: node_view(&result, parent),
        items,
        total,
        offset,
        limit,
    })
}

#[tauri::command]
fn get_largest(
    request: LargestRequest,
    manager: State<'_, ScanManager>,
) -> Result<Vec<NodeView>, String> {
    let result = result_for(&manager, request.scan_id)?;
    let kind = match request.kind {
        EntryKindRequest::File => EntryKind::File,
        EntryKindRequest::Directory => EntryKind::Directory,
    };
    Ok(result
        .largest(
            Some(kind),
            request.metric.into(),
            request.limit.clamp(1, 500),
        )
        .into_iter()
        .map(|node| node_view(&result, node))
        .collect())
}

#[tauri::command]
fn get_errors(
    request: ScanIdRequest,
    manager: State<'_, ScanManager>,
) -> Result<Vec<ScanErrorSample>, String> {
    Ok(result_for(&manager, request.scan_id)?.error_samples.clone())
}

#[tauri::command]
fn open_node(request: NodeRequest, manager: State<'_, ScanManager>) -> Result<(), String> {
    let result = result_for(&manager, request.scan_id)?;
    let path = result
        .path_for(request.node_id)
        .ok_or_else(|| "entry no longer exists in this scan".to_owned())?;
    open::that(path).map_err(|error| error.to_string())
}

#[tauri::command]
fn reveal_node(request: NodeRequest, manager: State<'_, ScanManager>) -> Result<(), String> {
    let result = result_for(&manager, request.scan_id)?;
    let node = result
        .node(request.node_id)
        .ok_or_else(|| "entry no longer exists in this scan".to_owned())?;
    let path = result
        .path_for(request.node_id)
        .ok_or_else(|| "entry path could not be reconstructed".to_owned())?;

    if node.kind == EntryKind::Directory {
        return open::that(path).map_err(|error| error.to_string());
    }
    reveal_file(&path)
}

fn ensure_scan_id(state: &ScanState, scan_id: u64) -> Result<(), String> {
    (state.active_id == Some(scan_id))
        .then_some(())
        .ok_or_else(|| "that scan is no longer active".to_owned())
}

fn result_for(manager: &State<'_, ScanManager>, scan_id: u64) -> Result<Arc<ScanResult>, String> {
    let state = manager
        .inner
        .lock()
        .map_err(|_| "scan state lock was poisoned".to_owned())?;
    ensure_scan_id(&state, scan_id)?;
    state
        .result
        .clone()
        .ok_or_else(|| "scan results are not ready".to_owned())
}

fn node_view(result: &ScanResult, node: &Node) -> NodeView {
    NodeView {
        id: node.id,
        parent_id: node.parent_id,
        name: node.name.clone(),
        path: result
            .display_path(node.id)
            .unwrap_or_else(|| node.name.clone()),
        kind: node.kind,
        logical_size: node.logical_size,
        allocated_size: node.allocated_size,
        file_count: node.file_count,
        directory_count: node.directory_count,
        modified_unix_ms: node.modified_unix_ms,
        hidden: node.hidden,
        is_symlink: node.is_symlink,
        mount_point: node.mount_point,
        hard_link_duplicate: node.hard_link_duplicate,
    }
}

#[cfg(target_os = "windows")]
fn reveal_file(path: &std::path::Path) -> Result<(), String> {
    Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn reveal_file(path: &std::path::Path) -> Result<(), String> {
    Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn reveal_file(path: &std::path::Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or(path);
    open::that(parent).map_err(|error| error.to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(ScanManager::default())
        .invoke_handler(tauri::generate_handler![
            default_path,
            choose_directory,
            start_scan,
            cancel_scan,
            scan_status,
            get_children,
            get_largest,
            get_errors,
            open_node,
            reveal_node,
        ])
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                window.set_focus()?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to run Disk Analyzer");
}
