use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use disk_core::{
    CancellationToken, EntryKind, Node, NodeId, ScanConfig, ScanErrorSample, ScanProgress,
    ScanResult, ScanSummary, SizeMetric, scan,
};
use serde::{Deserialize, Serialize};

use crate::targets::{self, ScanTarget};
use crate::{AppState, pick, terminal};

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

#[derive(Clone, Default)]
pub struct ScanManager {
    inner: Arc<Mutex<ManagerState>>,
}

#[derive(Default)]
struct ManagerState {
    next_id: u64,
    active_id: Option<u64>,
    running: bool,
    cancellation: Option<CancellationToken>,
    progress: Option<ScanProgress>,
    result: Option<Arc<ScanResult>>,
    error: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartScanRequest {
    pub path: String,
    #[serde(default)]
    pub threads: usize,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default = "default_true")]
    pub stay_on_filesystem: bool,
    #[serde(default = "default_true")]
    pub deduplicate_hard_links: bool,
}

fn default_true() -> bool {
    true
}

impl StartScanRequest {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            threads: 0,
            follow_symlinks: false,
            stay_on_filesystem: true,
            deduplicate_hard_links: true,
        }
    }
}

impl ScanManager {
    pub fn start(&self, request: StartScanRequest) -> Result<u64, ApiError> {
        let root = resolve_directory(&request.path)?;
        let display_path = root.to_string_lossy().into_owned();

        let mut config = ScanConfig::new(&root);
        config.threads = request.threads;
        config.follow_symlinks = request.follow_symlinks;
        config.stay_on_filesystem = request.stay_on_filesystem;
        config.deduplicate_hard_links = request.deduplicate_hard_links;

        let cancellation = CancellationToken::new();
        let scan_id = {
            let mut state = self.lock()?;
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
            state.path = Some(display_path.clone());
            id
        };

        let shared = Arc::clone(&self.inner);
        std::thread::Builder::new()
            .name("disk-scan".to_owned())
            .spawn(move || {
                terminal::scan_started(&display_path);
                let progress_state = Arc::clone(&shared);
                let result = scan(config, cancellation, move |progress| {
                    let active = if let Ok(mut state) = progress_state.lock()
                        && state.active_id == Some(scan_id)
                    {
                        state.progress = Some(progress.clone());
                        true
                    } else {
                        false
                    };
                    if active {
                        terminal::progress(progress);
                    }
                });

                let (summary, failure) = {
                    let Ok(mut state) = shared.lock() else {
                        return;
                    };
                    if state.active_id != Some(scan_id) {
                        return;
                    }
                    state.running = false;
                    state.cancellation = None;
                    match result {
                        Ok(result) => {
                            let summary = result.summary.clone();
                            state.result = Some(Arc::new(result));
                            (Some(summary), None)
                        }
                        Err(error) => {
                            let message = error.to_string();
                            state.error = Some(message.clone());
                            (None, Some(message))
                        }
                    }
                };

                match (summary, failure) {
                    (Some(summary), _) => terminal::scan_finished(&summary),
                    (_, Some(error)) => terminal::scan_failed(&error),
                    _ => {}
                }
            })
            .map_err(|error| ApiError::internal(format!("could not start scanner: {error}")))?;

        Ok(scan_id)
    }

    pub fn cancel(&self, scan_id: u64) -> Result<(), ApiError> {
        let state = self.lock()?;
        ensure_scan_id(&state, scan_id)?;
        if let Some(cancellation) = &state.cancellation {
            cancellation.cancel();
        }
        Ok(())
    }

    pub fn cancel_active(&self) {
        if let Ok(state) = self.inner.lock()
            && let Some(cancellation) = &state.cancellation
        {
            cancellation.cancel();
        }
    }

    fn status(&self, scan_id: u64) -> Result<ScanStatus, ApiError> {
        let state = self.lock()?;
        ensure_scan_id(&state, scan_id)?;
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
            scan_id,
            phase,
            progress: state.progress.clone(),
            summary: state.result.as_ref().map(|result| result.summary.clone()),
            root_id: state.result.as_ref().map(|result| result.root_id),
            error: state.error.clone(),
        })
    }

    fn result(&self, scan_id: u64) -> Result<Arc<ScanResult>, ApiError> {
        let state = self.lock()?;
        ensure_scan_id(&state, scan_id)?;
        state
            .result
            .clone()
            .ok_or_else(|| ApiError::conflict("scan results are not ready"))
    }

    fn active_id(&self) -> Option<u64> {
        self.inner.lock().ok().and_then(|state| state.active_id)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ManagerState>, ApiError> {
        self.inner
            .lock()
            .map_err(|_| ApiError::internal("scan state lock was poisoned"))
    }
}

fn resolve_directory(input: &str) -> Result<PathBuf, ApiError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(
            "Choose a directory before starting a scan.",
        ));
    }

    let expanded = expand_tilde(trimmed);
    let path = Path::new(&expanded);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ApiError::internal(error.to_string()))?
            .join(path)
    };

    if !absolute.is_dir() {
        return Err(ApiError::bad_request(format!(
            "{} is not a directory.",
            absolute.display()
        )));
    }

    Ok(absolute)
}

fn expand_tilde(path: &str) -> String {
    if (path == "~" || path.starts_with("~/") || path.starts_with("~\\"))
        && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    {
        let home = PathBuf::from(home);
        if path == "~" {
            return home.to_string_lossy().into_owned();
        }
        return home
            .join(path.trim_start_matches('~').trim_start_matches(['/', '\\']))
            .to_string_lossy()
            .into_owned();
    }

    path.to_owned()
}

fn ensure_scan_id(state: &ManagerState, scan_id: u64) -> Result<(), ApiError> {
    if state.active_id == Some(scan_id) {
        Ok(())
    } else {
        Err(ApiError::not_found(
            "That scan is no longer active. Start a new scan.",
        ))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InfoResponse {
    version: &'static str,
    default_path: String,
    cwd: String,
    active_scan_id: Option<u64>,
    scan_targets: Vec<ScanTarget>,
    platform: &'static str,
}

pub(crate) async fn info(State(state): State<AppState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        version: state.version,
        default_path: state.startup_path.clone(),
        cwd: state.cwd.clone(),
        active_scan_id: state.manager.active_id(),
        scan_targets: targets::scan_targets(&state.startup_path),
        platform: std::env::consts::OS,
    })
}

pub(crate) async fn start_scan(
    State(state): State<AppState>,
    Json(request): Json<StartScanRequest>,
) -> Result<Json<StartScanResponse>, ApiError> {
    let scan_id = state.manager.start(request)?;
    Ok(Json(StartScanResponse { scan_id }))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartScanResponse {
    scan_id: u64,
}

pub(crate) async fn scan_status(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
) -> Result<Json<ScanStatus>, ApiError> {
    Ok(Json(state.manager.status(scan_id)?))
}

pub(crate) async fn cancel_scan(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
) -> Result<StatusCode, ApiError> {
    state.manager.cancel(scan_id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanStatus {
    scan_id: u64,
    phase: &'static str,
    progress: Option<ScanProgress>,
    summary: Option<ScanSummary>,
    root_id: Option<NodeId>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MetricParam {
    Logical,
    #[default]
    Allocated,
}

impl From<MetricParam> for SizeMetric {
    fn from(value: MetricParam) -> Self {
        match value {
            MetricParam::Logical => Self::Logical,
            MetricParam::Allocated => Self::Allocated,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SortParam {
    #[default]
    Size,
    Name,
    Files,
    Directories,
    Modified,
    Kind,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EntryKindParam {
    File,
    Directory,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChildrenQuery {
    parent_id: NodeId,
    #[serde(default)]
    metric: MetricParam,
    #[serde(default)]
    sort: SortParam,
    #[serde(default = "default_true")]
    descending: bool,
    #[serde(default)]
    query: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_page_size")]
    limit: usize,
}

fn default_page_size() -> usize {
    200
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeView {
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
pub(crate) struct ChildPage {
    parent: NodeView,
    items: Vec<NodeView>,
    total: usize,
    offset: usize,
    limit: usize,
}

pub(crate) async fn children(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
    Query(request): Query<ChildrenQuery>,
) -> Result<Json<ChildPage>, ApiError> {
    let result = state.manager.result(scan_id)?;
    let parent = result
        .node(request.parent_id)
        .ok_or_else(|| ApiError::not_found("That folder no longer exists in this scan."))?;
    if parent.kind != EntryKind::Directory {
        return Err(ApiError::bad_request(
            "The selected entry is not a directory.",
        ));
    }

    let metric: SizeMetric = request.metric.into();
    let query = request.query.to_lowercase();
    let mut children: Vec<&Node> = result
        .children_of(request.parent_id)
        .filter(|node| query.is_empty() || node.name.to_lowercase().contains(&query))
        .collect();

    children.sort_unstable_by(|left, right| {
        let ordering = match request.sort {
            SortParam::Size => left.size(metric).cmp(&right.size(metric)),
            SortParam::Name => left.name.to_lowercase().cmp(&right.name.to_lowercase()),
            SortParam::Files => left.file_count.cmp(&right.file_count),
            SortParam::Directories => left.directory_count.cmp(&right.directory_count),
            SortParam::Modified => left.modified_unix_ms.cmp(&right.modified_unix_ms),
            SortParam::Kind => left.kind.label().cmp(right.kind.label()),
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

    Ok(Json(ChildPage {
        parent: node_view(&result, parent),
        items,
        total,
        offset,
        limit,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LargestQuery {
    kind: EntryKindParam,
    #[serde(default)]
    metric: MetricParam,
    #[serde(default = "default_largest_limit")]
    limit: usize,
}

fn default_largest_limit() -> usize {
    100
}

pub(crate) async fn largest(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
    Query(request): Query<LargestQuery>,
) -> Result<Json<Vec<NodeView>>, ApiError> {
    let result = state.manager.result(scan_id)?;
    let kind = match request.kind {
        EntryKindParam::File => EntryKind::File,
        EntryKindParam::Directory => EntryKind::Directory,
    };

    Ok(Json(
        result
            .largest(
                Some(kind),
                request.metric.into(),
                request.limit.clamp(1, 500),
            )
            .into_iter()
            .map(|node| node_view(&result, node))
            .collect(),
    ))
}

pub(crate) async fn errors(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
) -> Result<Json<Vec<ScanErrorSample>>, ApiError> {
    Ok(Json(state.manager.result(scan_id)?.error_samples.clone()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeRequest {
    node_id: NodeId,
}

pub(crate) async fn open_node(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
    Json(request): Json<NodeRequest>,
) -> Result<StatusCode, ApiError> {
    let result = state.manager.result(scan_id)?;
    let path = result
        .path_for(request.node_id)
        .ok_or_else(|| ApiError::not_found("That entry no longer exists in this scan."))?;
    open::that(path)
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(|error| ApiError::internal(error.to_string()))
}

pub(crate) async fn reveal_node(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<u64>,
    Json(request): Json<NodeRequest>,
) -> Result<StatusCode, ApiError> {
    let result = state.manager.result(scan_id)?;
    let node = result
        .node(request.node_id)
        .ok_or_else(|| ApiError::not_found("That entry no longer exists in this scan."))?;
    let path = result
        .path_for(request.node_id)
        .ok_or_else(|| ApiError::not_found("That entry path could not be reconstructed."))?;

    if node.kind == EntryKind::Directory {
        open::that(path)
            .map(|_| StatusCode::NO_CONTENT)
            .map_err(|error| ApiError::internal(error.to_string()))
    } else {
        reveal_file(&path)
            .map(|_| StatusCode::NO_CONTENT)
            .map_err(ApiError::internal)
    }
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PickFolderResponse {
    path: Option<String>,
}

pub(crate) async fn pick_folder() -> Result<Json<PickFolderResponse>, ApiError> {
    let path = tokio::task::spawn_blocking(pick::choose_directory)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map_err(ApiError::internal)?;
    Ok(Json(PickFolderResponse { path }))
}

#[cfg(target_os = "windows")]
fn reveal_file(path: &Path) -> Result<(), String> {
    std::process::Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn reveal_file(path: &Path) -> Result<(), String> {
    std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn reveal_file(path: &Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or(path);
    open::that(parent).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_home_shortcuts() {
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"));
        if let Ok(home) = home {
            let documents = PathBuf::from(&home).join("Documents");
            assert_eq!(expand_tilde("~"), home);
            assert_eq!(PathBuf::from(expand_tilde("~/Documents")), documents);
        }
    }

    #[test]
    fn rejects_empty_scan_paths() {
        assert!(resolve_directory("   ").is_err());
    }
}
