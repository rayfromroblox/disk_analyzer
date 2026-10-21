use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub(crate) mod api;
mod pick;
mod targets;
mod terminal;

pub use api::{ScanManager, StartScanRequest};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::header;
use axum::middleware::{self, Next};
use axum::routing::{get, post};
use rust_embed::RustEmbed;

#[derive(Clone)]
pub struct AppState {
    pub manager: ScanManager,
    pub version: &'static str,
    pub startup_path: String,
    pub cwd: String,
}

impl AppState {
    pub fn new(version: &'static str, startup_path: String, cwd: String) -> Self {
        Self {
            manager: ScanManager::default(),
            version,
            startup_path,
            cwd,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/info", get(api::info))
        .route("/api/scans", post(api::start_scan))
        .route("/api/scans/{scan_id}", get(api::scan_status))
        .route("/api/scans/{scan_id}/cancel", post(api::cancel_scan))
        .route("/api/scans/{scan_id}/children", get(api::children))
        .route("/api/scans/{scan_id}/largest", get(api::largest))
        .route("/api/scans/{scan_id}/errors", get(api::errors))
        .route("/api/scans/{scan_id}/open", post(api::open_node))
        .route("/api/scans/{scan_id}/reveal", post(api::reveal_node))
        .route("/api/pick-folder", post(api::pick_folder))
        .fallback(static_asset)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(guard_local_request))
        .with_state(state)
}

#[derive(RustEmbed)]
#[folder = "ui-dist"]
struct Assets;

async fn static_asset(uri: axum::http::Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    let requested = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };

    if requested.starts_with("api/") || requested.contains("..") {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    match Assets::get(requested) {
        Some(file) => asset_response(requested, file.data),
        None if !requested.contains('.') => match Assets::get("index.html") {
            Some(file) => asset_response("index.html", file.data),
            None => (StatusCode::NOT_FOUND, "Web UI has not been built").into_response(),
        },
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

fn asset_response(path: &str, data: std::borrow::Cow<'static, [u8]>) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };

    let mut response = Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, cache)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_FRAME_OPTIONS, "DENY");

    if path.ends_with(".html") {
        response = response.header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'",
        );
    }

    response
        .body(Body::from(data.into_owned()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn guard_local_request(request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if let Some(host) = &host
        && !host_is_loopback(host)
    {
        return (
            StatusCode::FORBIDDEN,
            "This server only accepts loopback requests.",
        )
            .into_response();
    }

    let mutating = !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );

    if mutating
        && let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        && !origin_is_loopback(origin)
    {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin requests are not allowed.",
        )
            .into_response();
    }

    next.run(request).await
}

fn origin_is_loopback(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    host_is_loopback(host)
}

fn host_is_loopback(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };

    matches!(name, "localhost" | "127.0.0.1" | "::1")
}
