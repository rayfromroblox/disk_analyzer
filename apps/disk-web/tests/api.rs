use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use disk_web::{AppState, router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn app(root: &std::path::Path) -> axum::Router {
    router(AppState::new(
        "test",
        root.to_string_lossy().into_owned(),
        root.to_string_lossy().into_owned(),
    ))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn scans_and_serves_directory_data() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("nested")).unwrap();
    std::fs::write(temp.path().join("alpha.txt"), vec![b'a'; 1024]).unwrap();
    std::fs::write(temp.path().join("nested/beta.txt"), vec![b'b'; 2048]).unwrap();

    let app = app(temp.path());
    let start = app
        .clone()
        .oneshot(post_json(
            "/api/scans",
            json!({
                "path": temp.path(),
                "threads": 1,
                "followSymlinks": false,
                "stayOnFilesystem": true,
                "deduplicateHardLinks": true
            }),
        ))
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let started = body_json(start).await;
    let scan_id = started["scanId"].as_u64().unwrap();

    let status_uri = format!("/api/scans/{scan_id}");
    let mut status = Value::Null;
    for _ in 0..300 {
        let response = app.clone().oneshot(get(&status_uri)).await.unwrap();
        status = body_json(response).await;
        if status["phase"] != "scanning" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert_eq!(status["phase"], "complete");
    assert_eq!(status["summary"]["files"], 2);
    let root_id = status["rootId"].as_u64().unwrap();

    let children = app
        .clone()
        .oneshot(get(&format!(
            "/api/scans/{scan_id}/children?parentId={root_id}&metric=allocated&sort=size&descending=true&offset=0&limit=50"
        )))
        .await
        .unwrap();
    assert_eq!(children.status(), StatusCode::OK);
    let children = body_json(children).await;
    assert_eq!(children["total"], 2);
    assert!(
        children["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == "alpha.txt")
    );

    let largest = app
        .clone()
        .oneshot(get(&format!(
            "/api/scans/{scan_id}/largest?kind=file&metric=logical&limit=10"
        )))
        .await
        .unwrap();
    let largest = body_json(largest).await;
    assert_eq!(largest.as_array().unwrap().len(), 2);
    assert_eq!(largest[0]["name"], "beta.txt");
}

#[tokio::test]
async fn rejects_cross_origin_and_non_loopback_requests() {
    let temp = tempfile::tempdir().unwrap();
    let app = app(temp.path());

    let foreign_host = Request::builder()
        .uri("/api/info")
        .header(header::HOST, "files.example.com")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(foreign_host).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let foreign_origin = Request::builder()
        .method("POST")
        .uri("/api/scans")
        .header(header::HOST, "127.0.0.1:4000")
        .header(header::ORIGIN, "https://files.example.com")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "path": temp.path() }).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(foreign_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    // The Vite dev server proxies the API from a different loopback port.
    let dev_origin = Request::builder()
        .method("POST")
        .uri("/api/scans/999/cancel")
        .header(header::HOST, "127.0.0.1:4000")
        .header(header::ORIGIN, "http://127.0.0.1:1420")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(dev_origin).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}
