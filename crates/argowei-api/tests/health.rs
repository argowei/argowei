use argowei_api::config::Settings;
use argowei_api::routes;
use argowei_api::state::AppState;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

fn test_state() -> AppState {
    AppState::connect(&Settings::from_env())
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn root_returns_name_and_version() {
    let app = routes::router(test_state());

    let response = app
        .oneshot(Request::builder().uri("/api").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let payload = body_json(response).await;
    assert_eq!(payload["name"], "Argowei API");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn health_reports_status_and_dependency_checks() {
    let app = routes::router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let payload = body_json(response).await;
    assert_eq!(payload["status"], "ok");
    assert!(payload["database"].is_string());
}
