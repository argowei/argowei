use argowei_api::config::Settings;
use argowei_api::routes;
use argowei_api::state::AppState;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn test_state() -> AppState {
    AppState::connect(&Settings {
        bind_address: "127.0.0.1:8000".parse().unwrap(),
        postgres_user: "argowei".to_string(),
        postgres_password: "argowei".to_string(),
        postgres_db: "argowei".to_string(),
        postgres_host: "127.0.0.1".to_string(),
        postgres_port: 1,
        cookie_secure: false,
        session_ttl_hours: 24,
        discovery_interfaces: Vec::new(),
        discovery_interval_secs: 300,
        discovery_timeout_secs: 3,
        hostname_sources: Vec::new(),
        dhcp_leases_file: None,
        dns_server: None,
        hostname_timeout_ms: 1000,
        hostname_refresh_secs: 3600,
        hostname_concurrency: 16,
        offline_after_missed_scans: 3,
        offline_after_secs: 900,
        baseline_window_secs: 0,
        nmap_path: "nmap".to_string(),
        scan_concurrency: 2,
        scan_targets: Default::default(),
        scan_max_secs: 0,
    })
}

#[tokio::test]
async fn list_devices_reports_service_unavailable_without_a_database() {
    // The test state points at an intentionally invalid Postgres port. This
    // keeps the error-path assertion stable even if a local dev database is
    // running on the default port.
    let app = routes::router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/devices")
                // A session cookie makes the auth layer query the database,
                // which is the unavailable dependency under test.
                .header("cookie", "argowei_session=any")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
