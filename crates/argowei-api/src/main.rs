//! Starts the API: reads the settings, prepares the database state (setup
//! token, baseline window), starts scheduled discovery and serves HTTP.

use std::net::SocketAddr;
use std::sync::Arc;

use argowei_api::alerts;
use argowei_api::config::Settings;
use argowei_api::discovery::{self, ArpScanner, DiscoveryConfig, InterfaceLocks};
use argowei_api::names::NamePipeline;
use argowei_api::routes;
use argowei_api::scans;
use argowei_api::state::AppState;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let settings = Settings::from_env();
    let state = AppState::connect(&settings);
    sqlx::migrate!("../../migrations")
        .run(&state.db)
        .await
        .expect("database migrations failed");
    state.auth.init_setup_token(&state.db).await;
    match scans::store::fail_interrupted(&state.db).await {
        Ok(0) => {}
        Ok(count) => tracing::warn!(count, "marked scans interrupted by the restart as failed"),
        Err(error) => tracing::error!(%error, "could not clean up interrupted scans"),
    }
    if let Err(error) = alerts::apply_baseline_window(
        &state.db,
        std::time::Duration::from_secs(settings.baseline_window_secs),
    )
    .await
    {
        tracing::warn!(%error, "could not store the baseline window; alerts use the last stored value");
    }
    discovery::spawn(
        state.db.clone(),
        Arc::new(ArpScanner),
        InterfaceLocks::default(),
        state.discovery.clone(),
        DiscoveryConfig::from(&settings),
        NamePipeline::from_settings(&settings),
    );
    scans::scheduler::spawn(
        state.db.clone(),
        state.scans.clone(),
        state.schedule_changed.clone(),
    );
    let app = routes::router(state).into_make_service_with_connect_info::<SocketAddr>();

    let addr = settings.bind_address;
    tracing::info!("listening on {addr}");
    let listener = TcpListener::bind(addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
