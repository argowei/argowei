use std::net::SocketAddr;
use std::sync::Arc;

use argowei_api::config::Settings;
use argowei_api::discovery::{self, ArpScanner, DiscoveryConfig, InterfaceLocks};
use argowei_api::names::NamePipeline;
use argowei_api::routes;
use argowei_api::state::AppState;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let settings = Settings::from_env();
    let state = AppState::connect(&settings);
    state.auth.init_setup_token(&state.db).await;
    discovery::spawn(
        state.db.clone(),
        Arc::new(ArpScanner),
        InterfaceLocks::default(),
        state.discovery.clone(),
        DiscoveryConfig::from(&settings),
        NamePipeline::from_settings(&settings),
    );
    let app = routes::router(state).into_make_service_with_connect_info::<SocketAddr>();

    let addr = settings.bind_address;
    tracing::info!("listening on {addr}");
    let listener = TcpListener::bind(addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
