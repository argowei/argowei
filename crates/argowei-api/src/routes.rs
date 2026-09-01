use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api", get(root))
        .route("/api/health", get(health))
        .with_state(state)
}

async fn root() -> Json<Value> {
    Json(json!({
        "name": "Argowei API",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Reports API liveness plus DB/Redis connectivity for compose healthchecks.
async fn health(State(state): State<AppState>) -> Json<Value> {
    let database_status = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "ok",
        Err(_) => "unavailable",
    };

    let redis_status = match state.redis.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            match pong {
                Ok(_) => "ok",
                Err(_) => "unavailable",
            }
        }
        Err(_) => "unavailable",
    };

    Json(json!({
        "status": "ok",
        "database": database_status,
        "redis": redis_status,
    }))
}
