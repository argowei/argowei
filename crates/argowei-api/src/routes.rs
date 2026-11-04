use axum::extract::State;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::state::AppState;
use crate::{alerts, audit, auth, devices, discovery, groups};

/// Everything except `/api`, `/api/health` and the login/setup endpoints
/// requires a valid session. New routes belong in `protected` unless there
/// is a reason for them to be public.
pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/api", get(root))
        .route("/api/health", get(health))
        .merge(auth::public_router());

    let protected = Router::new()
        .merge(devices::router())
        .merge(discovery::router())
        .merge(groups::router())
        .merge(alerts::router())
        .merge(audit::router())
        .merge(auth::protected_router())
        .route_layer(from_fn_with_state(state.clone(), auth::require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        // Layers added later wrap earlier ones: the audit layer sees the
        // outcome of authentication, and the origin check runs first.
        .layer(from_fn_with_state(state.clone(), audit::audit_mutations))
        .layer(from_fn(auth::check_origin))
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
        Err(error) => {
            tracing::warn!(%error, "health check: database unavailable");
            "unavailable"
        }
    };

    let redis_status = match ping_redis(&state.redis).await {
        Ok(()) => "ok",
        Err(error) => {
            tracing::warn!(%error, "health check: redis unavailable");
            "unavailable"
        }
    };

    Json(json!({
        "status": "ok",
        "database": database_status,
        "redis": redis_status,
    }))
}

async fn ping_redis(client: &redis::Client) -> redis::RedisResult<()> {
    let mut connection = client.get_multiplexed_async_connection().await?;
    redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await?;
    Ok(())
}
