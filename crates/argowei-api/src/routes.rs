//! The HTTP app: which routes need a session, and the middleware order.

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
        // Layers added later wrap earlier ones, so a request passes
        // check_origin -> audit_mutations -> require_auth -> handler:
        // - the origin check runs first: a cross-origin write is refused
        //   before anything else and is not audited (it is nobody's action,
        //   and any web page could otherwise fill the audit log);
        // - the audit layer wraps authentication, so requests denied there
        //   (401) are recorded, attributed via the user extension that
        //   require_auth puts on the response.
        // Pinned by `middleware_runs_origin_check_then_audit_then_auth`.
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

/// Reports API liveness and database connectivity.
async fn health(State(state): State<AppState>) -> Json<Value> {
    let database_status = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "ok",
        Err(error) => {
            tracing::warn!(%error, "health check: database unavailable");
            "unavailable"
        }
    };

    Json(json!({
        "status": "ok",
        "database": database_status,
    }))
}
