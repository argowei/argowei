//! Error type shared by API handlers: renders as a JSON `{"error": "..."}`
//! body with the matching status code.

use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::audit::Audited;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    NotFound(&'static str),
    Forbidden(&'static str),
    BadRequest(String),
    Conflict(&'static str),
    TooManyRequests {
        retry_after_secs: u64,
    },
    Unavailable,
    /// Wraps a failure the handler already wrote to the audit log, so the
    /// safety-net middleware does not add a second entry.
    Audited(Box<ApiError>),
}

impl ApiError {
    /// For failures already written to the audit log by the handler.
    pub fn audited(self) -> ApiError {
        ApiError::Audited(Box::new(self))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Audited(inner) = self {
            let mut response = inner.into_response();
            response.extensions_mut().insert(Audited);
            return response;
        }

        let (status, message) = match &self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication required".into()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, (*msg).to_owned()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, (*msg).to_owned()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, (*msg).to_owned()),
            ApiError::TooManyRequests { .. } => {
                (StatusCode::TOO_MANY_REQUESTS, "too many attempts".into())
            }
            ApiError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable".into(),
            ),
            ApiError::Audited(_) => unreachable!("handled above"),
        };

        let mut response = (status, Json(json!({ "error": message }))).into_response();
        if let ApiError::TooManyRequests { retry_after_secs } = self {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(retry_after_secs));
        }
        response
    }
}

pub fn db_error(error: sqlx::Error) -> ApiError {
    tracing::error!(%error, "database error");
    ApiError::Unavailable
}

/// A unique index rejected the write (e.g. a duplicate name).
pub fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error.as_database_error().map(|e| e.kind()),
        Some(sqlx::error::ErrorKind::UniqueViolation)
    )
}

/// A foreign key rejected the write (a referenced row is missing, or a
/// referencing row still exists).
pub fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    matches!(
        error.as_database_error().map(|e| e.kind()),
        Some(sqlx::error::ErrorKind::ForeignKeyViolation)
    )
}
