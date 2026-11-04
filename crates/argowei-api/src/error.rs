//! The error type of the API handlers.
//!
//! Every handler failure is an [`ApiError`], rendered as `{"error": "..."}`
//! with the matching status code. Database errors are logged with their cause
//! and reach the client only as a 503 without details: the client cannot act on
//! them, and should not learn about the schema from them.
//!
//! Some failures are worth an audit entry of their own (a failed login, a
//! denied setup). A handler that writes one returns the error wrapped with
//! [`ApiError::audited`], so the safety-net middleware in [`crate::audit`] does
//! not record the same request a second time.

use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::audit::mark_audited;

#[derive(Debug)]
pub enum ApiError {
    /// No valid session (401).
    Unauthorized,
    /// The addressed resource does not exist (404).
    NotFound(&'static str),
    /// Authenticated, or not needing authentication, but not allowed (403).
    Forbidden(&'static str),
    /// The request is malformed or fails validation (400); the message says why.
    BadRequest(String),
    /// The request clashes with the current state (409), e.g. a duplicate name.
    Conflict(&'static str),
    /// Throttled; the client may retry after the given number of seconds (429).
    TooManyRequests { retry_after_secs: u64 },
    /// A dependency (the database) failed; details are only logged (503).
    Unavailable,
    /// A failure the handler has already written to the audit log.
    Audited(Box<ApiError>),
}

impl ApiError {
    /// Marks a failure as already audited by the handler.
    pub fn audited(self) -> ApiError {
        ApiError::Audited(Box::new(self))
    }

    fn status_and_message(&self) -> (StatusCode, String) {
        match self {
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
            ApiError::Audited(inner) => inner.status_and_message(),
        }
    }

    fn retry_after(&self) -> Option<u64> {
        match self {
            ApiError::TooManyRequests { retry_after_secs } => Some(*retry_after_secs),
            ApiError::Audited(inner) => inner.retry_after(),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        let mut response = (status, Json(json!({ "error": message }))).into_response();
        if let Some(seconds) = self.retry_after() {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(seconds));
        }

        match self {
            ApiError::Audited(_) => mark_audited(response),
            _ => response,
        }
    }
}

/// Database errors are logged here, once, and answered with a bare 503. This
/// lets handlers use `?` on any query; the few that turn a specific database
/// error into something else (a duplicate name into 409) match on it first,
/// see [`is_unique_violation`] and [`is_foreign_key_violation`].
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database error");
        ApiError::Unavailable
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(error: ApiError) -> StatusCode {
        error.into_response().status()
    }

    #[test]
    fn each_error_has_its_status() {
        assert_eq!(status_of(ApiError::Unauthorized), StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(ApiError::NotFound("x")), StatusCode::NOT_FOUND);
        assert_eq!(status_of(ApiError::Forbidden("x")), StatusCode::FORBIDDEN);
        assert_eq!(
            status_of(ApiError::BadRequest("x".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status_of(ApiError::Conflict("x")), StatusCode::CONFLICT);
        assert_eq!(
            status_of(ApiError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn an_audited_error_keeps_status_and_retry_header_and_is_marked() {
        let response = ApiError::TooManyRequests {
            retry_after_secs: 7,
        }
        .audited()
        .into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "7");
        assert!(response
            .extensions()
            .get::<crate::audit::Audited>()
            .is_some());
    }

    #[test]
    fn a_plain_error_is_left_to_the_audit_middleware() {
        let response = ApiError::Forbidden("no").into_response();

        assert!(response
            .extensions()
            .get::<crate::audit::Audited>()
            .is_none());
    }
}
