//! The Argowei API server: an axum app over Postgres, plus scheduled discovery.
//!
//! - [`routes`] assembles the app and its middleware (origin check, audit,
//!   authentication).
//! - [`discovery`], [`presence`], [`names`] and [`alerts`] turn scans into
//!   devices, presence, names and new-device alerts.
//! - [`devices`], [`groups`], [`alerts`], [`audit`] and [`auth`] are the HTTP
//!   resources; [`error`] and [`validate`] are shared by their handlers.
//! - [`config`] reads the environment; [`state`] holds what handlers share.

pub mod alerts;
pub mod audit;
pub mod auth;
pub mod config;
pub mod devices;
pub mod discovery;
pub mod error;
pub mod events;
pub mod groups;
pub mod names;
pub mod presence;
pub mod routes;
pub mod state;
pub mod validate;
