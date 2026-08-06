use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct Device {
    pub id: i32,
    pub name: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub is_online: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}
