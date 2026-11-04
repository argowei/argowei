//! Looking up and storing device names: priority between sources, the user's
//! label, how rarely devices are asked, and that no lookup problem reaches a
//! discovery run.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use argowei_api::names::{after_scan, resolve_pending, NameLookup, NamePipeline, NamesError};
use argowei_collector::names::{NameSource, ResolvedName, Target, TargetNames};
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

const REFRESH: Duration = Duration::from_secs(3600);

const PHONE: &str = "aa:bb:cc:00:00:01";
const PRINTER: &str = "aa:bb:cc:00:00:02";

type Answer = Box<dyn Fn(&Target) -> TargetNames + Send + Sync>;

/// Answers lookups from a closure and records every batch it was asked.
struct FakeLookup {
    answer: Answer,
    batches: Mutex<Vec<Vec<Target>>>,
}

impl FakeLookup {
    fn new(answer: impl Fn(&Target) -> TargetNames + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            answer: Box::new(answer),
            batches: Mutex::new(Vec::new()),
        })
    }

    fn batches(&self) -> Vec<Vec<Target>> {
        self.batches.lock().unwrap().clone()
    }

    fn asked(&self) -> usize {
        self.batches().iter().map(Vec::len).sum()
    }
}

impl NameLookup for FakeLookup {
    fn lookup(&self, targets: &[Target]) -> Vec<TargetNames> {
        self.batches.lock().unwrap().push(targets.to_vec());
        targets.iter().map(|t| (self.answer)(t)).collect()
    }
}

fn answers(target: &Target, names: &[(NameSource, &str)]) -> TargetNames {
    TargetNames {
        target: target.clone(),
        names: names
            .iter()
            .map(|(source, name)| ResolvedName {
                source: *source,
                name: (*name).to_owned(),
            })
            .collect(),
        errors: Vec::new(),
    }
}

fn pipeline(lookup: Arc<FakeLookup>) -> NamePipeline {
    NamePipeline {
        lookup,
        refresh: REFRESH,
    }
}

async fn resolve(
    h: &Harness,
    lookup: &Arc<FakeLookup>,
    at: DateTime<Utc>,
) -> argowei_api::names::NamesSummary {
    resolve_pending(&h.pool, &pipeline(Arc::clone(lookup)), "eth0", at)
        .await
        .unwrap()
}

// --- storing and choosing ---------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_new_device_is_named_after_its_scan(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    assert_eq!(
        device_json(&h, &cookie, PHONE).await["name"],
        PHONE,
        "starts as the MAC"
    );
    assert!(device_json(&h, &cookie, PHONE).await["name_source"].is_null());

    let lookup = FakeLookup::new(|t| answers(t, &[(NameSource::Mdns, "Annas-iPhone")]));
    let summary = resolve(&h, &lookup, t0()).await;

    assert_eq!((summary.looked_up, summary.renamed), (1, 1));
    let d = device_json(&h, &cookie, PHONE).await;
    assert_eq!(d["name"], "Annas-iPhone");
    assert_eq!(d["name_source"], "mdns");
    assert_eq!(
        d["display_name"], "Annas-iPhone",
        "shown instead of the MAC"
    );
    assert_eq!(d["names"].as_array().unwrap().len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_lookup_is_given_the_devices_address_and_mac(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(5, PHONE), host(6, PRINTER)], t0()).await;

    let lookup = FakeLookup::new(|t| answers(t, &[]));
    resolve(&h, &lookup, t0()).await;

    let batch = &lookup.batches()[0];
    assert_eq!(batch.len(), 2);
    assert_eq!(
        (batch[0].ip.to_string(), batch[0].mac.as_str()),
        ("192.168.1.5".into(), PHONE)
    );
    assert_eq!(
        (batch[1].ip.to_string(), batch[1].mac.as_str()),
        ("192.168.1.6".into(), PRINTER)
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn when_sources_disagree_the_highest_priority_wins_and_all_answers_are_kept(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;

    let lookup = FakeLookup::new(|t| {
        answers(
            t,
            &[
                (NameSource::Rdns, "anna.lan"),
                (NameSource::Netbios, "ANNA-PC"),
                (NameSource::Mdns, "Annas-iPhone"),
                (NameSource::Dhcp, "anna"),
            ],
        )
    });
    resolve(&h, &lookup, t0()).await;

    let d = device_json(&h, &cookie, PHONE).await;
    assert_eq!(
        (d["name"].as_str(), d["name_source"].as_str()),
        (Some("anna"), Some("dhcp"))
    );
    let sources: Vec<(&str, &str)> = d["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["source"].as_str().unwrap(), n["name"].as_str().unwrap()))
        .collect();
    assert_eq!(
        sources,
        [
            ("dhcp", "anna"),
            ("mdns", "Annas-iPhone"),
            ("netbios", "ANNA-PC"),
            ("rdns", "anna.lan")
        ],
        "every source's answer is kept, preferred first"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_manual_label_always_wins_over_discovered_names(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    let id = device_json(&h, &cookie, PHONE).await["id"]
        .as_i64()
        .unwrap();
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{id}"),
        Some(&cookie),
        Some(json!({ "label": "Mein Handy" })),
    )
    .await;

    let lookup = FakeLookup::new(|t| {
        answers(
            t,
            &[
                (NameSource::Dhcp, "anna"),
                (NameSource::Mdns, "Annas-iPhone"),
            ],
        )
    });
    resolve(&h, &lookup, t0()).await;
    // A name that changes later does not dislodge the label either.
    let renamed = FakeLookup::new(|t| answers(t, &[(NameSource::Dhcp, "annas-new-phone")]));
    resolve(&h, &renamed, t0() + ChronoDuration::hours(2)).await;

    let d = device_json(&h, &cookie, PHONE).await;
    assert_eq!(d["label"], "Mein Handy");
    assert_eq!(d["display_name"], "Mein Handy");
    assert_eq!(
        d["name"], "annas-new-phone",
        "the discovered name is tracked underneath"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_changed_name_updates_and_is_recorded_once(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    resolve(
        &h,
        &FakeLookup::new(|t| answers(t, &[(NameSource::Mdns, "iPhone")])),
        t0(),
    )
    .await;

    let later = t0() + ChronoDuration::hours(2);
    let renamed = FakeLookup::new(|t| answers(t, &[(NameSource::Mdns, "Annas-iPhone")]));
    scan(&h, &[host(5, PHONE)], later).await;
    resolve(&h, &renamed, later).await;
    // Looked up again with the same answer: nothing new to record.
    let again = later + ChronoDuration::hours(2);
    scan(&h, &[host(5, PHONE)], again).await;
    resolve(&h, &renamed, again).await;

    assert_eq!(
        device_json(&h, &cookie, PHONE).await["name"],
        "Annas-iPhone"
    );
    let events: Vec<Value> =
        sqlx::query_scalar("SELECT payload FROM events WHERE type = 'device.named' ORDER BY id")
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        events.len(),
        2,
        "naming it, then renaming it; the repeat adds nothing"
    );
    assert_eq!(
        (events[0]["from"].as_str(), events[0]["to"].as_str()),
        (Some(PHONE), Some("iPhone"))
    );
    assert_eq!(
        (events[1]["from"].as_str(), events[1]["to"].as_str()),
        (Some("iPhone"), Some("Annas-iPhone"))
    );
    assert_eq!(events[1]["source"], "mdns");
    assert_eq!(
        events[1]["answers"],
        json!([{ "source": "mdns", "name": "Annas-iPhone" }])
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_source_that_stops_answering_keeps_its_last_name(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    resolve(
        &h,
        &FakeLookup::new(|t| {
            answers(
                t,
                &[
                    (NameSource::Mdns, "Annas-iPhone"),
                    (NameSource::Rdns, "anna.lan"),
                ],
            )
        }),
        t0(),
    )
    .await;

    let later = t0() + ChronoDuration::hours(2);
    scan(&h, &[host(5, PHONE)], later).await;
    resolve(
        &h,
        &FakeLookup::new(|t| answers(t, &[(NameSource::Rdns, "anna.lan")])),
        later,
    )
    .await;

    let d = device_json(&h, &cookie, PHONE).await;
    assert_eq!(
        d["name"], "Annas-iPhone",
        "a sleeping phone does not lose its name"
    );
    assert_eq!(d["names"].as_array().unwrap().len(), 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn names_from_the_network_are_checked_before_they_are_stored(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;

    let lookup = FakeLookup::new(|t| {
        answers(
            t,
            &[
                (NameSource::Dhcp, "bad\nname"),
                (NameSource::Mdns, "192-168-1-5.lan"),
                (NameSource::Netbios, "localhost"),
                (NameSource::Rdns, "anna.lan"),
            ],
        )
    });
    resolve(&h, &lookup, t0()).await;

    let d = device_json(&h, &cookie, PHONE).await;
    assert_eq!(
        d["names"].as_array().unwrap().len(),
        1,
        "only the usable answer is kept"
    );
    assert_eq!(
        (d["name"].as_str(), d["name_source"].as_str()),
        (Some("anna.lan"), Some("rdns"))
    );
}

// --- failures never reach a discovery run ----------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn resolver_failures_leave_the_device_alone_and_are_counted(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;

    let failing = FakeLookup::new(|t| TargetNames {
        target: t.clone(),
        names: Vec::new(),
        errors: vec![
            (NameSource::Mdns, "I/O error".into()),
            (NameSource::Rdns, "boom".into()),
        ],
    });
    let summary = resolve(&h, &failing, t0()).await;

    assert_eq!(
        (summary.looked_up, summary.renamed, summary.resolver_errors),
        (1, 0, 2)
    );
    assert_eq!(device_json(&h, &cookie, PHONE).await["name"], PHONE);
    let checked: bool = sqlx::query_scalar("SELECT names_checked_at IS NOT NULL FROM devices")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert!(
        checked,
        "a failed attempt still counts, so it is not repeated every scan"
    );
}

struct PanickingLookup;

impl NameLookup for PanickingLookup {
    fn lookup(&self, _: &[Target]) -> Vec<TargetNames> {
        panic!("resolver bug");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_lookup_that_panics_does_not_disturb_the_scan_or_the_database(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    let crashing = NamePipeline {
        lookup: Arc::new(PanickingLookup),
        refresh: REFRESH,
    };

    // The step reports the failure to its caller ...
    let error = resolve_pending(&h.pool, &crashing, "eth0", t0())
        .await
        .unwrap_err();
    assert!(matches!(error, NamesError::Task(_)));
    // ... and the step the scheduler actually runs swallows it.
    after_scan(&h.pool, &crashing, "eth0").await;

    assert_eq!(device_json(&h, &cookie, PHONE).await["name"], PHONE);
    let scans: i64 = sqlx::query_scalar("SELECT count(*) FROM discovery_scans")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(scans, 1, "the stored scan is untouched");
}

// --- efficiency --------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn only_devices_the_latest_scan_saw_are_asked(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    scan(&h, &[host(6, PRINTER)], t0() + minutes(5)).await;

    let lookup = FakeLookup::new(|t| answers(t, &[]));
    resolve(&h, &lookup, t0() + minutes(5)).await;

    let batches = lookup.batches();
    let asked: Vec<&str> = batches.iter().flatten().map(|t| t.mac.as_str()).collect();
    assert_eq!(asked, [PRINTER], "the phone did not answer the latest scan");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_named_device_is_asked_again_only_after_the_refresh_interval(pool: PgPool) {
    let (h, _) = admin(pool).await;
    let lookup = FakeLookup::new(|t| answers(t, &[(NameSource::Mdns, "Annas-iPhone")]));
    scan(&h, &[host(5, PHONE)], t0()).await;
    resolve(&h, &lookup, t0()).await;
    assert_eq!(lookup.asked(), 1);

    for (at, expected) in [(10, 1), (59, 1), (61, 2)] {
        scan(&h, &[host(5, PHONE)], t0() + minutes(at)).await;
        resolve(&h, &lookup, t0() + minutes(at)).await;
        assert_eq!(lookup.asked(), expected, "after {at} minutes");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_without_a_name_is_retried_sooner(pool: PgPool) {
    let (h, _) = admin(pool).await;
    let lookup = FakeLookup::new(|t| answers(t, &[]));
    scan(&h, &[host(5, PHONE)], t0()).await;
    resolve(&h, &lookup, t0()).await;

    // One sixth of the hour: ten minutes.
    scan(&h, &[host(5, PHONE)], t0() + minutes(5)).await;
    resolve(&h, &lookup, t0() + minutes(5)).await;
    assert_eq!(lookup.asked(), 1, "too soon");

    scan(&h, &[host(5, PHONE)], t0() + minutes(11)).await;
    resolve(&h, &lookup, t0() + minutes(11)).await;
    assert_eq!(lookup.asked(), 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn nothing_is_looked_up_when_nothing_is_due(pool: PgPool) {
    let (h, _) = admin(pool).await;
    let lookup = FakeLookup::new(|t| answers(t, &[]));

    let summary = resolve(&h, &lookup, t0()).await;

    assert_eq!(summary, Default::default());
    assert!(
        lookup.batches().is_empty(),
        "no batch, not even an empty one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_is_asked_at_its_current_address(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    scan(&h, &[host(77, PHONE)], t0() + minutes(5)).await;

    let lookup = FakeLookup::new(|t| answers(t, &[]));
    resolve(&h, &lookup, t0() + minutes(5)).await;

    assert_eq!(lookup.batches()[0][0].ip.to_string(), "192.168.1.77");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_without_an_ipv4_address_is_skipped(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;
    sqlx::query("DELETE FROM device_addresses")
        .execute(&h.pool)
        .await
        .unwrap();

    let lookup = FakeLookup::new(|t| answers(t, &[]));
    let summary = resolve(&h, &lookup, t0()).await;

    assert_eq!(summary.looked_up, 0);
    assert!(lookup.batches().is_empty());
}

// --- the schema and the API --------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_device_reports_no_source_and_no_names(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;

    let d = device_json(&h, &cookie, PHONE).await;

    assert!(d["name_source"].is_null());
    assert_eq!(d["names"], json!([]));
    assert_eq!(d["display_name"], PHONE);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_database_only_accepts_known_sources(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(5, PHONE)], t0()).await;

    let in_names = sqlx::query(
        "INSERT INTO device_names (device_id, source, name, first_seen, last_seen) \
         SELECT id, 'wins', 'x', now(), now() FROM devices",
    )
    .execute(&h.pool)
    .await;
    let on_device = sqlx::query("UPDATE devices SET name_source = 'wins'")
        .execute(&h.pool)
        .await;

    assert!(in_names.is_err() && on_device.is_err());
}

#[sqlx::test(migrations = "../../migrations")]
async fn names_need_a_session_to_be_read(pool: PgPool) {
    let (h, _) = admin(pool).await;

    let reply = send(&h.app, Method::GET, "/api/devices", None, None).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}
