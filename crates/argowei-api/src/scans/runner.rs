//! Running nmap in the background: bounded concurrency, a hard time limit,
//! cancellation, and nothing a request could inject.
//!
//! - **No shell.** nmap is started directly with an argument vector built
//!   from a fixed profile and a validated address
//!   ([`ScanProfile::nmap_args`]).
//! - **Clean environment.** The child gets only `PATH`, so secrets in the
//!   API's environment (database password, ...) never reach it.
//! - **Bounded.** A semaphore limits scans running at once; queued scans wait
//!   for a slot. nmap's XML is read up to [`MAX_XML_BYTES`].
//! - **Always ends.** A timeout or a cancel kills the child and waits for it;
//!   `kill_on_drop` covers every other way the task can end.

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use argowei_collector::nmap::{self, NmapRun};
use argowei_core::scan_profile::ScanProfile;
use argowei_core::scan_target::ScanTargets;
use sqlx::PgPool;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{watch, Semaphore};

use super::store::{self, Failure, Finished};
use crate::config::Settings;

/// nmap's XML for one host stays far below this, even for a full scan.
pub const MAX_XML_BYTES: u64 = 16 * 1024 * 1024;
/// Enough of nmap's stderr to explain a failure.
const MAX_STDERR_BYTES: u64 = 64 * 1024;
/// Error messages stored with a scan are cut to this many characters.
const MAX_ERROR_CHARS: usize = 500;

/// How scans run. Built from [`Settings`]; tests point `nmap_path` at a
/// stand-in script.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub nmap_path: String,
    pub concurrency: usize,
    pub targets: ScanTargets,
    /// Caps every profile's own time limit (`ARGOWEI_SCAN_MAX_SECS`).
    pub max_duration: Option<Duration>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            nmap_path: "nmap".to_owned(),
            concurrency: 2,
            targets: ScanTargets::default(),
            max_duration: None,
        }
    }
}

impl From<&Settings> for ScanConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            nmap_path: settings.nmap_path.clone(),
            concurrency: settings.scan_concurrency,
            targets: settings.scan_targets.clone(),
            max_duration: (settings.scan_max_secs > 0)
                .then(|| Duration::from_secs(settings.scan_max_secs)),
        }
    }
}

/// A scan to run, as stored by the request that created it.
#[derive(Debug, Clone)]
pub struct ScanJob {
    pub scan_id: i64,
    pub device_id: i32,
    pub target: IpAddr,
    pub profile: ScanProfile,
}

/// Runs scans in the background. Cheap to clone; all clones share the slots
/// and the running scans.
#[derive(Clone)]
pub struct ScanRunner {
    inner: Arc<Inner>,
}

struct Inner {
    config: ScanConfig,
    slots: Arc<Semaphore>,
    /// Cancel switches of queued and running scans, by scan id.
    cancels: Mutex<HashMap<i64, watch::Sender<bool>>>,
}

impl ScanRunner {
    pub fn new(config: ScanConfig) -> Self {
        let slots = Arc::new(Semaphore::new(config.concurrency.max(1)));
        Self {
            inner: Arc::new(Inner {
                config,
                slots,
                cancels: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn targets(&self) -> &ScanTargets {
        &self.inner.config.targets
    }

    /// Starts working on a stored, queued scan.
    pub fn submit(&self, db: PgPool, job: ScanJob) {
        let (cancel, cancelled) = watch::channel(false);
        self.cancels().insert(job.scan_id, cancel);
        let runner = self.clone();
        tokio::spawn(async move {
            let scan_id = job.scan_id;
            runner.run(&db, job, cancelled).await;
            runner.cancels().remove(&scan_id);
        });
    }

    /// Stops a queued or running scan of this process. The caller has
    /// already stored the cancellation; this only ends the work.
    pub fn cancel(&self, scan_id: i64) {
        if let Some(cancel) = self.cancels().get(&scan_id) {
            let _ = cancel.send(true);
        }
    }

    fn cancels(&self) -> std::sync::MutexGuard<'_, HashMap<i64, watch::Sender<bool>>> {
        self.inner.cancels.lock().expect("scan cancel map poisoned")
    }

    async fn run(&self, db: &PgPool, job: ScanJob, mut cancelled: watch::Receiver<bool>) {
        let slot = tokio::select! {
            slot = Arc::clone(&self.inner.slots).acquire_owned() => slot,
            _ = cancelled.wait_for(|c| *c) => return,
        };
        let Ok(_slot) = slot else { return }; // the semaphore is never closed

        match store::mark_running(db, job.scan_id).await {
            Ok(true) => {}
            Ok(false) => return, // cancelled while queued
            Err(error) => {
                tracing::error!(scan_id = job.scan_id, %error, "could not start scan");
                return;
            }
        }

        let limit = self
            .inner
            .config
            .max_duration
            .map_or(job.profile.timeout(), |cap| cap.min(job.profile.timeout()));
        let args = job.profile.nmap_args(job.target, limit);
        let target = job.target.to_string();
        let finished = Finished {
            scan_id: job.scan_id,
            device_id: job.device_id,
            profile: job.profile,
            target: &target,
        };

        let outcome = execute(&self.inner.config.nmap_path, &args, limit, &mut cancelled).await;
        let stored = match outcome {
            Ok((run, xml)) => store::store_result(db, &finished, &run, &xml)
                .await
                .map(|_| ()),
            // The cancel request stored the outcome already.
            Err(RunError::Cancelled) => Ok(()),
            Err(error) => fail(db, &finished, &error).await,
        };
        match stored {
            Ok(()) => tracing::info!(scan_id = job.scan_id, %target, "scan finished"),
            Err(error) => {
                tracing::error!(scan_id = job.scan_id, %error, "could not store scan outcome")
            }
        }
    }
}

async fn fail(db: &PgPool, scan: &Finished<'_>, error: &RunError) -> sqlx::Result<()> {
    let failure = match error {
        RunError::TimedOut(_) => Failure::TimedOut,
        _ => Failure::Failed,
    };
    let message: String = error.to_string().chars().take(MAX_ERROR_CHARS).collect();
    tracing::warn!(scan_id = scan.scan_id, error = %message, "scan failed");
    let mut tx = db.begin().await?;
    store::store_failure(&mut tx, scan, failure, &message, &["running"]).await?;
    tx.commit().await
}

/// Why a run produced no result.
#[derive(Debug)]
pub enum RunError {
    /// nmap could not be started (e.g. not installed).
    Spawn(String, std::io::Error),
    Io(std::io::Error),
    /// nmap exited with an error; its message, if any.
    Exited(String),
    /// More output than [`MAX_XML_BYTES`].
    TooLarge,
    Unparsable(nmap::NmapError),
    TimedOut(Duration),
    Cancelled,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(path, error) if error.kind() == std::io::ErrorKind::NotFound => write!(
                f,
                "nmap was not found at \"{path}\"; install it or set ARGOWEI_NMAP_PATH"
            ),
            Self::Spawn(path, error) => write!(f, "could not start \"{path}\": {error}"),
            Self::Io(error) => write!(f, "reading nmap's output failed: {error}"),
            Self::Exited(message) => write!(f, "nmap failed: {message}"),
            Self::TooLarge => write!(f, "nmap's output exceeded {MAX_XML_BYTES} bytes"),
            Self::Unparsable(error) => write!(f, "{error}"),
            Self::TimedOut(limit) => {
                write!(f, "the scan did not finish within {} s", limit.as_secs())
            }
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for RunError {}

/// Runs nmap once and returns the parsed run and its XML. Kills the child on
/// timeout, cancel or oversized output, and waits for it before returning.
pub async fn execute(
    nmap_path: &str,
    args: &[String],
    limit: Duration,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<(NmapRun, String), RunError> {
    let mut command = Command::new(nmap_path);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| RunError::Spawn(nmap_path.to_owned(), error))?;

    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = tokio::spawn(read_draining(
        child.stderr.take().expect("stderr is piped"),
        MAX_STDERR_BYTES,
    ));

    let finished = {
        let work = async {
            let output = read_capped(stdout, MAX_XML_BYTES + 1)
                .await
                .map_err(RunError::Io)?;
            if output.len() as u64 > MAX_XML_BYTES {
                return Err(RunError::TooLarge);
            }
            let status = child.wait().await.map_err(RunError::Io)?;
            Ok((status, output))
        };
        tokio::select! {
            result = work => result,
            _ = tokio::time::sleep(limit) => Err(RunError::TimedOut(limit)),
            _ = cancelled.wait_for(|c| *c) => Err(RunError::Cancelled),
        }
    };

    let (status, output) = match finished {
        Ok(done) => done,
        Err(error) => {
            // Ends nmap before anything else happens; a no-op if it already exited.
            let _ = child.start_kill();
            let _ = child.wait().await;
            stderr.abort();
            return Err(error);
        }
    };
    let stderr = stderr.await.ok().and_then(Result::ok).unwrap_or_default();

    let xml = String::from_utf8_lossy(&output).into_owned();
    if !status.success() {
        let message = String::from_utf8_lossy(&stderr).trim().to_owned();
        return Err(RunError::Exited(if message.is_empty() {
            format!("exit status {status}")
        } else {
            message
        }));
    }
    let run = nmap::parse_xml(&xml).map_err(RunError::Unparsable)?;
    if !run.succeeded {
        return Err(RunError::Exited(
            run.error
                .unwrap_or_else(|| "nmap reported an error".to_owned()),
        ));
    }
    Ok((run, xml))
}

/// Reads at most `limit` bytes; the rest of the stream is left unread (the
/// caller kills the writer when it hits the limit).
async fn read_capped(reader: impl AsyncRead + Unpin, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    reader.take(limit).read_to_end(&mut buffer).await?;
    Ok(buffer)
}

/// Keeps the first `limit` bytes and discards the rest, reading to the end:
/// a writer must never block on a full pipe nobody reads.
async fn read_draining(mut reader: impl AsyncRead + Unpin, limit: u64) -> std::io::Result<Vec<u8>> {
    let kept = read_capped(&mut reader, limit).await?;
    tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?;
    Ok(kept)
}
