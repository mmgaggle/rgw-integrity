//! The client: leases buckets from the server, scans them, and reports what
//! it finds.  Its concurrency is the server's to set.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::admin::Admin;
use crate::limiter::Limiter;
use crate::proto::{Control, Failure, Heartbeat, LeaseRequest, Leased, Report, ScanSpec, Unit, UnitProgress};
use crate::scan::{BucketReport, Engine, GcIndex};
use crate::store::Store;

pub struct ClientOpts {
    pub server: String,
    pub token: String,
    pub ca_cert: Option<PathBuf>,
    pub insecure: bool,
    pub name: String,
    /// exit once no scan is running and this client has nothing to do
    pub once: bool,
}

struct Http {
    base: String,
    client: reqwest::Client,
}

impl Http {
    fn new(opts: &ClientOpts) -> Result<Http> {
        let mut headers = reqwest::header::HeaderMap::new();
        let auth = format!("Bearer {}", opts.token);
        headers.insert(reqwest::header::AUTHORIZATION, auth.parse().context("the token is not a valid header value")?);
        let mut b = reqwest::Client::builder().default_headers(headers).timeout(Duration::from_secs(300)).gzip(true);
        if let Some(ca) = &opts.ca_cert {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            b = b.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        if opts.insecure {
            b = b.danger_accept_invalid_certs(true);
        }
        Ok(Http { base: opts.server.trim_end_matches('/').to_string(), client: b.build()? })
    }

    async fn post<B: Serialize, R: DeserializeOwned>(&self, path: &str, body: &B) -> Result<R> {
        let resp = self.client.post(format!("{}{path}", self.base)).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("{path}: {status}: {}", resp.text().await.unwrap_or_default());
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(serde_json::from_str("null")?);
        }
        Ok(resp.json().await?)
    }

    async fn get<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let resp = self.client.get(format!("{}{path}", self.base)).send().await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("{path}: {status}: {}", resp.text().await.unwrap_or_default());
        }
        Ok(resp.json().await?)
    }
}

struct State {
    id: String,
    host: String,
    progress: Mutex<HashMap<i64, (String, Arc<AtomicU64>)>>,
    checked: AtomicU64,
    errors: AtomicU64,
    draining: AtomicBool,
}

impl State {
    fn heartbeat(&self, limiter: &Limiter, size: usize) -> Heartbeat {
        let units = self
            .progress
            .lock()
            .unwrap()
            .iter()
            .map(|(unit, (bucket, n))| UnitProgress { unit: *unit, bucket: bucket.clone(), rados_objects: n.load(Ordering::Relaxed) })
            .collect();
        Heartbeat {
            client: self.id.clone(),
            host: self.host.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            units,
            inflight_size: size,
            inflight_in_use: limiter.in_use(),
            checked: self.checked.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            draining: self.draining.load(Ordering::Relaxed),
        }
    }
}

/// Send heartbeats, and apply the server's answers to the limiter.
async fn heartbeats(http: Arc<Http>, state: Arc<State>, limiter: Arc<Limiter>, tx: watch::Sender<Option<Control>>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let size = limiter.size().await;
        match http.post::<_, Control>("/api/v1/heartbeat", &state.heartbeat(&limiter, size)).await {
            Ok(c) => {
                if c.inflight != size {
                    tracing::info!("in flight: {size} -> {}", c.inflight);
                    limiter.resize(c.inflight).await;
                }
                if c.paused != limiter.paused() {
                    tracing::warn!("{}", if c.paused { "paused by the server" } else { "resumed by the server" });
                    limiter.set_paused(c.paused);
                }
                tx.send_replace(Some(c));
            }
            Err(e) => tracing::error!("heartbeat: {e:#}"),
        }
    }
}

/// The engine for a scan, and the GC snapshot version it holds.
struct ScanEngine {
    engine: Arc<Engine>,
    gc_version: i64,
}

async fn scan_engine(http: &Http, store: &Arc<dyn Store>, admin: &Arc<Admin>, limiter: &Arc<Limiter>, scan: i64, gc_version: i64) -> Result<ScanEngine> {
    let spec: ScanSpec = http.get(&format!("/api/v1/scan/{scan}")).await?;
    let gc: GcIndex = http.get(&format!("/api/v1/gc/{scan}")).await?;
    tracing::info!("scan {scan}: {} GC entries naming {} objects", gc.entries, gc.map.len());
    let engine = Engine {
        store: store.clone(),
        admin: admin.clone(),
        ctx: Arc::new(spec.context),
        gc: RwLock::new(Arc::new(gc)),
        gc_min_wait: spec.gc_min_wait,
        limiter: limiter.clone(),
        opts: spec.options,
    };
    Ok(ScanEngine { engine: Arc::new(engine), gc_version })
}

pub async fn run(opts: ClientOpts, store: Arc<dyn Store>, admin: Arc<Admin>) -> Result<()> {
    let http = Arc::new(Http::new(&opts)?);
    let state = Arc::new(State {
        id: format!("{}:{}", opts.name, std::process::id()),
        host: opts.name.clone(),
        progress: Mutex::default(),
        checked: AtomicU64::new(0),
        errors: AtomicU64::new(0),
        draining: AtomicBool::new(false),
    });
    let limiter = Limiter::new(64);
    let (tx, mut control) = watch::channel(None::<Control>);
    tokio::spawn(heartbeats(http.clone(), state.clone(), limiter.clone(), tx));

    // the first signal drains: no new leases, finish the running units
    let draining = state.clone();
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        for n in 0.. {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            if n > 0 {
                tracing::warn!("exiting; the server will lease the running units again");
                std::process::exit(1);
            }
            tracing::warn!("draining: finishing the running units; signal again to exit now");
            draining.draining.store(true, Ordering::Relaxed);
        }
    });

    tracing::warn!("client {} reporting to {}", state.id, http.base);
    let mut engines: HashMap<i64, ScanEngine> = HashMap::new();
    let mut running: JoinSet<(Unit, Result<BucketReport>)> = JoinSet::new();
    loop {
        let c = control.borrow_and_update().clone();
        let draining = state.draining.load(Ordering::Relaxed);
        let mut leased_none = true;
        if let Some(c) = &c {
            // a newer GC snapshot of the running scan
            if let (Some(scan), Some(se)) = (c.scan, c.scan.and_then(|s| engines.get_mut(&s))) {
                if se.gc_version != c.gc_version {
                    match http.get::<GcIndex>(&format!("/api/v1/gc/{scan}")).await {
                        Ok(gc) => {
                            se.engine.set_gc(Arc::new(gc));
                            se.gc_version = c.gc_version;
                        }
                        Err(e) => tracing::error!("GC snapshot: {e:#}"),
                    }
                }
            }
            if !draining && !c.paused && running.len() < c.parallel {
                let req = LeaseRequest { client: state.id.clone(), max: c.parallel - running.len() };
                match http.post::<_, Leased>("/api/v1/lease", &req).await {
                    Ok(leased) => {
                        leased_none = leased.units.is_empty();
                        for unit in leased.units {
                            if !engines.contains_key(&unit.scan) {
                                match scan_engine(&http, &store, &admin, &limiter, unit.scan, c.gc_version).await {
                                    Ok(se) => {
                                        engines.retain(|s, _| Some(*s) == c.scan);
                                        engines.insert(unit.scan, se);
                                    }
                                    Err(e) => {
                                        tracing::error!("scan {}: {e:#}", unit.scan);
                                        let f = Failure { client: state.id.clone(), unit: unit.id, error: format!("{e:#}") };
                                        let _ = http.post::<_, ()>("/api/v1/fail", &f).await;
                                        continue;
                                    }
                                }
                            }
                            let engine = engines[&unit.scan].engine.clone();
                            let progress = Arc::new(AtomicU64::new(0));
                            state.progress.lock().unwrap().insert(unit.id, (unit.bucket.clone(), progress.clone()));
                            tracing::info!("scanning {} ( unit {} )", unit.bucket, unit.id);
                            running.spawn(async move {
                                let r = engine.scan_bucket_with(&unit.bucket, unit.stats.clone(), progress).await;
                                (unit, r)
                            });
                        }
                    }
                    Err(e) => tracing::error!("lease: {e:#}"),
                }
            }
            if opts.once && running.is_empty() && leased_none && c.scan.is_none() {
                tracing::warn!("no scan is running; exiting");
                return Ok(());
            }
        }
        if draining && running.is_empty() {
            tracing::warn!("drained; exiting");
            return Ok(());
        }
        let wait = if leased_none || running.len() >= c.as_ref().map_or(1, |c| c.parallel) { 5 } else { 1 };
        tokio::select! {
            Some(done) = running.join_next(), if !running.is_empty() => {
                let (unit, result) = done?;
                state.progress.lock().unwrap().remove(&unit.id);
                match result {
                    Ok(mut report) => {
                        state.checked.fetch_add(report.rados_objects, Ordering::Relaxed);
                        state.errors.fetch_add(report.errors.len() as u64, Ordering::Relaxed);
                        report.missing = Vec::new();
                        tracing::info!("{}: {} RADOS objects, {} findings in {:.1} s", report.bucket, report.rados_objects, report.findings.len(), report.seconds);
                        let r = Report { client: state.id.clone(), unit: unit.id, report };
                        if let Err(e) = http.post::<_, ()>("/api/v1/report", &r).await {
                            tracing::error!("reporting {}: {e:#}", unit.bucket);
                        }
                    }
                    Err(e) => {
                        state.errors.fetch_add(1, Ordering::Relaxed);
                        tracing::error!("{}: {e:#}", unit.bucket);
                        let f = Failure { client: state.id.clone(), unit: unit.id, error: format!("{e:#}") };
                        if let Err(e) = http.post::<_, ()>("/api/v1/fail", &f).await {
                            tracing::error!("reporting the failure of {}: {e:#}", unit.bucket);
                        }
                    }
                }
            }
            _ = control.changed() => {}
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
        }
    }
}
