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

/// The engine for a scan, the GC snapshot version it holds, and its orphan
/// detection's partitions.
struct ScanEngine {
    scan: i64,
    engine: Arc<Engine>,
    gc_version: i64,
    plan: Option<crate::detect::Plan>,
    shuffle: Option<Arc<dyn crate::shuffle::Shuffle>>,
    markers: tokio::sync::OnceCell<HashMap<String, crate::admin::BucketStats>>,
}

impl ScanEngine {
    fn detection(&self) -> Result<(&crate::detect::Plan, &Arc<dyn crate::shuffle::Shuffle>)> {
        match (&self.plan, &self.shuffle) {
            (Some(p), Some(s)) => Ok((p, s)),
            _ => bail!("scan {} does not find orphans", self.scan),
        }
    }

    /// The scan's buckets by marker, which orphans are classified by.
    async fn markers(&self, http: &Http) -> Result<&HashMap<String, crate::admin::BucketStats>> {
        self.markers
            .get_or_try_init(|| async {
                let stats: Vec<crate::admin::BucketStats> = http.get(&format!("/api/v1/scan/{}/buckets", self.scan)).await?;
                Ok(stats.into_iter().map(|s| (s.marker.clone(), s)).collect())
            })
            .await
    }
}

async fn scan_engine(http: &Http, store: &Arc<dyn Store>, admin: &Arc<Admin>, limiter: &Arc<Limiter>, scan: i64, gc_version: i64) -> Result<ScanEngine> {
    let spec: ScanSpec = http.get(&format!("/api/v1/scan/{scan}")).await?;
    let gc: GcIndex = http.get(&format!("/api/v1/gc/{scan}")).await?;
    tracing::info!("scan {scan}: {} GC entries naming {} objects", gc.entries, gc.map.len());
    let plan = spec.plan.filter(|_| spec.options.orphans);
    let shuffle = match plan.as_ref().and_then(|p| p.work.as_deref()) {
        Some(pool) => Some(store.shuffle(pool)?),
        None => None,
    };
    let engine = Engine {
        store: store.clone(),
        admin: admin.clone(),
        ctx: Arc::new(spec.context),
        gc: RwLock::new(Arc::new(gc)),
        gc_min_wait: spec.gc_min_wait,
        limiter: limiter.clone(),
        opts: spec.options,
        partitions: plan.as_ref().map(|p| p.partitions),
    };
    Ok(ScanEngine { scan, engine: Arc::new(engine), gc_version, plan, shuffle, markers: Default::default() })
}

/// Run one unit: scan a bucket, list a pool slice, or join a partition.
async fn run_unit(se: Arc<ScanEngine>, http: Arc<Http>, writer: String, unit: &Unit, progress: Arc<AtomicU64>) -> Result<BucketReport> {
    let started = std::time::Instant::now();
    match unit.kind.as_str() {
        "list" => {
            let (plan, shuffle) = se.detection()?;
            let sl: crate::detect::Slice = serde_json::from_value(unit.spec.clone().context("a pool slice without its spec")?)?;
            let listed = crate::list_slice(&se.engine, &sl, plan.partitions, shuffle.as_ref(), se.scan, &writer).await?;
            progress.store(listed, Ordering::Relaxed);
            Ok(BucketReport { bucket: unit.bucket.clone(), rados_objects: listed, seconds: started.elapsed().as_secs_f64(), ..Default::default() })
        }
        "join" => {
            let (_, shuffle) = se.detection()?;
            let j: crate::detect::Join = serde_json::from_value(unit.spec.clone().context("a join without its spec")?)?;
            let (candidates, stats) = crate::detect::join(shuffle.as_ref(), se.scan, j.partition, &j.writers).await?;
            progress.store(stats.listed, Ordering::Relaxed);
            tracing::info!("partition {}: {} listed, {} referenced, {} not", j.partition, stats.listed, stats.references, stats.unreferenced);
            Ok(BucketReport {
                bucket: unit.bucket.clone(),
                rados_objects: stats.listed,
                candidates,
                seconds: started.elapsed().as_secs_f64(),
                ..Default::default()
            })
        }
        "classify" => {
            let (plan, _) = se.detection()?;
            let c: crate::detect::Classify = serde_json::from_value(unit.spec.clone().context("a classification without its spec")?)?;
            let markers = se.markers(&http).await?;
            let (findings, tally) = se.engine.classify_orphans(&c.oids, markers, Some(plan.created)).await;
            progress.store(c.oids.len() as u64, Ordering::Relaxed);
            Ok(BucketReport {
                bucket: unit.bucket.clone(),
                rados_objects: c.oids.len() as u64,
                findings,
                tally,
                seconds: started.elapsed().as_secs_f64(),
                ..Default::default()
            })
        }
        _ => {
            // a bucket, or one shard of it ( a shard unit's spec )
            let (bucket, shard) = match (&unit.kind[..], &unit.spec) {
                ("shard", Some(spec)) => {
                    let s: crate::detect::ShardUnit = serde_json::from_value(spec.clone())?;
                    (s.bucket, Some(s.shard))
                }
                _ => (unit.bucket.clone(), None),
            };
            let mut r = se.engine.scan_bucket_with(&bucket, unit.stats.clone(), progress, shard).await?;
            // the references must be in the partitions before the report says the bucket is done
            if let Some(refs) = r.references.take() {
                let (_, shuffle) = se.detection()?;
                refs.flush(shuffle.as_ref(), se.scan, &writer).await?;
            }
            Ok(r)
        }
    }
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
    let mut engines: HashMap<i64, Arc<ScanEngine>> = HashMap::new();
    let mut gc_versions: HashMap<i64, i64> = HashMap::new();
    let mut running: JoinSet<(Unit, Result<BucketReport>)> = JoinSet::new();
    loop {
        let c = control.borrow_and_update().clone();
        let draining = state.draining.load(Ordering::Relaxed);
        let mut leased_none = true;
        if let Some(c) = &c {
            // a newer GC snapshot of the running scan
            if let (Some(scan), Some(se)) = (c.scan, c.scan.and_then(|s| engines.get(&s))) {
                if se.gc_version != c.gc_version && gc_versions.get(&scan) != Some(&c.gc_version) {
                    match http.get::<GcIndex>(&format!("/api/v1/gc/{scan}")).await {
                        Ok(gc) => {
                            se.engine.set_gc(Arc::new(gc));
                            gc_versions.insert(scan, c.gc_version);
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
                                        engines.insert(unit.scan, Arc::new(se));
                                    }
                                    Err(e) => {
                                        tracing::error!("scan {}: {e:#}", unit.scan);
                                        let f = Failure { client: state.id.clone(), unit: unit.id, error: format!("{e:#}") };
                                        let _ = http.post::<_, ()>("/api/v1/fail", &f).await;
                                        continue;
                                    }
                                }
                            }
                            let se = engines[&unit.scan].clone();
                            let progress = Arc::new(AtomicU64::new(0));
                            state.progress.lock().unwrap().insert(unit.id, (unit.bucket.clone(), progress.clone()));
                            tracing::info!("{} ( unit {}, {} )", unit.bucket, unit.id, unit.kind);
                            let (http, writer) = (http.clone(), state.id.clone());
                            running.spawn(async move {
                                let r = run_unit(se, http, writer, &unit, progress).await;
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
                        match http.post::<_, ()>("/api/v1/report", &r).await {
                            Err(e) => tracing::error!("reporting {}: {e:#}", unit.bucket),
                            // a joined partition's objects go once the server has its findings
                            Ok(()) if unit.kind == "join" => {
                                if let (Some(se), Some(spec)) = (engines.get(&unit.scan), unit.spec.clone()) {
                                    if let (Ok(j), Ok((_, shuffle))) = (serde_json::from_value::<crate::detect::Join>(spec), se.detection()) {
                                        if let Err(e) = crate::detect::cleanup(shuffle.as_ref(), unit.scan, j.partition, &j.writers).await {
                                            tracing::error!("cleaning partition {}: {e:#}", j.partition);
                                        }
                                    }
                                }
                            }
                            Ok(()) => {}
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
