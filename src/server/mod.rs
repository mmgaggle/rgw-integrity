//! The server: it keeps state in SQLite ( in RADOS through libcephsqlite, in
//! production ), hands out buckets to clients on leases, collects their
//! findings, and serves the dashboard.

pub mod db;
pub mod oidc;
pub mod web;

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use axum::extract::{FromRequestParts, Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::admin::Admin;
use crate::finding::{Catalog, Context, Finding};
use crate::proto::{Control, Failure, Heartbeat, LeaseRequest, Leased, Report, ScanSpec, StartScan};
use crate::scan::{GcIndex, now};
use crate::store::Store;
use db::{Db, Filter, Settings};

pub const SESSION_COOKIE: &str = "rgwi_session";

pub struct App {
    pub db: Db,
    pub admin: Arc<Admin>,
    pub store: Option<Arc<dyn Store>>,
    pub catalog: Catalog,
    client_token: String,
    admin_token: String,
    /// the running scan's GC snapshot: (scan, version, JSON)
    gc: RwLock<Option<(i64, i64, Arc<Vec<u8>>)>>,
    starting: tokio::sync::Mutex<()>,
    pub secure_cookies: bool,
    /// where clients exchange orphan detection's partitions
    pub work_pool: Option<String>,
    /// orphan detection's sizing, instead of the objects' count
    pub partitions: Option<u32>,
    pub slices: Option<usize>,
    pub oidc: Option<oidc::Oidc>,
    /// only single sign-on logs in to the dashboard, not the admin token
    pub oidc_only: bool,
    /// the server's URL, as browsers reach it
    pub public_url: Option<String>,
    sessions: std::sync::Mutex<HashMap<String, Session>>,
}

/// A dashboard login.
#[derive(Clone)]
pub struct Session {
    pub who: oidc::Identity,
    expires: std::time::Instant,
    /// the ID token, for the provider's logout
    pub id_token: Option<String>,
}

const SESSION_HOURS: u64 = 12;

pub type Shared = Arc<App>;

/// An API error: its status and message.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("{e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;

fn token_matches(given: &str, want: &str) -> bool {
    !want.is_empty() && given.as_bytes().ct_eq(want.as_bytes()).into()
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts.headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

pub fn session(parts: &Parts) -> Option<String> {
    let cookies = parts.headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookies.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == SESSION_COOKIE).map(|(_, v)| v.to_string())
}

/// A request with the client token ( or the admin token ).
pub struct ClientAuth;

impl FromRequestParts<Shared> for ClientAuth {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self, StatusCode> {
        match bearer(parts) {
            Some(t) if token_matches(t, &app.client_token) || token_matches(t, &app.admin_token) => Ok(ClientAuth),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

/// A request from someone allowed to administer: the admin token, a
/// provider's access token as a bearer token, or a dashboard session.
pub struct AdminAuth(pub oidc::Identity);

fn wants_html(parts: &Parts) -> bool {
    parts.headers.get(axum::http::header::ACCEPT).and_then(|a| a.to_str().ok()).is_some_and(|a| a.contains("text/html"))
}

impl FromRequestParts<Shared> for AdminAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self, Response> {
        if let Some(t) = bearer(parts) {
            if token_matches(t, &app.admin_token) {
                return Ok(AdminAuth(oidc::Identity { name: "admin token".into(), via: "token", groups: Vec::new() }));
            }
            if let (Some(o), 2) = (&app.oidc, t.matches('.').count()) {
                return match o.verify_access_token(t).await {
                    Ok(who) => Ok(AdminAuth(who)),
                    Err(oidc::Refusal::NotAllowed(name)) => Err((StatusCode::FORBIDDEN, format!("{name} is not allowed here")).into_response()),
                    Err(oidc::Refusal::Failed(e)) => Err((StatusCode::UNAUTHORIZED, format!("{e:#}")).into_response()),
                };
            }
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        if let Some(s) = session(parts).and_then(|id| app.session(&id)) {
            return Ok(AdminAuth(s.who));
        }
        // browsers go to the login page; API callers get a 401
        if wants_html(parts) {
            let next = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let to = format!("/login?next={}", web::urlencode(next));
            return Err(axum::response::Redirect::to(&to).into_response());
        }
        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}

impl App {
    pub fn admin_token_matches(&self, token: &str) -> bool {
        token_matches(token, &self.admin_token)
    }

    /// Log someone in: a new session's id, for its cookie.
    pub fn new_session(&self, who: oidc::Identity, id_token: Option<String>) -> String {
        let id = {
            let bytes: [u8; 32] = rand::random();
            hex::encode(bytes)
        };
        let expires = std::time::Instant::now() + std::time::Duration::from_secs(SESSION_HOURS * 3600);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires > std::time::Instant::now());
        sessions.insert(id.clone(), Session { who, expires, id_token });
        id
    }

    pub fn session(&self, id: &str) -> Option<Session> {
        self.sessions.lock().unwrap().get(id).filter(|s| s.expires > std::time::Instant::now()).cloned()
    }

    pub fn end_session(&self, id: &str) -> Option<Session> {
        self.sessions.lock().unwrap().remove(id)
    }

    pub fn session_cookie(&self, id: &str, max_age: u64) -> String {
        let secure = if self.secure_cookies { "; Secure" } else { "" };
        // Lax: the session must arrive with the redirect back from the provider
        format!("{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
    }

    pub async fn settings(&self) -> Result<Settings> {
        self.db.call(|c| db::settings(c)).await
    }

    pub async fn event(&self, kind: &str, message: String) {
        let kind = kind.to_string();
        if let Err(e) = self.db.call(move |c| db::event(c, now(), &kind, &message)).await {
            tracing::error!("recording an event: {e:#}");
        }
    }

    async fn context(&self, settings: &Settings) -> Result<Context> {
        let majors: BTreeSet<u32> = match (&settings.release, &self.store) {
            (Some(r), _) if !r.is_empty() => crate::release_majors(r)?,
            (_, Some(store)) => store.majors().await.unwrap_or_else(|e| {
                tracing::error!("cannot read `ceph versions` ( {e:#} ); considering every known issue");
                BTreeSet::new()
            }),
            _ => BTreeSet::new(),
        };
        Ok(Context {
            catalog: self.catalog.clone(),
            majors,
            fixed: settings.fixed.iter().copied().collect(),
            fixed_since: settings.fixed_since.as_deref().and_then(|d| crate::oid::parse_time(&format!("{d} 00:00:00"))),
        })
    }

    /// Start a scan: list the buckets, snapshot GC, and queue a unit per bucket.
    pub async fn start_scan(self: &Arc<Self>, req: StartScan, gc: bool) -> Result<i64> {
        let _starting = self.starting.lock().await;
        if let Some(id) = self.db.call(|c| db::running_scan(c)).await? {
            bail!("scan {id} is still running");
        }
        let settings = self.settings().await?;
        let ctx = self.context(&settings).await?;
        let gc_min_wait = self.store.as_ref().and_then(|s| s.conf_get("rgw_gc_obj_min_wait")).and_then(|v| v.parse().ok()).unwrap_or(7200);
        if req.options.orphans && (!req.buckets.is_empty() || req.options.match_prefix.is_some()) {
            bail!("finding orphans needs every bucket's references: scan every bucket, and every key");
        }
        let mut units = Vec::new();
        let mut rx = self.admin.all_bucket_stats();
        while let Some(st) = rx.recv().await {
            let st = st?;
            let name = st.name();
            if req.buckets.is_empty() || req.buckets.contains(&name) {
                units.push(db::NewUnit::bucket(name, st.num_objects(), Some(serde_json::to_string(&st)?)));
            }
        }
        for b in &req.buckets {
            if !units.iter().any(|u| &u.label == b) {
                units.push(db::NewUnit::bucket(b.clone(), 0, None));
            }
        }
        if units.is_empty() {
            bail!("there are no buckets to scan");
        }
        let buckets = units.len();
        let plan = if req.options.orphans { Some(self.plan_orphans(&mut units).await?) } else { None };
        let snapshot = if gc { Some(GcIndex::load(&self.admin).await?) } else { None };
        let entries = snapshot.as_ref().map_or(0, |g| g.entries);
        let (options, note) = (req.options.clone(), req.note.clone());
        let what = match &plan {
            Some(p) => format!(", and orphans in {} partitions of {} pool slices", p.partitions, units.len() - buckets - p.partitions as usize),
            None => String::new(),
        };
        let id = self.db.call(move |c| db::insert_scan(c, now(), &options, &ctx, gc_min_wait, entries, &note, plan.as_ref(), &units)).await?;
        let json = serde_json::to_vec(&snapshot.unwrap_or_default())?;
        *self.gc.write().unwrap() = Some((id, now(), Arc::new(json)));
        self.event("scan", format!("scan {id} started: {buckets} buckets{what}, {entries} GC entries")).await;
        Ok(id)
    }

    /// Orphan detection: a unit per slice of each data pool, and a join per
    /// partition that waits for them and the buckets.
    async fn plan_orphans(&self, units: &mut Vec<db::NewUnit>) -> Result<crate::detect::Plan> {
        let Some(work) = self.work_pool.clone() else {
            bail!("finding orphans needs a pool to exchange partitions in: start the server with a ceph: database, or --work-pool");
        };
        let Some(store) = &self.store else { bail!("finding orphans needs the cluster") };
        let pools = self.admin.zone_pools().await?.data;
        let counts = store.pool_objects().await?;
        let count = |p: &String| counts.get(p.split(':').next().unwrap_or(p)).copied().unwrap_or(0);
        let partitions = self.partitions.unwrap_or_else(|| crate::detect::partitions_for(pools.iter().map(count).sum())).max(1);
        for pool in &pools {
            let n = self.slices.unwrap_or_else(|| crate::detect::slices_for(count(pool))).max(1);
            for i in 0..n {
                let spec = crate::detect::Slice { pool: pool.clone(), slice: i, slices: n };
                units.push(db::NewUnit {
                    label: format!("{pool} slice {}/{n}", i + 1),
                    kind: "list",
                    objects: count(pool) / n as u64,
                    stats: None,
                    spec: Some(serde_json::to_string(&spec)?),
                    blocked: false,
                });
            }
        }
        for p in 0..partitions {
            let spec = crate::detect::Join { partition: p, writers: Vec::new() };
            units.push(db::NewUnit {
                label: format!("orphans, partition {}/{partitions}", p + 1),
                kind: "join",
                objects: 0,
                stats: None,
                spec: Some(serde_json::to_string(&spec)?),
                blocked: true,
            });
        }
        Ok(crate::detect::Plan { partitions, work: Some(work), created: now() })
    }

    /// Remove what a scan's orphan detection left in the work pool.
    async fn clean_partitions(&self, scan: i64) {
        let Some(store) = self.store.clone() else { return };
        let Ok(Some(spec)) = self.db.call(move |c| db::scan_spec(c, scan)).await else { return };
        let Some(plan) = spec.plan else { return };
        let (Some(work), Ok(writers)) = (plan.work, self.db.call(move |c| db::scan_writers(c, scan)).await) else { return };
        let shuffle = match store.shuffle(&work) {
            Ok(s) => s,
            Err(e) => return tracing::error!("cleaning scan {scan}'s partitions: {e:#}"),
        };
        for p in 0..plan.partitions {
            if let Err(e) = crate::detect::cleanup(shuffle.as_ref(), scan, p, &writers).await {
                return tracing::error!("cleaning scan {scan}'s partitions: {e:#}");
            }
        }
    }

    /// Let a scan's joins go once the rest is in, and close the scan when
    /// its last unit is.
    async fn maybe_finish(self: &Arc<Self>, scan: i64) -> Result<()> {
        if let Some(msg) = self.db.call(move |c| db::unblock_joins(c, scan)).await? {
            self.event("scan", msg).await;
        }
        if let Some(msg) = self.db.call(move |c| db::plan_classification(c, scan)).await? {
            self.event("scan", msg).await;
        }
        if !self.db.call(move |c| db::scan_complete(c, scan)).await? {
            return Ok(());
        }
        let app = self.clone();
        tokio::spawn(async move { app.clean_partitions(scan).await });
        let Some(spec) = self.db.call(move |c| db::scan_spec(c, scan)).await? else { return Ok(()) };
        let ctx = spec.context;
        let (leaks, gone) = self.db.call(move |c| db::finish_scan(c, scan, &ctx, now())).await?;
        self.event("scan", format!("scan {scan} finished: {leaks} unheld references, {gone} findings gone")).await;
        Ok(())
    }

    /// The Control a client gets: its share of the global concurrency.
    async fn control(&self, hb: &Heartbeat, settings: &Settings) -> Result<Control> {
        let hb2 = hb.clone();
        let (inflight_override, active, scan) = self
            .db
            .call(move |c| {
                let o = db::heartbeat(c, &hb2, now())?;
                let units: Vec<i64> = hb2.units.iter().map(|u| u.unit).collect();
                let lease_secs = db::settings(c)?.lease_secs;
                db::renew(c, &hb2.client, &units, now() + lease_secs)?;
                Ok((o, db::active_clients(c, now() - 30)?, db::running_scan(c)?))
            })
            .await?;
        let share = settings.global_inflight / active.max(1);
        let gc_version = self.gc.read().unwrap().as_ref().filter(|(s, _, _)| Some(*s) == scan).map_or(0, |(_, v, _)| *v);
        Ok(Control {
            inflight: inflight_override.unwrap_or(share).max(1),
            parallel: settings.parallel.max(1),
            paused: settings.paused,
            scan,
            gc_version,
            lease_secs: settings.lease_secs,
        })
    }

    /// Put back the units whose leases lapsed, and start scans on schedule.
    async fn housekeeping(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            match self.db.call(|c| db::reap(c, now())).await {
                Ok(reaped) => {
                    for (bucket, client) in reaped {
                        self.event("lease", format!("{bucket}: {} stopped renewing its lease", client.unwrap_or_default())).await;
                    }
                }
                Err(e) => tracing::error!("reaping leases: {e:#}"),
            }
            if let Ok(Some(scan)) = self.db.call(|c| db::running_scan(c)).await {
                if let Err(e) = self.maybe_finish(scan).await {
                    tracing::error!("finishing scan {scan}: {e:#}");
                }
            }
            if let Err(e) = self.auto_scan().await {
                tracing::error!("scheduled scan: {e:#}");
            }
        }
    }

    async fn auto_scan(self: &Arc<Self>) -> Result<()> {
        let settings = self.settings().await?;
        if settings.auto_scan_hours == 0 || settings.paused {
            return Ok(());
        }
        let scans = self.db.call(|c| db::scans(c, 1)).await?;
        let due = match scans.first() {
            None => true,
            Some(s) if s.state == "running" => false,
            Some(s) => s.finished.unwrap_or(s.created) + settings.auto_scan_hours as i64 * 3600 <= now(),
        };
        if due {
            let req = StartScan { options: settings.default_options.clone(), buckets: Vec::new(), note: "scheduled".into() };
            self.start_scan(req, true).await?;
        }
        Ok(())
    }
}

async fn heartbeat(_: ClientAuth, State(app): State<Shared>, Json(hb): Json<Heartbeat>) -> ApiResult<Json<Control>> {
    let settings = app.settings().await?;
    Ok(Json(app.control(&hb, &settings).await?))
}

async fn lease(_: ClientAuth, State(app): State<Shared>, Json(req): Json<LeaseRequest>) -> ApiResult<Json<Leased>> {
    let settings = app.settings().await?;
    if settings.paused {
        return Ok(Json(Leased::default()));
    }
    let max = req.max.min(settings.parallel.max(1));
    let units = app.db.call(move |c| db::lease(c, &req.client, max, now(), settings.lease_secs)).await?;
    Ok(Json(Leased { units }))
}

async fn scan_buckets(_: ClientAuth, State(app): State<Shared>, UrlPath(id): UrlPath<i64>) -> ApiResult<Json<Vec<crate::admin::BucketStats>>> {
    Ok(Json(app.db.call(move |c| db::scan_buckets(c, id)).await?))
}

async fn scan_spec(_: ClientAuth, State(app): State<Shared>, UrlPath(id): UrlPath<i64>) -> ApiResult<Json<ScanSpec>> {
    match app.db.call(move |c| db::scan_spec(c, id)).await? {
        Some(spec) => Ok(Json(spec)),
        None => Err(ApiError(StatusCode::NOT_FOUND, format!("no scan {id}"))),
    }
}

async fn gc_snapshot(_: ClientAuth, State(app): State<Shared>, UrlPath(scan): UrlPath<i64>) -> ApiResult<Response> {
    let snap = app.gc.read().unwrap().clone();
    match snap {
        Some((s, version, json)) if s == scan => Ok((
            [(axum::http::header::CONTENT_TYPE, "application/json".to_string()), (axum::http::header::ETAG, format!("\"{version}\""))],
            json.as_ref().clone(),
        )
            .into_response()),
        // a server restarted mid-scan has no snapshot: an empty one
        _ => Ok(Json(GcIndex::default()).into_response()),
    }
}

async fn report(_: ClientAuth, State(app): State<Shared>, Json(r): Json<Report>) -> ApiResult<StatusCode> {
    let unit = r.unit;
    let scan: Option<i64> = app
        .db
        .call(move |c| Ok(c.query_row("SELECT scan_id FROM units WHERE id = ?1", [unit], |row| row.get(0)).ok()))
        .await?;
    let Some(scan) = scan else { return Err(ApiError(StatusCode::NOT_FOUND, format!("no unit {unit}"))) };
    let (client, report) = (r.client.clone(), r.report);
    let summary = format!("{}: {} RADOS objects, {} findings, {:.1} s, by {}", report.bucket, report.rados_objects, report.findings.len(), report.seconds, client);
    app.db.call(move |c| db::complete(c, scan, unit, &client, &report, now())).await?;
    tracing::info!("{summary}");
    app.maybe_finish(scan).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn failure(_: ClientAuth, State(app): State<Shared>, Json(f): Json<Failure>) -> ApiResult<StatusCode> {
    let msg = format!("unit {} failed on {}: {}", f.unit, f.client, f.error);
    app.db.call(move |c| db::fail(c, f.unit, &f.client, &f.error)).await?;
    app.event("unit", msg).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct StartQuery {
    #[serde(default = "yes")]
    gc: bool,
}

fn yes() -> bool {
    true
}

async fn api_start(AdminAuth(who): AdminAuth, State(app): State<Shared>, Query(q): Query<StartQuery>, Json(req): Json<StartScan>) -> ApiResult<Json<i64>> {
    let id = app.start_scan(req, q.gc).await.map_err(|e| ApiError(StatusCode::CONFLICT, format!("{e:#}")))?;
    app.event("scan", format!("scan {id} started by {}", who.name)).await;
    Ok(Json(id))
}

async fn api_findings(_: AdminAuth, State(app): State<Shared>, Query(filter): Query<Filter>) -> ApiResult<Json<serde_json::Value>> {
    let (rows, total) = app.db.call(move |c| db::findings(c, &filter)).await?;
    Ok(Json(serde_json::json!({ "total": total, "findings": rows })))
}

async fn api_settings(AdminAuth(who): AdminAuth, State(app): State<Shared>, Json(s): Json<Settings>) -> ApiResult<StatusCode> {
    let msg = format!("settings, by {}: {}", who.name, serde_json::to_string(&s).unwrap_or_default());
    app.db.call(move |c| db::save_settings(c, &s)).await?;
    app.event("control", msg).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_status(_: AdminAuth, State(app): State<Shared>) -> ApiResult<Json<serde_json::Value>> {
    let (settings, scans, clients) =
        app.db.call(|c| Ok((db::settings(c)?, db::scans(c, 5)?, db::clients(c)?))).await?;
    Ok(Json(serde_json::json!({ "settings": settings, "scans": scans, "clients": clients })))
}

/// Findings from elsewhere: rgw-integrity scan, or rgw-gap-list.py, as JSON lines.
async fn api_import(AdminAuth(who): AdminAuth, State(app): State<Shared>, body: String) -> ApiResult<Json<usize>> {
    let findings: Vec<Finding> = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e}")))?;
    let n = findings.len();
    app.db
        .call(move |c| {
            let tx = c.transaction()?;
            for f in &findings {
                db::upsert_finding(&tx, None, f, now())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    app.event("import", format!("{n} findings imported by {}", who.name)).await;
    Ok(Json(n))
}

pub fn router(app: Shared) -> Router {
    Router::new()
        .route("/api/v1/heartbeat", post(heartbeat))
        .route("/api/v1/lease", post(lease))
        .route("/api/v1/scan/{id}", get(scan_spec))
        .route("/api/v1/scan/{id}/buckets", get(scan_buckets))
        .route("/api/v1/gc/{scan}", get(gc_snapshot))
        .route("/api/v1/report", post(report))
        .route("/api/v1/fail", post(failure))
        .route("/api/v1/scans", post(api_start))
        .route("/api/v1/findings", get(api_findings))
        .route("/api/v1/settings", post(api_settings))
        .route("/api/v1/status", get(api_status))
        .route("/api/v1/import", post(api_import))
        .merge(web::routes())
        .layer(axum::extract::DefaultBodyLimit::max(512 << 20))
        .layer(tower_http::compression::CompressionLayer::new())
        .with_state(app)
}

/// Read a token from a file, or create the file with a new token.
pub fn token_file(path: &Path) -> Result<String> {
    if path.exists() {
        let t = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?.trim().to_string();
        if t.len() < 16 {
            bail!("the token in {} is shorter than 16 characters", path.display());
        }
        return Ok(t);
    }
    let token: String = {
        use rand::RngExt;
        let mut rng = rand::rng();
        (0..40).map(|_| rng.sample(rand::distr::Alphanumeric) as char).collect()
    };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).with_context(|| format!("creating {}", path.display()))?;
    writeln!(f, "{token}")?;
    tracing::warn!("wrote a new token to {}", path.display());
    Ok(token)
}

pub struct ServeOpts {
    pub listen: SocketAddr,
    pub tls: Option<(PathBuf, PathBuf)>,
    pub db: String,
    pub cephsqlite: String,
    pub client_token: String,
    pub admin_token: String,
    pub work_pool: Option<String>,
    pub partitions: Option<u32>,
    pub slices: Option<usize>,
    pub oidc: Option<oidc::OidcConfig>,
    pub oidc_only: bool,
    pub public_url: Option<String>,
}

pub async fn serve(opts: ServeOpts, admin: Arc<Admin>, store: Option<Arc<dyn Store>>, catalog: Catalog) -> Result<()> {
    let (spec, lib) = (opts.db.clone(), opts.cephsqlite.clone());
    let db = tokio::task::spawn_blocking(move || Db::open(&spec, &lib)).await??;
    let oidc = match opts.oidc {
        Some(cfg) => Some(oidc::Oidc::discover(cfg).await.context("single sign-on")?),
        None => None,
    };
    let app = Arc::new(App {
        db,
        admin,
        store,
        catalog,
        client_token: opts.client_token,
        admin_token: opts.admin_token,
        gc: RwLock::new(None),
        starting: tokio::sync::Mutex::new(()),
        secure_cookies: opts.tls.is_some(),
        work_pool: opts.work_pool,
        partitions: opts.partitions,
        slices: opts.slices,
        oidc,
        oidc_only: opts.oidc_only,
        public_url: opts.public_url,
        sessions: std::sync::Mutex::default(),
    });
    app.event("server", format!("started, state in {}", app.db.location)).await;
    tokio::spawn(app.clone().housekeeping());
    let router = router(app);
    match opts.tls {
        Some((cert, key)) => {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .with_context(|| format!("loading {} and {}", cert.display(), key.display()))?;
            tracing::warn!("listening on https://{}", opts.listen);
            axum_server::bind_rustls(opts.listen, config).serve(router.into_make_service()).await?;
        }
        None => {
            tracing::warn!("listening on http://{} without TLS", opts.listen);
            let listener = tokio::net::TcpListener::bind(opts.listen).await?;
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}
