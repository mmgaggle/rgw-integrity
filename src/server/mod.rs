//! The server: it keeps state in SQLite ( in RADOS through libcephsqlite, in
//! production ), hands out buckets to clients on leases, collects their
//! findings, and serves the dashboard.

pub mod db;
pub mod web;

use std::collections::BTreeSet;
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
}

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

/// A request with the admin token, as a bearer token or the session cookie.
pub struct AdminAuth;

impl FromRequestParts<Shared> for AdminAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self, Response> {
        let ok = bearer(parts).is_some_and(|t| token_matches(t, &app.admin_token))
            || session(parts).is_some_and(|t| token_matches(&t, &app.admin_token));
        if ok {
            return Ok(AdminAuth);
        }
        // browsers go to the login page; API callers get a 401
        let html = parts.headers.get(axum::http::header::ACCEPT).and_then(|a| a.to_str().ok()).is_some_and(|a| a.contains("text/html"));
        if html {
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
        let mut buckets = Vec::new();
        let mut rx = self.admin.all_bucket_stats();
        while let Some(st) = rx.recv().await {
            let st = st?;
            let name = st.name();
            if req.buckets.is_empty() || req.buckets.contains(&name) {
                buckets.push((name, st.num_objects(), Some(serde_json::to_string(&st)?)));
            }
        }
        for b in &req.buckets {
            if !buckets.iter().any(|(n, _, _)| n == b) {
                buckets.push((b.clone(), 0, None));
            }
        }
        if buckets.is_empty() {
            bail!("there are no buckets to scan");
        }
        let snapshot = if gc { Some(GcIndex::load(&self.admin).await?) } else { None };
        let entries = snapshot.as_ref().map_or(0, |g| g.entries);
        let (options, note, count) = (req.options.clone(), req.note.clone(), buckets.len());
        let id = self.db.call(move |c| db::insert_scan(c, now(), &options, &ctx, gc_min_wait, entries, &note, &buckets)).await?;
        let json = serde_json::to_vec(&snapshot.unwrap_or_default())?;
        *self.gc.write().unwrap() = Some((id, now(), Arc::new(json)));
        self.event("scan", format!("scan {id} started: {count} buckets, {entries} GC entries")).await;
        Ok(id)
    }

    /// Close the scan if its last unit is in.
    async fn maybe_finish(&self, scan: i64) -> Result<()> {
        if !self.db.call(move |c| db::scan_complete(c, scan)).await? {
            return Ok(());
        }
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

async fn api_start(_: AdminAuth, State(app): State<Shared>, Query(q): Query<StartQuery>, Json(req): Json<StartScan>) -> ApiResult<Json<i64>> {
    app.start_scan(req, q.gc).await.map(Json).map_err(|e| ApiError(StatusCode::CONFLICT, format!("{e:#}")))
}

async fn api_findings(_: AdminAuth, State(app): State<Shared>, Query(filter): Query<Filter>) -> ApiResult<Json<serde_json::Value>> {
    let (rows, total) = app.db.call(move |c| db::findings(c, &filter)).await?;
    Ok(Json(serde_json::json!({ "total": total, "findings": rows })))
}

async fn api_settings(_: AdminAuth, State(app): State<Shared>, Json(s): Json<Settings>) -> ApiResult<StatusCode> {
    let msg = format!("settings: {}", serde_json::to_string(&s).unwrap_or_default());
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
async fn api_import(_: AdminAuth, State(app): State<Shared>, body: String) -> ApiResult<Json<usize>> {
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
    app.event("import", format!("{n} findings imported")).await;
    Ok(Json(n))
}

pub fn router(app: Shared) -> Router {
    Router::new()
        .route("/api/v1/heartbeat", post(heartbeat))
        .route("/api/v1/lease", post(lease))
        .route("/api/v1/scan/{id}", get(scan_spec))
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
}

pub async fn serve(opts: ServeOpts, admin: Arc<Admin>, store: Option<Arc<dyn Store>>, catalog: Catalog) -> Result<()> {
    let (spec, lib) = (opts.db.clone(), opts.cephsqlite.clone());
    let db = tokio::task::spawn_blocking(move || Db::open(&spec, &lib)).await??;
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
