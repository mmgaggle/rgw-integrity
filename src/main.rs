//! rgw-integrity: find, and classify, what known RGW races leave behind in a
//! Ceph cluster.  One binary: a standalone `scan`, or a `server` that hands
//! out buckets to `client`s and keeps what they find.

mod admin;
mod client;
mod detect;
mod finding;
mod json_stream;
mod limiter;
mod oid;
mod orphans;
#[cfg(feature = "ceph")]
mod rados;
mod proto;
mod scan;
mod server;
mod shuffle;
mod store;

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use tokio::task::JoinSet;

use crate::admin::{Admin, BucketStats};
use crate::finding::{Catalog, Context, Tally};
use crate::scan::{Engine, GcIndex, Options, RefLedger};

#[derive(Parser)]
#[command(version, about = "Find and classify the artifacts known RGW races leave behind")]
struct Cli {
    /// more logging: -v info, -vv debug
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan buckets from this host, writing findings to a file
    Scan(ScanArgs),
    /// Hand out buckets to clients, keep what they find, and serve the dashboard
    Server(ServerArgs),
    /// Scan the buckets a server leases to this host
    Client(ClientArgs),
    /// Send a findings file ( rgw-integrity scan, or rgw-gap-list.py ) to a server
    Import(ImportArgs),
}

#[derive(Args)]
struct ServerArgs {
    #[command(flatten)]
    ceph: CephArgs,
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: std::net::SocketAddr,
    /// the TLS certificate chain and key, PEM
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// serve plain HTTP; only for tests
    #[arg(long)]
    insecure_http: bool,
    /// where state lives: ceph:<pool>[:<namespace>]/<name> through
    /// libcephsqlite, or file:<path>
    #[arg(long)]
    db: String,
    /// libcephsqlite, for a ceph: database
    #[arg(long, default_value = "libcephsqlite.so")]
    cephsqlite: String,
    /// the token clients present; created if the file does not exist
    #[arg(long, default_value = "/etc/rgw-integrity/client.token")]
    client_token_file: PathBuf,
    /// the token of the dashboard and the admin API; created if missing
    #[arg(long, default_value = "/etc/rgw-integrity/admin.token")]
    admin_token_file: PathBuf,
    /// do not connect to the cluster ( a file: database, to try the dashboard )
    #[arg(long)]
    no_ceph: bool,
    /// the pool clients exchange orphan detection's partitions in; the
    /// database's pool by default
    #[arg(long)]
    work_pool: Option<String>,
    #[command(flatten)]
    sizing: SizingArgs,
    #[command(flatten)]
    oidc: OidcArgs,
}

/// Single sign-on with OpenID Connect, for the dashboard and the admin API.
#[derive(Args)]
struct OidcArgs {
    /// the provider's issuer URL; enables single sign-on
    #[arg(long, requires_all = ["oidc_client_id", "public_url"])]
    oidc_issuer: Option<String>,
    #[arg(long)]
    oidc_client_id: Option<String>,
    /// the client's secret; without it, the client is public and relies on PKCE
    #[arg(long)]
    oidc_client_secret_file: Option<PathBuf>,
    /// the server's URL as browsers reach it; the provider sends them back
    /// to <url>/oidc/callback
    #[arg(long)]
    public_url: Option<String>,
    #[arg(long, default_value = "openid profile email")]
    oidc_scopes: String,
    /// the claim that names the user
    #[arg(long, default_value = "preferred_username")]
    oidc_user_claim: String,
    /// the claim that lists the user's groups
    #[arg(long, default_value = "groups")]
    oidc_groups_claim: String,
    /// users allowed in, comma separated
    #[arg(long, value_delimiter = ',')]
    oidc_allowed_users: Vec<String>,
    /// groups allowed in, comma separated
    #[arg(long, value_delimiter = ',')]
    oidc_allowed_groups: Vec<String>,
    /// let in anyone the provider vouches for
    #[arg(long)]
    oidc_allow_any_user: bool,
    /// the audience of the admin API's bearer tokens; the client id by default
    #[arg(long)]
    oidc_api_audience: Option<String>,
    /// the CA of the provider's certificate
    #[arg(long)]
    oidc_ca_cert: Option<PathBuf>,
    /// what the login button calls the provider
    #[arg(long, default_value = "single sign-on")]
    oidc_name: String,
    /// log in to the dashboard only with single sign-on; the admin token
    /// still works as the API's bearer token
    #[arg(long, requires = "oidc_issuer")]
    oidc_only: bool,
}

impl OidcArgs {
    fn config(&self) -> Result<Option<server::oidc::OidcConfig>> {
        let Some(issuer) = &self.oidc_issuer else { return Ok(None) };
        if !self.oidc_allow_any_user && self.oidc_allowed_users.is_empty() && self.oidc_allowed_groups.is_empty() {
            anyhow::bail!("single sign-on lets in only --oidc-allowed-users or --oidc-allowed-groups, or anyone with --oidc-allow-any-user");
        }
        let client_id = self.oidc_client_id.clone().expect("clap requires it");
        let public = self.public_url.clone().expect("clap requires it");
        let secret = match &self.oidc_client_secret_file {
            Some(f) => Some(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?.trim().to_string()),
            None => None,
        };
        Ok(Some(server::oidc::OidcConfig {
            issuer: issuer.clone(),
            api_audience: self.oidc_api_audience.clone().unwrap_or_else(|| client_id.clone()),
            client_id,
            client_secret: secret,
            redirect_url: format!("{}/oidc/callback", public.trim_end_matches('/')),
            scopes: self.oidc_scopes.split_whitespace().map(str::to_string).collect(),
            user_claim: self.oidc_user_claim.clone(),
            groups_claim: self.oidc_groups_claim.clone(),
            allowed_users: self.oidc_allowed_users.iter().map(|u| u.trim().to_string()).collect(),
            allowed_groups: self.oidc_allowed_groups.iter().map(|g| g.trim().to_string()).collect(),
            allow_any_user: self.oidc_allow_any_user,
            ca_cert: self.oidc_ca_cert.clone(),
            name: self.oidc_name.clone(),
        }))
    }
}

#[derive(Args)]
struct ClientArgs {
    #[command(flatten)]
    ceph: CephArgs,
    /// the server, as https://host:port
    #[arg(short, long)]
    server: String,
    #[arg(long, default_value = "/etc/rgw-integrity/client.token")]
    token_file: PathBuf,
    /// the CA that signed the server's certificate
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// accept any server certificate; only for tests
    #[arg(long)]
    insecure: bool,
    /// the name this client reports; the host name by default
    #[arg(long)]
    name: Option<String>,
    /// exit once no scan is running and this client has nothing to do
    #[arg(long)]
    once: bool,
}

#[derive(Args)]
struct ImportArgs {
    #[arg(short, long)]
    server: String,
    #[arg(long, default_value = "/etc/rgw-integrity/admin.token")]
    token_file: PathBuf,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    insecure: bool,
    /// findings, one JSON object per line
    file: PathBuf,
}

/// How to reach the cluster, and what the findings are judged against.
#[derive(Args, Clone)]
struct CephArgs {
    /// the Ceph config file
    #[arg(short, long, default_value = "/etc/ceph/ceph.conf", env = "CEPH_CONF")]
    conf: PathBuf,
    /// the client id to connect as ( client.<id> ); client.admin by default
    #[arg(long)]
    id: Option<String>,
    #[arg(long, default_value = "radosgw-admin")]
    radosgw_admin: String,
    /// data pool(s) to stat in, instead of the zone's; 'pool' or 'pool:namespace'
    #[arg(short, long)]
    pool: Vec<String>,
    /// a TOML file of issues that add to or replace the built-in catalog
    #[arg(long)]
    catalog: Option<PathBuf>,
    /// the cluster's release, as a name ( reef, squid, tentacle ) or major
    /// version, instead of `ceph versions`
    #[arg(long)]
    release: Option<String>,
    /// ceph/ceph pull request numbers of fixes the build carries
    #[arg(long, value_delimiter = ',')]
    fixed: Vec<u32>,
    /// the date ( YYYY-MM-DD ) those fixes were deployed; newer findings whose
    /// causes are all fixed are flagged after_fix
    #[arg(long)]
    fixed_since: Option<String>,
}

#[derive(Args)]
struct CheckArgs {
    /// skip findings younger than this many seconds, which may belong to
    /// requests in flight
    #[arg(long, default_value_t = 3600)]
    grace: i64,
    /// compare each index entry's ETag with its head's ( one xattr read per object )
    #[arg(short = 'I', long)]
    check_index: bool,
    /// read each tail object's refcount ( one xattr read per tail object )
    #[arg(short = 'R', long)]
    refcount: bool,
    /// do not read the GC queue
    #[arg(short = 'G', long)]
    no_gc: bool,
    /// do not read each bucket's open multipart uploads
    #[arg(short = 'U', long)]
    no_uploads: bool,
    /// only S3 objects whose key starts with this
    #[arg(short, long)]
    r#match: Option<String>,
    /// concurrent head reads of the index check
    #[arg(short = 'T', long, default_value_t = 32)]
    threads: usize,
    /// find orphans: list the data pools, and keep what no bucket references
    /// ( scans every bucket )
    #[arg(long)]
    find_orphans: bool,
}

impl CheckArgs {
    fn options(&self) -> Options {
        Options {
            grace: self.grace,
            check_index: self.check_index,
            refcount: self.refcount,
            uploads: !self.no_uploads,
            match_prefix: self.r#match.clone(),
            threads: self.threads,
            orphans: self.find_orphans,
        }
    }
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    ceph: CephArgs,
    #[command(flatten)]
    checks: CheckArgs,
    /// bucket(s) to scan; every bucket by default
    #[arg(short, long)]
    bucket: Vec<String>,
    /// a file of bucket names, one per line
    #[arg(short = 'l', long)]
    bucket_file: Option<PathBuf>,
    /// classify the orphans in this rgw-orphan-list output file, instead of
    /// scanning buckets
    #[arg(short = 'O', long)]
    orphans: Option<PathBuf>,
    /// the findings file, one JSON object per line
    #[arg(short = 'J', long, default_value = "rgw-integrity-findings.jsonl")]
    findings: PathBuf,
    /// the `s3://bucket/key MISSING <oid>` lines of rgw-gap-list
    #[arg(short = 'o', long, default_value = "rgw-integrity-missing.txt")]
    missing: PathBuf,
    /// RADOS operations in flight at once
    #[arg(short, long, default_value_t = 1024)]
    inflight: usize,
    /// buckets scanned at once
    #[arg(long, default_value_t = 4)]
    parallel: usize,
    /// where --find-orphans keeps its partitions; a new directory under the
    /// system's temporary directory by default
    #[arg(long)]
    work_dir: Option<PathBuf>,
    #[command(flatten)]
    sizing: SizingArgs,
}

/// Orphan detection's sizing, instead of one partition per million objects
/// and one pool slice per half million.
#[derive(Args, Clone, Copy, Default)]
struct SizingArgs {
    #[arg(long)]
    orphan_partitions: Option<u32>,
    /// slices of each data pool
    #[arg(long)]
    orphan_slices: Option<usize>,
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("rgw_integrity={level}")));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}

pub fn release_majors(release: &str) -> Result<BTreeSet<u32>> {
    let r = release.trim().to_lowercase();
    let major = match r.as_str() {
        "reef" => 18,
        "squid" => 19,
        "tentacle" => 20,
        "umbrella" | "main" => 21,
        n => n.parse().with_context(|| format!("unknown release {release}; use reef, squid, tentacle, main or a major version"))?,
    };
    Ok([major].into())
}

fn admin_of(ceph: &CephArgs) -> Admin {
    Admin { program: ceph.radosgw_admin.clone(), conf: Some(ceph.conf.clone()), id: ceph.id.clone() }
}

fn context_of(ceph: &CephArgs, majors: BTreeSet<u32>) -> Result<Context> {
    Ok(Context {
        catalog: Catalog::load(ceph.catalog.as_deref())?,
        majors,
        fixed: ceph.fixed.iter().copied().collect(),
        fixed_since: ceph
            .fixed_since
            .as_deref()
            .map(|d| oid::parse_time(&format!("{d} 00:00:00")).context("--fixed-since is YYYY-MM-DD"))
            .transpose()?,
    })
}

/// Connect to the cluster: its data, extra and index pools.
#[cfg(feature = "ceph")]
async fn connect(ceph: &CephArgs) -> Result<(Arc<dyn store::Store>, Arc<Admin>)> {
    let admin = Arc::new(admin_of(ceph));
    let zone = admin.zone_pools().await.unwrap_or_else(|e| {
        tracing::error!("cannot read the zone ( {e:#} ); using the default pools");
        admin::ZonePools {
            data: vec!["default.rgw.buckets.data".into()],
            extra: vec!["default.rgw.buckets.non-ec".into()],
            index: [("default-placement".to_string(), "default.rgw.buckets.index".to_string())].into(),
        }
    });
    // as rgw-gap-list.py does, stat in the extra pools too
    let data: Vec<String> = if ceph.pool.is_empty() {
        zone.data.iter().chain(zone.extra.iter().filter(|e| !zone.data.contains(e))).cloned().collect()
    } else {
        ceph.pool.clone()
    };
    tracing::info!("stat pools {data:?}, extra pools {:?}", zone.extra);
    let (conf, id) = (ceph.conf.clone(), ceph.id.clone());
    let cluster = tokio::task::spawn_blocking(move || rados::Cluster::connect(Some(&conf), id.as_deref())).await??;
    let store: Arc<dyn store::Store> = Arc::new(rados::RadosStore::new(cluster, &data, &zone.extra, zone.index)?);
    Ok((store, admin))
}

#[cfg(not(feature = "ceph"))]
async fn connect(_ceph: &CephArgs) -> Result<(Arc<dyn store::Store>, Arc<Admin>)> {
    anyhow::bail!("this build has no librados; rebuild with the ceph feature")
}

/// Connect, and set up the checks.
async fn engine(ceph: &CephArgs, opts: Options, inflight: usize, gc: bool) -> Result<Arc<Engine>> {
    let (store, admin) = connect(ceph).await?;
    let majors = match &ceph.release {
        Some(r) => release_majors(r)?,
        None => store.majors().await.unwrap_or_else(|e| {
            tracing::error!("cannot read `ceph versions` ( {e:#} ); considering every known issue");
            BTreeSet::new()
        }),
    };
    tracing::info!("considering the issues of major version(s) {majors:?}");
    let ctx = context_of(ceph, majors)?;
    let gc_min_wait = store.conf_get("rgw_gc_obj_min_wait").and_then(|v| v.parse().ok()).unwrap_or(7200);
    let gc = if gc {
        let gc = GcIndex::load(&admin).await?;
        tracing::info!("read {} GC entries naming {} objects", gc.entries, gc.map.len());
        gc
    } else {
        GcIndex::default()
    };
    Ok(Arc::new(Engine {
        store,
        admin,
        ctx: Arc::new(ctx),
        gc: RwLock::new(Arc::new(gc)),
        gc_min_wait,
        limiter: limiter::Limiter::new(inflight),
        opts,
        partitions: None,
    }))
}

async fn all_bucket_stats(admin: &Admin) -> Result<HashMap<String, BucketStats>> {
    let mut stats = HashMap::new();
    let mut rx = admin.all_bucket_stats();
    while let Some(st) = rx.recv().await {
        let st = st?;
        stats.insert(st.name(), st);
    }
    Ok(stats)
}

struct Output {
    findings: BufWriter<File>,
    missing: BufWriter<File>,
    tally: Tally,
    gaps: u64,
}

impl Output {
    fn finding(&mut self, f: &finding::Finding) -> Result<()> {
        self.tally.add(f);
        writeln!(self.findings, "{}", serde_json::to_string(f)?)?;
        Ok(())
    }
}

fn summarize(t: &Tally, findings: &std::path::Path) {
    if t.classes.is_empty() {
        eprintln!("No findings.");
    } else {
        let classes: Vec<String> =
            finding::Class::ALL.iter().filter_map(|c| t.classes.get(c.as_str()).map(|n| format!("{n} {c}"))).collect();
        eprintln!("Findings: {}", classes.join(", "));
        let mut causes: Vec<_> = t.causes.iter().collect();
        causes.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        eprintln!("Most likely causes: {}", causes.iter().map(|(c, n)| format!("{n} {c}")).collect::<Vec<_>>().join(", "));
        eprintln!("Findings are in {}", findings.display());
    }
    if !t.skipped.is_empty() {
        eprintln!("Skipped: {}", t.skipped.iter().map(|(r, n)| format!("{n} {r}")).collect::<Vec<_>>().join(", "));
    }
}

/// List the data pools into the partitions, and join each with the
/// references the bucket scans filed.
async fn find_orphans(
    engine: &Arc<Engine>,
    pools: &[String],
    counts: &HashMap<String, u64>,
    partitions: u32,
    slices_per_pool: Option<usize>,
    shuffle: Arc<dyn shuffle::Shuffle>,
    started: i64,
    parallel: usize,
) -> Result<(Vec<finding::Finding>, Tally)> {
    let mut slices = Vec::new();
    for pool in pools {
        let n = slices_per_pool.unwrap_or_else(|| detect::slices_for(counts.get(pool.split(':').next().unwrap_or(pool)).copied().unwrap_or(0))).max(1);
        slices.extend((0..n).map(|i| detect::Slice { pool: pool.clone(), slice: i, slices: n }));
    }
    let listed: Vec<Result<u64>> = futures::StreamExt::collect(futures::StreamExt::buffer_unordered(
        futures::stream::iter(slices.into_iter().map(|sl| {
            let (engine, shuffle) = (engine.clone(), shuffle.clone());
            async move { list_slice(&engine, &sl, partitions, shuffle.as_ref(), 0, "local").await }
        })),
        parallel.max(1),
    ))
    .await;
    let listed: u64 = listed.into_iter().collect::<Result<Vec<_>>>()?.into_iter().sum();
    tracing::info!("listed {listed} objects");
    let stats = all_bucket_stats(&engine.admin).await?;
    let markers: HashMap<String, BucketStats> = stats.into_values().map(|s| (s.marker.clone(), s)).collect();
    let mut findings = Vec::new();
    let mut tally = Tally::default();
    let writers = vec!["local".to_string()];
    let mut candidates = Vec::new();
    for p in 0..partitions {
        let (c, js) = detect::join(shuffle.as_ref(), 0, p, &writers).await?;
        tracing::info!("partition {p}: {} listed, {} referenced, {} not", js.listed, js.references, js.unreferenced);
        candidates.extend(c);
        detect::cleanup(shuffle.as_ref(), 0, p, &writers).await?;
    }
    // an unlisted head and its tail can land in different partitions: classify them together
    for unit in detect::classification_units(candidates, 20_000) {
        let (f, t) = engine.classify_orphans(&unit, &markers, Some(started)).await;
        findings.extend(f);
        for (k, v) in t.skipped {
            *tally.skipped.entry(k).or_default() += v;
        }
    }
    Ok((findings, tally))
}

/// List one slice of a pool into the partitions.
pub async fn list_slice(engine: &Engine, sl: &detect::Slice, partitions: u32, shuffle: &dyn shuffle::Shuffle, scan: i64, writer: &str) -> Result<u64> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let store = engine.store.clone();
    let (pool, slice, slices) = (sl.pool.clone(), sl.slice, sl.slices);
    let lister = tokio::spawn(async move { store.list_slice(&pool, slice, slices, tx).await });
    let mut listing = detect::Listing::new(partitions);
    while let Some(names) = rx.recv().await {
        listing.add(names, shuffle, scan, writer).await?;
    }
    lister.await??;
    listing.finish(shuffle, scan, writer).await
}

async fn scan(args: ScanArgs) -> Result<()> {
    let engine = engine(&args.ceph, args.checks.options(), args.inflight, !args.checks.no_gc).await?;
    let mut out = Output {
        findings: BufWriter::new(File::create(&args.findings).with_context(|| format!("creating {}", args.findings.display()))?),
        missing: BufWriter::new(File::create(&args.missing).with_context(|| format!("creating {}", args.missing.display()))?),
        tally: Tally::default(),
        gaps: 0,
    };

    if let Some(path) = &args.orphans {
        let oids: Vec<String> = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?
            .lines()
            .filter_map(|l| l.trim().split('\t').next_back().map(str::to_string))
            .filter(|l| !l.is_empty())
            .collect();
        let stats = all_bucket_stats(&engine.admin).await?;
        let markers: HashMap<String, BucketStats> = stats.into_values().map(|s| (s.marker.clone(), s)).collect();
        tracing::info!("classifying {} orphans", oids.len());
        let (findings, tally) = engine.classify_orphans(&oids, &markers, None).await;
        for f in &findings {
            out.finding(f)?;
        }
        out.tally.skipped = tally.skipped;
    } else {
        let mut stats = HashMap::new();
        let buckets: Vec<String> = if !args.bucket.is_empty() || args.bucket_file.is_some() {
            let mut b = args.bucket.clone();
            if let Some(path) = &args.bucket_file {
                b.extend(std::fs::read_to_string(path)?.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string));
            }
            b
        } else {
            // every bucket's stats from one call, not one per bucket
            stats = all_bucket_stats(&engine.admin).await?;
            let mut names: Vec<String> = stats.keys().cloned().collect();
            names.sort();
            names
        };
        tracing::info!("scanning {} bucket(s)", buckets.len());
        // orphan detection: bucket scans file their references in local partitions
        let started = scan::now();
        let detection = if args.checks.find_orphans {
            if !args.bucket.is_empty() || args.bucket_file.is_some() || args.checks.r#match.is_some() {
                anyhow::bail!("--find-orphans needs every bucket's references: no --bucket, --bucket-file or --match");
            }
            let pools = engine.admin.zone_pools().await?.data;
            let counts = engine.store.pool_objects().await?;
            let objects: u64 = pools.iter().map(|p| counts.get(p.split(':').next().unwrap_or(p)).copied().unwrap_or(0)).sum();
            let partitions = args.sizing.orphan_partitions.unwrap_or_else(|| detect::partitions_for(objects)).max(1);
            let dir = args.work_dir.clone().unwrap_or_else(|| std::env::temp_dir().join(format!("rgw-integrity-{}", std::process::id())));
            let shuffle: Arc<dyn shuffle::Shuffle> = Arc::new(shuffle::LocalShuffle::new(dir.clone())?);
            tracing::info!("finding orphans among {objects} objects in {pools:?}, in {partitions} partitions under {}", dir.display());
            Some((pools, counts, partitions, shuffle, dir))
        } else {
            None
        };
        let engine = match &detection {
            Some((_, _, partitions, _, _)) => {
                let mut e = Arc::try_unwrap(engine).map_err(|_| anyhow::anyhow!("the engine is shared"))?;
                e.partitions = Some(*partitions);
                Arc::new(e)
            }
            None => engine,
        };
        let mut refs = RefLedger::default();
        let mut tasks = JoinSet::new();
        let mut queue = buckets.into_iter();
        loop {
            while tasks.len() < args.parallel.max(1) {
                let Some(b) = queue.next() else { break };
                let (engine, st) = (engine.clone(), stats.remove(&b));
                tasks.spawn(async move {
                    let r = engine.scan_bucket(&b, st).await;
                    (b, r)
                });
            }
            let Some(done) = tasks.join_next().await else { break };
            let (bucket, report) = done?;
            let mut report = match report {
                Ok(r) => r,
                Err(e) => {
                    if detection.is_some() {
                        anyhow::bail!("{bucket}: {e:#}; without its references, orphans cannot be told");
                    }
                    tracing::error!("{bucket}: {e:#}");
                    continue;
                }
            };
            if let (Some(r), Some((_, _, _, shuffle, _))) = (report.references.take(), &detection) {
                r.flush(shuffle.as_ref(), 0, "local").await?;
            }
            for e in &report.errors {
                tracing::error!("{bucket}: {e}");
            }
            for f in &report.findings {
                out.finding(f)?;
            }
            for line in &report.missing {
                writeln!(out.missing, "{line}")?;
            }
            out.gaps += report.gaps;
            for (k, v) in &report.tally.skipped {
                *out.tally.skipped.entry(k.clone()).or_default() += v;
            }
            refs.merge(report.refs);
            tracing::info!(
                "{bucket}: {} RADOS objects, {} missing, {} findings in {:.1} s",
                report.rados_objects,
                report.gaps,
                report.findings.len(),
                report.seconds
            );
        }
        for f in refs.resolve(&engine.ctx) {
            out.finding(&f)?;
        }
        if let Some((pools, counts, partitions, shuffle, dir)) = detection {
            let (findings, tally) =
                find_orphans(&engine, &pools, &counts, partitions, args.sizing.orphan_slices, shuffle, started, args.parallel).await?;
            for f in &findings {
                out.finding(f)?;
            }
            for (k, v) in tally.skipped {
                *out.tally.skipped.entry(k).or_default() += v;
            }
            if args.work_dir.is_none() {
                std::fs::remove_dir_all(&dir).ok();
            }
        }
    }

    out.findings.flush()?;
    out.missing.flush()?;
    summarize(&out.tally, &args.findings);
    if out.tally.classes.is_empty() {
        std::fs::remove_file(&args.findings).ok();
    }
    if out.gaps == 0 {
        std::fs::remove_file(&args.missing).ok();
    } else {
        eprintln!("{} missing RADOS objects are in {}", out.gaps, args.missing.display());
    }
    Ok(())
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if r == 0 { String::from_utf8_lossy(&buf[..end]).into_owned() } else { "unknown".into() }
}

async fn server(args: ServerArgs) -> Result<()> {
    let tls = match (args.tls_cert, args.tls_key) {
        (Some(c), Some(k)) => Some((c, k)),
        _ if args.insecure_http => None,
        _ => anyhow::bail!("give --tls-cert and --tls-key, or --insecure-http for a test"),
    };
    let client_token = server::token_file(&args.client_token_file)?;
    let admin_token = server::token_file(&args.admin_token_file)?;
    let (store, admin) = if args.no_ceph {
        (None, Arc::new(admin_of(&args.ceph)))
    } else {
        let (store, admin) = connect(&args.ceph).await?;
        (Some(store), admin)
    };
    let work_pool = args.work_pool.clone().or_else(|| {
        args.db.strip_prefix("ceph:").and_then(|r| r.split_once('/')).map(|(pool, _)| pool.split(':').next().unwrap_or(pool).to_string())
    });
    let opts = server::ServeOpts {
        listen: args.listen,
        tls,
        db: args.db,
        cephsqlite: args.cephsqlite,
        client_token,
        admin_token,
        work_pool,
        partitions: args.sizing.orphan_partitions,
        slices: args.sizing.orphan_slices,
        oidc: args.oidc.config()?,
        oidc_only: args.oidc.oidc_only,
        public_url: args.oidc.public_url.clone(),
    };
    server::serve(opts, admin, store, Catalog::load(args.ceph.catalog.as_deref())?).await
}

async fn client(args: ClientArgs) -> Result<()> {
    let token = std::fs::read_to_string(&args.token_file).with_context(|| format!("reading {}", args.token_file.display()))?;
    let (store, admin) = connect(&args.ceph).await?;
    let opts = client::ClientOpts {
        server: args.server,
        token: token.trim().to_string(),
        ca_cert: args.ca_cert,
        insecure: args.insecure,
        name: args.name.unwrap_or_else(hostname),
        once: args.once,
    };
    client::run(opts, store, admin).await
}

async fn import(args: ImportArgs) -> Result<()> {
    let token = std::fs::read_to_string(&args.token_file).with_context(|| format!("reading {}", args.token_file.display()))?;
    let body = std::fs::read_to_string(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let mut b = reqwest::Client::builder();
    if let Some(ca) = &args.ca_cert {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    if args.insecure {
        b = b.danger_accept_invalid_certs(true);
    }
    let resp = b
        .build()?
        .post(format!("{}/api/v1/import", args.server.trim_end_matches('/')))
        .bearer_auth(token.trim())
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("{}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }
    eprintln!("imported {} findings", resp.text().await?);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    // libcephsqlite reads the config from the environment; set it before any
    // thread starts
    if let Cmd::Server(a) = &cli.command {
        if a.db.starts_with("ceph:") {
            unsafe {
                std::env::set_var("CEPH_CONF", &a.ceph.conf);
                if let Some(id) = &a.ceph.id {
                    std::env::set_var("CEPH_ARGS", format!("--id {id}"));
                }
            }
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        match cli.command {
            Cmd::Scan(args) => scan(args).await,
            Cmd::Server(args) => server(args).await,
            Cmd::Client(args) => client(args).await,
            Cmd::Import(args) => import(args).await,
        }
    })
}
