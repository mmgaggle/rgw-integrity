//! rgw-integrity: find, and classify, what known RGW races leave behind in a
//! Ceph cluster.  One binary: a standalone `scan`, or a `server` that hands
//! out buckets to `client`s and keeps what they find.

mod admin;
mod finding;
mod json_stream;
mod limiter;
mod oid;
mod orphans;
#[cfg(feature = "ceph")]
mod rados;
mod scan;
mod store;

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "ceph")]
use std::sync::RwLock;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use tokio::task::JoinSet;

use crate::admin::{Admin, BucketStats};
use crate::finding::{Catalog, Context, Tally};
use crate::scan::{Engine, Options, RefLedger};
#[cfg(feature = "ceph")]
use crate::scan::GcIndex;

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

/// Connect, and set up the checks.
#[cfg(feature = "ceph")]
async fn engine(ceph: &CephArgs, opts: Options, inflight: usize, gc: bool) -> Result<Arc<Engine>> {
    use crate::store::Store;
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
    let store = Arc::new(rados::RadosStore::new(cluster, &data, &zone.extra, zone.index)?);
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
    }))
}

#[cfg(not(feature = "ceph"))]
async fn engine(_ceph: &CephArgs, _opts: Options, _inflight: usize, _gc: bool) -> Result<Arc<Engine>> {
    anyhow::bail!("this build has no librados; rebuild with the ceph feature")
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
        let (findings, tally) = engine.classify_orphans(&oids, &markers).await;
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
            let report = match report {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("{bucket}: {e:#}");
                    continue;
                }
            };
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match cli.command {
        Cmd::Scan(args) => scan(args).await,
    }
}
