//! rgw-integrity: find, and classify, what known RGW races leave behind in a
//! Ceph cluster.  One binary: a standalone `scan`, or a `server` that hands
//! out buckets to `client`s and keeps what they find.

mod admin;
mod client;
mod decode;
mod detect;
mod finding;
mod gaplist;
mod json_stream;
mod limiter;
mod native;
mod oid;
mod orphans;
#[cfg(feature = "ceph")]
mod rados;
mod proto;
mod scan;
mod server;
mod shuffle;
mod store;
mod verify;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Scan buckets from this host, writing findings and the gap list to files
    ///
    /// Scan buckets from this host, writing findings and the gap list to
    /// files.  Copies on several hosts do not share the work ( each scans
    /// every bucket it is given ): for that, run a server and clients.
    #[command(after_help = SCAN_EXIT_STATUS)]
    Scan(ScanArgs),
    /// Hand out buckets to clients, keep what they find, and serve the dashboard
    Server(ServerArgs),
    /// Scan the buckets a server leases to this host
    Client(ClientArgs),
    /// Send findings to a server: rgw-integrity scan's, or rgw-gap-list.py's
    /// results, which become unverified findings for a scan to check ( a gap
    /// the server has recorded already, even one a scan marked gone, is kept
    /// as it is )
    Import(ImportArgs),
    /// List a bucket's RADOS objects, in radosgw-admin bucket radoslist
    /// --rgw-obj-fs's columns
    ///
    /// List a bucket's RADOS objects, from its index shards and manifests,
    /// and those of its Swift large objects' segments in other buckets: a
    /// line per object in radosgw-admin bucket radoslist --rgw-obj-fs's
    /// columns ( oid, bucket, key ), a tenant's bucket as tenant/bucket, and
    /// an open upload's parts ( which radoslist leaves out ) as bare oids.  It
    /// lists no delete marker's head, which does not exist, and names a
    /// versioned '_' key's OLH as it is stored ( see the README's Listing ).
    List(ListArgs),
    /// Stat the RADOS objects of gap lists again, as rgw-gap-list.py -x
    /// does, and keep the lines of what is still missing, but for delete
    /// markers ( what rgw-gap-verify-versioned.sh meant to drop ); exits
    /// non-zero if anything is still missing or could not be verified
    Verify(VerifyArgs),
}

#[derive(Args)]
struct VerifyArgs {
    #[command(flatten)]
    ceph: CephArgs,
    /// the lines of what is still missing, `s3://<bucket>/<key> STILL MISSING
    /// <oid>`, and, as they were, of what could not be statted; not written
    /// when there are none ( an earlier one is removed, unless it is an input )
    #[arg(short, long, default_value = "rgw-integrity-still-missing.txt")]
    output: PathBuf,
    /// keep the lines of delete markers: do not look up the index entries of
    /// the heads still missing ( one radosgw-admin bi list per key )
    #[arg(long)]
    keep_delete_markers: bool,
    /// RADOS operations in flight at once
    #[arg(short, long, default_value_t = 1024)]
    inflight: usize,
    /// gap lists, of any mix: rgw-integrity scan's -o file; rgw-gap-list.py's
    /// results ( v2.2, or v3.0's text or JSON records ), of its -x verify, of
    /// rgw-gap-verify-versioned.sh or rgw-gap-list-by-bucket; or this
    /// command's output
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

/// A scan that ran, but did not scan every bucket unit in full ( not 2,
/// clap's status for a command line it refuses, when nothing ran ).
const EXIT_INCOMPLETE: u8 = 3;
/// A scan a signal stopped before every bucket unit was scanned.
const EXIT_INTERRUPTED: u8 = 4;

const SCAN_EXIT_STATUS: &str = "Exit status: 0 when every bucket unit was scanned in full, findings or not; 1 when the scan \
could not run or stopped on an error; 2 when the command line is refused, and nothing ran; 3 when some units failed or \
had any error ( objects not checked, a listing cut short, a bucket deleted while the scan ran ), so what they found is \
partial; 4 when a signal stopped it before it was done ( units left unscanned, or orphan detection not run ).";

#[derive(Args)]
struct ListArgs {
    #[command(flatten)]
    ceph: CephArgs,
    /// not empty: radosgw-admin takes an empty --bucket for every bucket
    #[arg(short, long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    bucket: String,
    /// only this index shard
    #[arg(long)]
    shard: Option<u32>,
    /// run radosgw-admin bucket radoslist instead, to compare
    #[arg(long, conflicts_with = "shard")]
    radoslist: bool,
    /// between the RADOS object, the bucket and the key
    #[arg(long, default_value = "\t")]
    separator: String,
    /// RADOS operations in flight at once: the reads of heads, manifests and
    /// upload records, not the paging of index shards
    #[arg(long, default_value_t = 256)]
    inflight: usize,
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
    /// the pool clients exchange orphan detection's partitions in, as a
    /// pool spec ( as --pool's: a ':' or '\' in its name escaped by a '\' ),
    /// whose namespace, if it has one, is replaced by rgw-integrity-work;
    /// the database's pool by default
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
    /// rgw-integrity scan's findings, one JSON object per line; or the
    /// results of rgw-gap-list.py ( `s3://<bucket>/<key> MISSING <oid>` ), of
    /// its -x verify, of rgw-gap-verify-versioned.sh or rgw-gap-list-by-bucket,
    /// or v3.0's JSON results records ( as its unfinished results objects
    /// would hold them ).  A tenant's `s3://t/b/<key>` part and tail lines
    /// import under t/b beside the head's line, or when the server's
    /// `radosgw-admin bucket list` names a bucket t/b; else under bucket t (
    /// see the README's Import )
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
    /// the most radosgw-admin commands this process runs at once: per-object
    /// lookups ( index entries, manifests, lifecycles; verify's delete-marker
    /// lookups at most 16 of them ) and per-bucket calls ( bucket stats, bucket
    /// list, zone get, metadata get ).  The streamed listings ( a unit's, bucket
    /// stats of every bucket, gc list ) are not counted
    #[arg(long, default_value_t = admin::DEFAULT_CONCURRENCY, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    admin_concurrency: usize,
    /// data pool(s) to stat in, instead of the zone's: repeat -p, or give one
    /// space-separated list as rgw-gap-list.py does.  Each is 'pool' or
    /// 'pool:namespace', with a ':' or '\' in either escaped by a '\', as the
    /// zone writes them ( and a space by a '\' too ).  The zone's extra pools
    /// are still searched for upload meta objects.  Without --pool the zone
    /// must be readable and list data pools
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

impl CephArgs {
    /// --pool's specs: each value split at whitespace no '\' escapes, as
    /// rgw-gap-list.py splits -p, with empty items dropped and the escapes kept
    /// for store::parse_pool()
    #[cfg_attr(not(feature = "ceph"), allow(dead_code))]
    fn pools(&self) -> Vec<String> {
        let mut pools = Vec::new();
        for value in &self.pool {
            let (mut spec, mut esc) = (String::new(), false);
            for c in value.chars() {
                if !esc && c.is_whitespace() {
                    if !spec.is_empty() {
                        pools.push(std::mem::take(&mut spec));
                    }
                    continue;
                }
                esc = !esc && c == '\\';
                spec.push(c);
            }
            if !spec.is_empty() {
                pools.push(spec);
            }
        }
        pools
    }
}

#[derive(Args)]
struct CheckArgs {
    /// report findings on objects younger than this many seconds only on a
    /// later scan: they may belong to requests in flight.  Their gaps are
    /// still in -o's file.  0 reports them at once, as rgw-gap-list does
    #[arg(long, default_value_t = 3600)]
    grace: i64,
    /// compare each index entry's ETag with its head's ( one xattr read per object )
    #[arg(short = 'I', long)]
    check_index: bool,
    /// read each tail object's refcount ( one xattr read per tail object; with
    /// -m, also of the objects outside the prefix, whose heads may carry the
    /// references of the tails inside it )
    #[arg(short = 'R', long)]
    refcount: bool,
    /// do not read the GC queue
    #[arg(short = 'G', long)]
    no_gc: bool,
    /// do not read each bucket's open multipart uploads
    #[arg(short = 'U', long)]
    no_uploads: bool,
    /// only S3 objects whose key ( name, or name[instance] for a version )
    /// starts with this literal prefix, as S3 listings take one: trimmed, as
    /// rgw-gap-list's -m, and every key when blank.  rgw-gap-list's -m is a
    /// word-boundary regex instead, and so skips e.g. foobar under -m foo, or
    /// every key under -m /x.  The native listing reads only the index
    /// entries under the prefix, in every shard, so the listing costs what
    /// the keys under it do ( --radoslist and --refcount still list whole
    /// buckets, and filter )
    #[arg(short, long, visible_alias = "prefix", value_name = "PREFIX")]
    r#match: Option<String>,
    /// concurrent head reads of the index check
    #[arg(short = 'T', long, default_value_t = 32)]
    threads: usize,
    /// find orphans: list the pools the scan stats in ( --pool's, or the
    /// zone's data and extra pools ), and keep what no bucket references (
    /// scans every bucket; refused when radosgw-admin bucket stats cannot
    /// read a bucket, as its objects would be taken for orphans, and stopped
    /// when a bucket's listing, or with --radoslist its open uploads, cannot
    /// be read in full )
    #[arg(long)]
    find_orphans: bool,
    /// list buckets with radosgw-admin bucket radoslist, instead of reading
    /// their index shards and manifests natively
    #[arg(long)]
    radoslist: bool,
}

impl CheckArgs {
    /// -m, trimmed and none when blank; warn when that changed what was typed.
    fn match_prefix(&self) -> Option<String> {
        let p = scan::normalise_prefix(self.r#match.as_deref());
        if let Some(m) = self.r#match.as_deref().filter(|m| Some(*m) != p.as_deref()) {
            match &p {
                Some(p) => tracing::warn!("-m {m:?} trimmed to {p:?}"),
                None => tracing::warn!("-m {m:?} is blank: checking every key"),
            }
        }
        p
    }

    fn options(&self) -> Options {
        Options {
            grace: self.grace,
            check_index: self.check_index,
            refcount: self.refcount,
            uploads: !self.no_uploads,
            match_prefix: self.match_prefix(),
            threads: self.threads,
            orphans: self.find_orphans,
            listing: if self.radoslist { scan::Listing::Radoslist } else { scan::Listing::Native },
            // scan() sets it: it knows whether it names buckets
            every_bucket: false,
        }
    }
}

#[derive(Args)]
struct ScanArgs {
    #[command(flatten)]
    ceph: CephArgs,
    #[command(flatten)]
    checks: CheckArgs,
    /// bucket(s) to scan, repeated or space separated as rgw-gap-list's -b;
    /// every bucket by default, and -b and -l add up ( a bucket named more
    /// than once is scanned once ).  Not empty: radosgw-admin takes an empty
    /// --bucket for every bucket
    #[arg(short, long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    bucket: Vec<String>,
    /// a file of bucket names, one per line, trimmed but not split: a Swift
    /// container may have spaces in its name.  Blank lines are skipped, and a
    /// file that names none is an error
    #[arg(short = 'l', long)]
    bucket_file: Option<PathBuf>,
    /// classify the orphans in this rgw-orphan-list output file, instead of
    /// scanning buckets
    #[arg(short = 'O', long)]
    orphans: Option<PathBuf>,
    /// the findings file, one JSON object per line
    #[arg(short = 'J', long, default_value = "rgw-integrity-findings.jsonl")]
    findings: PathBuf,
    /// the gap list: rgw-gap-list's `s3://bucket/key MISSING <oid>` lines, a
    /// tenant's bucket written tenant/bucket, as v3.0 writes it ( v2.2 writes
    /// the bucket alone; rgw-gap-verify-versioned.sh cannot check those
    /// lines, rgw-integrity verify can ).  Every gap but what is none at
    /// all ( a delete marker's head, radoslist's misnamed OLH, a key deleted
    /// during the scan ): gaps too young ( --grace ) or in flight to judge
    /// are in it, with no finding yet, and counted under Skipped.  -J is the
    /// checked, classified list.  -J and -o are locked while the scan runs:
    /// another scan in the same directory needs its own
    #[arg(short = 'o', long, default_value = "rgw-integrity-missing.txt")]
    missing: PathBuf,
    /// record each bucket unit the scan finishes in this file, one JSON object
    /// per line ( bucket, shard, shards, finished, rados_objects, gaps,
    /// findings, errors, the checks run, the unit's -J and -o lines, and the
    /// buckets it relied on for Swift segments ), for --maxage to resume
    /// from.  Appended to, locked while the scan runs, and cut to each unit's
    /// latest record when the scan starts
    #[arg(long, conflicts_with = "orphans")]
    state: Option<PathBuf>,
    /// skip the bucket units --state records as finished without errors this
    /// many seconds ago or less, with the same checks and index shard count
    /// ( as rgw-gap-list's -a ), but for one whose Swift large objects'
    /// segments it followed into a bucket that scan did not list, or left to
    /// a bucket this one does not name.  -J and -o still start empty: the
    /// lines the skipped units' records carry are written to them first, so
    /// they hold the whole result, each followed segment's lines once, and
    /// nothing an earlier scan of a rescanned unit found.  A record without
    /// the segment fields ( of an older rgw-integrity ) is passed over, and
    /// its unit rescanned.  With units skipped, the refcount check's
    /// references go unresolved
    #[arg(short = 'a', long, value_name = "SECS", requires = "state", conflicts_with = "find_orphans")]
    maxage: Option<u64>,
    /// RADOS operations in flight at once, shared by the --parallel units:
    /// stats, and the reads of heads, manifests, upload records, refcounts
    /// and single index entries, not the paging of index shards (
    /// rgw-gap-list's -i, 10000 by default, bounds its process's stats, of
    /// one bucket at a time )
    #[arg(short, long, default_value_t = 1024)]
    inflight: usize,
    /// bucket units ( buckets, or index shards of big ones ) scanned at
    /// once; and -b and -l buckets' stats read at once, to find the big ones
    #[arg(long, default_value_t = 4)]
    parallel: usize,
    /// where --find-orphans keeps its partitions: in a new directory of the
    /// scan's own under it ( the system's temporary directory by default ),
    /// removed however the scan ends
    #[arg(long)]
    work_dir: Option<PathBuf>,
    #[command(flatten)]
    sizing: SizingArgs,
}

impl ScanArgs {
    /// --find-orphans needs every bucket and every key: `opts` holds the -m
    /// actually used, so a blank one is no filter here either.
    fn orphans_scope(&self, opts: &Options) -> Result<()> {
        if !self.bucket.is_empty() || self.bucket_file.is_some() || opts.match_prefix.is_some() {
            anyhow::bail!("--find-orphans needs every bucket's references: no --bucket, --bucket-file or --match ( --prefix )");
        }
        Ok(())
    }
}

/// Orphan detection's sizing, instead of one partition per million objects
/// and one pool slice per half million.
#[derive(Args, Clone, Copy, Default)]
struct SizingArgs {
    /// scan a bucket of more S3 objects than this a shard at a time: each
    /// index shard a unit of its own ( with the native listing )
    #[arg(long, default_value_t = 100_000)]
    shard_units_above: u64,
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
    Admin::new(ceph.radosgw_admin.clone(), Some(ceph.conf.clone()), ceph.id.clone(), ceph.admin_concurrency)
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

/// The pools to stat heads and tails in, and the zone's pools, from the zone
/// ( or why it could not be read ) and --pool's specs.  Without --pool the zone
/// must have been read and list data pools: statting in guessed pools would
/// report every object of a bucket stored elsewhere as missing.  With it, an
/// unreadable zone leaves the default extra and index pools.  As rgw-gap-list.py
/// does, the zone's extra pools are statted in too.
#[cfg_attr(not(feature = "ceph"), allow(dead_code))]
fn stat_pools(zone: Result<admin::ZonePools>, pool: &[String]) -> Result<(Vec<String>, admin::ZonePools)> {
    match zone {
        Ok(zone) if !pool.is_empty() => Ok((pool.to_vec(), zone)),
        Ok(zone) if zone.data.is_empty() => anyhow::bail!("the zone lists no data pools; give them with --pool"),
        Ok(zone) => {
            let data = zone.data.iter().chain(zone.extra.iter().filter(|e| !zone.data.contains(e))).cloned().collect();
            Ok((data, zone))
        }
        Err(e) if pool.is_empty() => anyhow::bail!("cannot read the zone ( {e:#} ); give the data pools with --pool"),
        Err(e) => {
            tracing::warn!("cannot read the zone ( {e:#} ); using the default extra and index pools");
            let zone = admin::ZonePools {
                data: Vec::new(),
                extra: vec!["default.rgw.buckets.non-ec".into()],
                index: [("default-placement".to_string(), "default.rgw.buckets.index".to_string())].into(),
            };
            Ok((pool.to_vec(), zone))
        }
    }
}

/// Connect to the cluster: its data, extra and index pools.
#[cfg(feature = "ceph")]
async fn connect(ceph: &CephArgs) -> Result<(Arc<dyn store::Store>, Arc<Admin>)> {
    let admin = Arc::new(admin_of(ceph));
    // a failed zone get is transient or a broken setup; try again before giving up
    let mut zone = admin.zone_pools().await;
    for delay in [1, 2] {
        let Err(e) = &zone else { break };
        tracing::warn!("cannot read the zone ( {e:#} ); trying again in {delay}s");
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        zone = admin.zone_pools().await;
    }
    let (data, zone) = stat_pools(zone, &ceph.pools())?;
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
    let engine = Engine {
        store,
        admin,
        ctx: Arc::new(ctx),
        gc: RwLock::new(Arc::new(gc)),
        gc_min_wait,
        limiter: limiter::Limiter::new(inflight),
        opts,
        partitions: None,
        segments: Default::default(),
    };
    engine.note_listing();
    Ok(Arc::new(engine))
}

/// The -J and -o files of a scan.  Dropped, however the scan ends, it removes
/// those that hold nothing, before letting go of their locks.
struct Output {
    findings: BufWriter<File>,
    missing: BufWriter<File>,
    paths: [PathBuf; 2],
    tally: Tally,
    gaps: u64,
}

impl Output {
    /// Open and lock -J and -o ( see open_locked() ); nothing is truncated
    /// until start().
    fn open(findings_path: &Path, missing: &Path) -> Result<Output> {
        use std::os::unix::fs::MetadataExt;
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        let findings = open_locked(findings_path, &opts, "-J")?;
        let f = findings.metadata()?;
        let opened = if std::fs::metadata(missing).is_ok_and(|m| m.dev() == f.dev() && m.ino() == f.ino()) {
            Err(anyhow::anyhow!("-J and -o name the same file, {}", missing.display()))
        } else {
            open_locked(missing, &opts, "-o")
        };
        let missing_file = match opened {
            Ok(m) => m,
            Err(e) => {
                // still locked: a -J this scan made goes with it
                if f.len() == 0 {
                    std::fs::remove_file(findings_path).ok();
                }
                return Err(e);
            }
        };
        Ok(Output {
            findings: BufWriter::new(findings),
            missing: BufWriter::new(missing_file),
            paths: [findings_path.to_path_buf(), missing.to_path_buf()],
            tally: Tally::default(),
            gaps: 0,
        })
    }

    /// Start writing, over what the files hold.
    fn start(&mut self) -> Result<()> {
        for w in [&mut self.findings, &mut self.missing] {
            w.get_mut().set_len(0)?;
        }
        Ok(())
    }

    fn finding(&mut self, f: &finding::Finding) -> Result<()> {
        self.tally.add(f);
        writeln!(self.findings, "{}", serde_json::to_string(f)?)?;
        Ok(())
    }

    /// Write again what a unit --maxage skips found, as its record carries it.
    fn carry(&mut self, r: &UnitRecord) -> Result<()> {
        for f in &r.found {
            self.finding(f)?;
        }
        for line in &r.missing {
            writeln!(self.missing, "{line}")?;
        }
        self.gaps += r.gaps;
        Ok(())
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        // the files are locked: another scan cannot have written to them
        for (w, path) in [&mut self.findings, &mut self.missing].into_iter().zip(&self.paths) {
            if w.flush().is_ok() && is_empty(w) {
                std::fs::remove_file(path).ok();
            }
        }
    }
}

/// Remove those of the files at `paths` that hold nothing: a scan's -J and
/// -o, still locked, when it exits without dropping its Output.
fn remove_empty(paths: &[PathBuf]) {
    for path in paths {
        if std::fs::metadata(path).is_ok_and(|m| m.len() == 0) {
            std::fs::remove_file(path).ok();
        }
    }
}

/// Whether a file holds nothing, this scan's lines or an earlier one's.
fn is_empty(w: &BufWriter<File>) -> bool {
    w.get_ref().metadata().is_ok_and(|m| m.len() == 0)
}

/// Open a file for this scan alone: lock it, without waiting, before anything
/// is truncated or written, so a second scan in the same directory cannot
/// clobber the first's output, nor remove it as empty.  The lock lasts as long
/// as the file.
fn open_locked(path: &Path, opts: &OpenOptions, flag: &str) -> Result<File> {
    use std::os::unix::fs::MetadataExt;
    loop {
        let file = opts.open(path).with_context(|| format!("opening {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                anyhow::bail!("{} is in use by another rgw-integrity scan; give this one another {flag}", path.display())
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e).with_context(|| format!("locking {}", path.display())),
        }
        // the scan that held it may have removed it before letting go: then lock the one at the path now
        let (held, at) = (file.metadata()?, std::fs::metadata(path));
        if at.is_ok_and(|m| m.dev() == held.dev() && m.ino() == held.ino()) {
            return Ok(file);
        }
    }
}

/// A bucket unit a scan finished, as --state records it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct UnitRecord {
    bucket: String,
    /// the index shard, for a unit of one shard
    shard: Option<u32>,
    /// the bucket's index shards, when its stats were read before its scan
    shards: Option<u64>,
    /// when it finished, in seconds since the epoch
    finished: i64,
    rados_objects: u64,
    gaps: u64,
    findings: usize,
    errors: usize,
    /// the checks it ran ( see scope_of() )
    scope: String,
    /// its findings and -o lines, for a scan that skips it to write again (
    /// no default: a record without them is passed over, and its unit rescanned )
    found: Vec<finding::Finding>,
    missing: Vec<String>,
    /// the other buckets its Swift large objects' segments were left to, as
    /// the scan listed them, and whether it followed any into a bucket the
    /// scan did not list ( native::Depends; no default either )
    segments_left_to: BTreeSet<String>,
    segments_followed: bool,
}

/// The checks a scan runs, as its --state records name them: a unit scanned
/// with other checks, or another prefix, is not skipped.
fn scope_of(opts: &Options) -> String {
    serde_json::to_string(&Options { threads: 0, ..opts.clone() }).unwrap_or_default()
}

/// Each unit's latest record in a --state file, and whether the file holds
/// more lines than those; a line that does not parse ( a scan killed
/// mid-line ) is passed over.
fn latest_records(text: &str) -> (HashMap<(String, Option<u32>), UnitRecord>, bool) {
    let mut latest: HashMap<(String, Option<u32>), UnitRecord> = HashMap::new();
    let mut lines = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        lines += 1;
        let Ok(r) = serde_json::from_str::<UnitRecord>(line) else {
            tracing::warn!("passing over a --state line that does not parse: {line}");
            continue;
        };
        match latest.get(&(r.bucket.clone(), r.shard)) {
            Some(l) if l.finished > r.finished => {}
            _ => {
                latest.insert((r.bucket.clone(), r.shard), r);
            }
        }
    }
    let more = lines > latest.len();
    (latest, more)
}

/// Whether --maxage skips a unit: its latest record finished without errors,
/// `maxage` seconds before `now` or less, with the same checks and, for a
/// unit of one index shard, the same shard count ( a reshard moves keys
/// between shards ).  Its lines must be the whole of what a scan of it now
/// would report: so it followed no Swift segments into another bucket (
/// those lines may be another unit's, or this scan's again ), and `named`,
/// the buckets this scan names ( None: every one ), holds each it left
/// segments to.
fn recently_finished(
    latest: Option<&UnitRecord>,
    shards: Option<u64>,
    scope: &str,
    named: Option<&HashSet<String>>,
    now: i64,
    maxage: u64,
) -> bool {
    latest.is_some_and(|r| {
        r.errors == 0
            && r.scope == scope
            && now.saturating_sub(r.finished) <= maxage.min(i64::MAX as u64) as i64
            && (r.shard.is_none() || (shards.is_some() && r.shards == shards))
            && !r.segments_followed
            && named.is_none_or(|n| r.segments_left_to.iter().all(|b| n.contains(b)))
    })
}

/// The --state file: the latest record of each unit earlier scans finished,
/// and this one's, appended as each is done.
struct State {
    file: File,
    latest: HashMap<(String, Option<u32>), UnitRecord>,
}

impl State {
    fn open(path: &Path) -> Result<State> {
        let mut opts = OpenOptions::new();
        opts.read(true).append(true).create(true);
        let mut file = open_locked(path, &opts, "--state")?;
        let mut text = Vec::new();
        file.read_to_end(&mut text).with_context(|| format!("reading {}", path.display()))?;
        let (latest, more) = latest_records(&String::from_utf8_lossy(&text));
        if more {
            // records carry their lines: keep the latest of each unit, not every scan's ( a crash here loses
            // records, and their units are rescanned )
            let mut records: Vec<&UnitRecord> = latest.values().collect();
            records.sort_by(|a, b| (a.finished, &a.bucket, a.shard).cmp(&(b.finished, &b.bucket, b.shard)));
            let mut kept = String::new();
            for r in records {
                kept.push_str(&serde_json::to_string(r)?);
                kept.push('\n');
            }
            file.set_len(0).with_context(|| format!("cutting {}", path.display()))?;
            file.write_all(kept.as_bytes())?;
        } else if text.last().is_some_and(|b| *b != b'\n') {
            file.write_all(b"\n")?;
        }
        Ok(State { file, latest })
    }

    /// Record a finished unit, in one write, once its lines are in the output files.
    fn record(&mut self, r: &UnitRecord) -> Result<()> {
        let mut line = serde_json::to_string(r)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        Ok(())
    }
}

/// What a scan covered, for its closing line and exit status.
#[derive(Debug, Default)]
struct Coverage {
    /// the bucket units to scan ( those --maxage skips aside )
    units: usize,
    /// units whose scan failed, so found nothing
    failed: usize,
    /// units scanned with errors: objects not checked, or a listing cut short
    errored: usize,
    /// what a signal left undone
    interrupted: Option<String>,
}

impl Coverage {
    fn complete(&self) -> bool {
        self.failed == 0 && self.errored == 0 && self.interrupted.is_none()
    }

    /// The closing line and exit status of a scan that did not cover
    /// everything; None when it did.
    fn outcome(&self) -> Option<(String, u8)> {
        let partial = match (self.failed, self.errored) {
            (0, 0) => None,
            (f, 0) => Some(format!("{f} of {} bucket unit(s) failed", self.units)),
            (0, e) => Some(format!("{e} of {} bucket unit(s) had errors", self.units)),
            (f, e) => Some(format!("{f} of {} bucket unit(s) failed and {e} had errors", self.units)),
        }
        .map(|p| format!("{p}, so they are not fully checked; see the log"));
        match (&self.interrupted, partial) {
            (Some(i), p) => Some((format!("Interrupted: {i}{}", p.map(|p| format!("; {p}")).unwrap_or_default()), EXIT_INTERRUPTED)),
            (None, Some(p)) => Some((format!("Incomplete: {p}"), EXIT_INCOMPLETE)),
            (None, None) => None,
        }
    }
}

/// A scan that ran, but did not cover everything: its closing line, and the
/// exit status that tells automation so.
#[derive(Debug)]
struct Exit {
    code: u8,
    message: String,
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Exit {}

/// The status of a scan's running units, and of the whole, from their counters.
fn status_lines(running: &BTreeMap<String, Arc<AtomicU64>>, done: usize, units: usize, checked: u64) -> Vec<String> {
    let mut lines: Vec<String> =
        running.iter().map(|(unit, n)| format!("[status] {unit}: {} RADOS objects checked so far", n.load(Ordering::Relaxed))).collect();
    let total = checked + running.values().map(|n| n.load(Ordering::Relaxed)).sum::<u64>();
    lines.push(format!("[status] {done} of {units} bucket unit(s) done, {} running; {total} RADOS objects checked", running.len()));
    lines
}

/// Why the refcount check's references go unresolved, if they do: a head in
/// a unit not scanned ( one a signal left, or --maxage skipped ) may carry what
/// a tail needs, and resolving would report that tail unheld.  `needed`:
/// whether the scanned units took references at all.
fn unresolved_refs(unscanned: usize, skipped: usize, needed: bool) -> Option<&'static str> {
    (needed && (unscanned > 0 || skipped > 0)).then_some("the refcount check's references were not resolved")
}

/// A new directory for orphan detection's partitions, under `parent` (
/// --work-dir, or the system's temporary directory ): the scan's alone, as
/// partitions are appended to and joined whole, so an earlier scan's left
/// there would hide the orphans this one lists.
fn work_dir(parent: &Path, started: i64) -> Result<PathBuf> {
    std::fs::create_dir_all(parent).with_context(|| format!("making {}", parent.display()))?;
    let dir = parent.join(format!("rgw-integrity-{}-{started}", std::process::id()));
    std::fs::create_dir(&dir).with_context(|| format!("making {}", dir.display()))?;
    Ok(dir)
}

/// A directory the scan made, removed when it is done with it, or fails.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// The stats of the buckets named, `parallel` at a time, by name: one whose
/// stats cannot be read is left out, and scanned without them, as its unit
/// asks again and records why.
async fn named_stats(admin: &Admin, names: &[String], parallel: usize) -> HashMap<String, BucketStats> {
    use futures::StreamExt;
    futures::stream::iter(names)
        .map(|b| async move { (b.clone(), admin.bucket_stats(b).await) })
        .buffer_unordered(parallel.max(1))
        .filter_map(|(b, st)| async move { st.ok().map(|st| (b, st)) })
        .collect()
        .await
}

/// The buckets -b and -l name, each once in the order first named, or None
/// for every bucket.  Each -b is split on whitespace, as rgw-gap-list's
/// `-b "b1 b2"`: no S3 bucket name has any ( valid_s3_bucket_name, relaxed
/// or not ).  A Swift container's may, so -l lines are only trimmed, as
/// rgw-gap-list's are.
fn named_buckets(bucket: &[String], file: Option<&std::path::Path>) -> Result<Option<Vec<String>>> {
    if bucket.is_empty() && file.is_none() {
        return Ok(None);
    }
    let mut b = Vec::new();
    let mut split = None;
    for v in bucket {
        let before = b.len();
        b.extend(v.split_whitespace().map(str::to_string));
        match b.len() - before {
            // -b " ": radosgw-admin would take the empty name for every bucket
            0 => anyhow::bail!("an empty bucket name: -b {v:?}"),
            1 => {}
            n => split = split.or(Some((v, n))),
        }
    }
    if let Some((v, n)) = split {
        tracing::warn!("split -b {v:?} into {n} buckets, as rgw-gap-list does; name a bucket with spaces in -l");
    }
    if let Some(path) = file {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let before = b.len();
        b.extend(text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string));
        if b.len() == before {
            anyhow::bail!("{} names no bucket", path.display());
        }
    }
    // clap rejects an empty -b; this is the last guard before radosgw-admin lists every bucket as one
    if b.iter().any(String::is_empty) {
        anyhow::bail!("an empty bucket name");
    }
    // a bucket named twice is one unit: two would write its lines twice
    let (mut seen, named) = (HashSet::new(), b.len());
    b.retain(|n| seen.insert(n.clone()));
    if b.len() < named {
        tracing::warn!("{} bucket name(s) given more than once; scanning each once", named - b.len());
    }
    Ok(Some(b))
}

/// Count SIGINT and SIGTERM: the first sets `stop`, the second exits,
/// removing first `work`, the directory the scan made, and those of
/// `outputs`, its -J and -o, that hold nothing ( as Output's drop, which the
/// exit skips, would ).
fn stop_on_signal(work: Option<PathBuf>, outputs: [PathBuf; 2]) -> tokio::sync::watch::Receiver<bool> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        for n in 0.. {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            if n > 0 {
                tracing::warn!("exiting; the buckets already done are in the output files");
                if let Some(dir) = &work {
                    std::fs::remove_dir_all(dir).ok();
                }
                remove_empty(&outputs);
                std::process::exit(EXIT_INTERRUPTED.into());
            }
            tracing::warn!("interrupted: finishing the running buckets, and starting no more; signal again to exit now");
            tx.send_replace(true);
        }
    });
    rx
}

/// `complete`: whether every unit was scanned in full; if not, no findings
/// is no clean result.
fn summarize(t: &Tally, findings: &std::path::Path, complete: bool) {
    if t.classes.is_empty() {
        eprintln!("{}", if complete { "No findings." } else { "No findings in what was checked." });
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
        let n = slices_per_pool.unwrap_or_else(|| detect::slices_for(counts.get(&store::parse_pool(pool).0).copied().unwrap_or(0))).max(1);
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
    // a bucket that could not be read since the scan started would have its objects called orphans
    let markers = engine.admin.all_buckets().await?.markers()?;
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

/// Classify the orphans an rgw-orphan-list output file names, into `out`,
/// started only once the file and every bucket's markers are read: a scan
/// that cannot read them keeps an earlier scan's -J and -o.
async fn classify_listed(engine: &Engine, path: &Path, out: &mut Output) -> Result<()> {
    let oids: Vec<String> = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .lines()
        .filter_map(|l| l.trim().split('\t').next_back().map(str::to_string))
        .filter(|l| !l.is_empty())
        .collect();
    let markers = engine.admin.all_buckets().await?.markers()?;
    out.start()?;
    tracing::info!("classifying {} orphans", oids.len());
    let (findings, tally) = engine.classify_orphans(&oids, &markers, None).await;
    for f in &findings {
        out.finding(f)?;
    }
    out.tally.skipped = tally.skipped;
    Ok(())
}

async fn scan(args: ScanArgs) -> Result<()> {
    // a scope orphans cannot be told in is refused before anything is opened, or the listing described
    let mut opts = args.checks.options();
    // one that names no bucket lists every one
    opts.every_bucket = args.bucket.is_empty() && args.bucket_file.is_none();
    if args.checks.find_orphans && args.orphans.is_none() {
        args.orphans_scope(&opts)?;
    }
    // the files first: a scan whose files another holds stops before it connects
    let mut state = args.state.as_deref().map(State::open).transpose()?;
    let mut out = Output::open(&args.findings, &args.missing)?;
    let engine = engine(&args.ceph, opts, args.inflight, !args.checks.no_gc).await?;
    let mut coverage = Coverage::default();
    // the units --maxage skips, and what their records say they found
    let (mut resumed, mut resumed_findings, mut resumed_gaps) = (0usize, 0usize, 0u64);
    let mut unresolved = None;

    if let Some(path) = &args.orphans {
        classify_listed(&engine, path, &mut out).await?;
    } else {
        let mut stats: HashMap<String, BucketStats> = HashMap::new();
        let buckets: Vec<String> = if let Some(b) = named_buckets(&args.bucket, args.bucket_file.as_deref())? {
            // their stats, so a big one is scanned a shard at a time, as when every bucket is
            if engine.opts.listing == scan::Listing::Native {
                stats = named_stats(&engine.admin, &b, args.parallel).await;
            }
            b
        } else {
            // every bucket's stats from one call, not one per bucket; those
            // it leaves out are scanned without, and record why
            let all = engine.admin.all_buckets().await?;
            if args.checks.find_orphans {
                all.require_stats()?;
            }
            all.unstatted.iter().for_each(|b| crate::admin::AllBuckets::warn_unstatted(b));
            let names;
            (names, stats) = all.by_name();
            names
        };
        tracing::info!("scanning {} bucket(s)", buckets.len());
        // they check the Swift segments they hold themselves; every unit's
        // report goes to these files, so a segment several follow is reported once
        let named: Option<HashSet<String>> = (!engine.opts.every_bucket).then(|| buckets.iter().cloned().collect());
        if let Some(named) = &named {
            engine.segments.lists_too(named.iter().cloned());
        }
        engine.segments.report_once();
        // orphan detection: bucket scans file their references in local partitions
        let started = scan::now();
        let detection = if args.checks.find_orphans {
            // the pools the scan stats in ( --pool's, or the zone's ): an object elsewhere is no orphan it can tell
            let pools = engine.store.data_pools();
            if pools.is_empty() {
                anyhow::bail!("finding orphans needs the data pools the scan stats in, and there are none");
            }
            let counts = engine.store.pool_objects().await?;
            let objects: u64 = pools.iter().map(|p| counts.get(&store::parse_pool(p).0).copied().unwrap_or(0)).sum();
            let partitions = args.sizing.orphan_partitions.unwrap_or_else(|| detect::partitions_for(objects)).max(1);
            let dir = work_dir(&args.work_dir.clone().unwrap_or_else(std::env::temp_dir), started)?;
            let shuffle: Arc<dyn shuffle::Shuffle> = Arc::new(shuffle::LocalShuffle::new(dir.clone())?);
            tracing::info!("finding orphans among {objects} objects in {pools:?}, in {partitions} partitions under {}", dir.display());
            Some((pools, counts, partitions, shuffle, dir))
        } else {
            None
        };
        // its work directory goes when the scan does, however it ends
        let made = detection.as_ref().map(|d| d.4.clone());
        let _work = made.clone().map(RemoveOnDrop);
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
        // the first signal keeps what the running buckets find, as a client does
        let mut stop = stop_on_signal(made, out.paths.clone());
        let scope = scope_of(&engine.opts);
        // a unit per bucket, or per index shard of a big one
        let native = engine.opts.listing == scan::Listing::Native;
        let queue: Vec<(String, Option<BucketStats>, Option<u32>)> = buckets
            .into_iter()
            .flat_map(|b| {
                let st = stats.remove(&b);
                let shards = match (&st, native) {
                    (Some(st), true) => native::shard_units(st, args.sizing.shard_units_above),
                    _ => vec![None],
                };
                shards.into_iter().map(move |shard| (b.clone(), st.clone(), shard))
            })
            .collect();
        // resume: skip what an earlier scan finished cleanly, recently enough
        let queue = match (&state, args.maxage) {
            (Some(state), Some(maxage)) => {
                let now = scan::now();
                let (queue, skipped): (Vec<_>, Vec<_>) = queue.into_iter().partition(|(b, st, shard)| {
                    let latest = state.latest.get(&(b.clone(), *shard));
                    !recently_finished(latest, st.as_ref().map(|s| s.num_shards), &scope, named.as_ref(), now, maxage)
                });
                // the files start empty: what the skipped units found, their records carry
                out.start()?;
                for (b, _, shard) in &skipped {
                    let r = &state.latest[&(b.clone(), *shard)];
                    out.carry(r)?;
                    (resumed_findings, resumed_gaps) = (resumed_findings + r.found.len(), resumed_gaps + r.gaps);
                }
                out.findings.flush()?;
                out.missing.flush()?;
                resumed = skipped.len();
                if resumed > 0 {
                    tracing::warn!("skipping {resumed} bucket unit(s) scanned within {maxage} s; {} to scan", queue.len());
                }
                queue
            }
            _ => {
                out.start()?;
                queue
            }
        };
        coverage.units = queue.len();
        let mut queue = queue.into_iter();
        // each running unit's count of RADOS objects checked, for the status
        let mut running: BTreeMap<String, Arc<AtomicU64>> = BTreeMap::new();
        let (mut done, mut checked) = (0usize, 0u64);
        let period = std::time::Duration::from_secs(30);
        let mut status = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        status.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            while !*stop.borrow() && tasks.len() < args.parallel.max(1) {
                let Some((b, st, shard)) = queue.next() else { break };
                let label = shard.map_or_else(|| b.clone(), |s| format!("{b}#{s}"));
                let progress = Arc::new(AtomicU64::new(0));
                running.insert(label.clone(), progress.clone());
                let shards = st.as_ref().map(|s| s.num_shards);
                let engine = engine.clone();
                tasks.spawn(async move {
                    let r = engine.scan_bucket_with(&b, st, progress, shard).await;
                    ((b, shard, shards, label), r)
                });
            }
            let joined = tokio::select! {
                j = tasks.join_next() => j,
                _ = status.tick() => {
                    for line in status_lines(&running, done, coverage.units, checked) {
                        tracing::info!("{line}");
                    }
                    continue;
                }
            };
            let Some(joined) = joined else { break };
            let ((name, shard, shards, bucket), report) = joined?;
            running.remove(&bucket);
            done += 1;
            let mut report = match report {
                Ok(r) => r,
                Err(e) => {
                    if detection.is_some() {
                        anyhow::bail!("{bucket}: {e:#}; without its references, orphans cannot be told");
                    }
                    tracing::error!("{bucket}: {e:#}");
                    coverage.failed += 1;
                    continue;
                }
            };
            if let (Some(r), Some((_, _, _, shuffle, _))) = (report.references.take(), &detection) {
                r.flush(shuffle.as_ref(), 0, "local").await?;
            }
            for e in &report.errors {
                tracing::error!("{bucket}: {e}");
            }
            if !report.errors.is_empty() {
                coverage.errored += 1;
            }
            for f in &report.findings {
                out.finding(f)?;
            }
            for line in &report.missing {
                writeln!(out.missing, "{line}")?;
            }
            // what is done survives a second signal
            out.findings.flush()?;
            out.missing.flush()?;
            if let Some(state) = state.as_mut() {
                // what its bucket's units relied on: shards are not told apart, which can only rescan more
                let depends = engine.segments.depends(&name);
                state.record(&UnitRecord {
                    bucket: name,
                    shard,
                    shards,
                    finished: scan::now(),
                    rados_objects: report.rados_objects,
                    gaps: report.gaps,
                    findings: report.findings.len(),
                    errors: report.errors.len(),
                    scope: scope.clone(),
                    found: report.findings.clone(),
                    missing: report.missing.clone(),
                    segments_left_to: depends.left_to,
                    segments_followed: depends.followed,
                })?;
            }
            out.gaps += report.gaps;
            checked += report.rados_objects;
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
        let unscanned = queue.count();
        if unscanned > 0 {
            coverage.interrupted = Some(format!("{unscanned} bucket unit(s) were not scanned"));
        }
        unresolved = unresolved_refs(unscanned, resumed, !refs.is_empty());
        if let Some(not) = unresolved {
            if unscanned > 0 {
                coverage.interrupted = coverage.interrupted.map(|i| format!("{i}; {not}"));
            }
        } else {
            for f in refs.resolve(&engine.ctx) {
                out.finding(&f)?;
            }
        }
        if let Some((pools, counts, partitions, shuffle, _)) = detection {
            // orphans need every bucket's references, and no signal
            let found = if *stop.borrow() {
                None
            } else {
                tokio::select! {
                    r = find_orphans(&engine, &pools, &counts, partitions, args.sizing.orphan_slices, shuffle, started, args.parallel) => Some(r?),
                    _ = stop.wait_for(|s| *s) => None,
                }
            };
            match found {
                Some((findings, tally)) => {
                    for f in &findings {
                        out.finding(f)?;
                    }
                    for (k, v) in tally.skipped {
                        *out.tally.skipped.entry(k).or_default() += v;
                    }
                }
                None => {
                    let not = "no orphans were looked for";
                    coverage.interrupted = Some(coverage.interrupted.map_or_else(|| not.to_string(), |i| format!("{i}; {not}")));
                }
            }
        }
    }

    out.findings.flush()?;
    out.missing.flush()?;
    summarize(&out.tally, &args.findings, coverage.complete());
    if resumed > 0 {
        let refs = unresolved.filter(|_| coverage.interrupted.is_none()).map(|n| format!("; {n}, as the skipped units' heads may hold them")).unwrap_or_default();
        eprintln!(
            "Resumed: {resumed} bucket unit(s) finished within --maxage were skipped; their {resumed_findings} finding(s) and {resumed_gaps} missing RADOS object(s), as --state recorded them, are in the files and counted above{refs}"
        );
    }
    // Output's drop removes a file that holds nothing
    if out.gaps > 0 {
        eprintln!("{} missing RADOS objects are in {}", out.gaps, args.missing.display());
    }
    if let Some((message, code)) = coverage.outcome() {
        return Err(Exit { code, message }.into());
    }
    Ok(())
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if r == 0 { String::from_utf8_lossy(&buf[..end]).into_owned() } else { "unknown".into() }
}

/// The work pool's spec: --work-pool's, or that of a ceph: database's pool,
/// which libcephsqlite names as it is, so escaped here ( see pool_spec() ).
fn work_pool(given: Option<String>, db: &str) -> Option<String> {
    given.or_else(|| {
        let (pool, _) = db.strip_prefix("ceph:")?.split_once('/')?;
        Some(store::pool_spec(pool.split(':').next().unwrap_or(pool), ""))
    })
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
    let work_pool = work_pool(args.work_pool.clone(), &args.db);
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
        shard_units_above: args.sizing.shard_units_above,
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

async fn verify(args: VerifyArgs) -> Result<()> {
    let mut gaps = Vec::new();
    for path in &args.files {
        let body = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let read = gaplist::read(&body).with_context(|| format!("reading {}", path.display()))?;
        if !read.findings.is_empty() {
            anyhow::bail!("{} holds {} findings; verify reads gap lists, as scan's -o file", path.display(), read.findings.len());
        }
        gaps.extend(read.gaps);
    }
    if gaps.is_empty() {
        anyhow::bail!("no MISSING lines in {}", args.files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>().join(", "));
    }
    // a line of one list can settle another's split, and the bucket names what is left
    gaplist::resolve(&mut gaps);
    tracing::info!("verifying {} lines", gaps.len());
    let (store, admin) = connect(&args.ceph).await?;
    gaplist::settle_tenants(&admin, &mut gaps).await;
    let stat = |oid: String| {
        let store = store.clone();
        async move { store.stat(&oid).await }
    };
    let lookup = |bucket: String, name: String| {
        let admin = admin.clone();
        async move { verify::index_entries(&admin, &bucket, &name).await }
    };
    let v = verify::verify(gaps, stat, (!args.keep_delete_markers).then_some(lookup), args.inflight).await;
    let written = verify::write_lines(&args.output, &v.lines, &args.files)?;
    if v.summary.failed() {
        anyhow::bail!("{}; the lines are in {}", v.summary, args.output.display());
    }
    eprintln!("{}", v.summary);
    if written {
        eprintln!("the lines are in {}", args.output.display());
    }
    Ok(())
}

async fn list(args: ListArgs) -> Result<()> {
    let engine = engine(&args.ceph, Options::default(), args.inflight, false).await?;
    let mut rx = if args.radoslist {
        native::radoslist_seeds(engine.admin.radoslist(&args.bucket))
    } else {
        let stats = engine.admin.bucket_stats(&args.bucket).await?;
        if let Some(s) = args.shard.filter(|s| u64::from(*s) >= stats.num_shards.max(1)) {
            anyhow::bail!("{} has {} shard(s); there is no shard {s}", args.bucket, stats.num_shards.max(1));
        }
        engine.native_seeds(stats, args.shard)
    };
    let sep = args.separator.replace("\\t", "\t");
    let mut out = BufWriter::new(std::io::stdout());
    let mut errors = 0;
    while let Some(seed) = rx.recv().await {
        let seed = seed?;
        if let Some(e) = &seed.error {
            tracing::error!("{e}");
            errors += 1;
        }
        for oid in &seed.oids {
            if seed.parts {
                writeln!(out, "{oid}")?;
            } else {
                writeln!(out, "{oid}{sep}{}{sep}{}", seed.bucket, seed.key)?;
            }
        }
    }
    out.flush()?;
    if errors > 0 {
        anyhow::bail!("{errors} object(s) could not be listed in full");
    }
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
    let result = rt.block_on(async move {
        match cli.command {
            Cmd::Scan(args) => scan(args).await,
            Cmd::Server(args) => server(args).await,
            Cmd::Client(args) => client(args).await,
            Cmd::Import(args) => import(args).await,
            Cmd::List(args) => list(args).await,
            Cmd::Verify(args) => verify(args).await,
        }
    });
    // a scan that did not cover everything says what, and exits with its own status
    if let Some(exit) = result.as_ref().err().and_then(|e| e.downcast_ref::<Exit>()) {
        eprintln!("{exit}");
        std::process::exit(exit.code.into());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Named buckets are split into shard units as every bucket's are: their
    /// stats are read first, and one whose stats fail is scanned whole.
    #[tokio::test]
    async fn named_buckets_get_shard_units() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-named-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("radosgw-admin");
        let big = r#"{"bucket":"big","id":"ID","marker":"M","num_shards":4,"usage":{"rgw.main":{"num_objects":500000}}}"#;
        std::fs::write(&program, format!("#!/bin/sh\n[ \"$3\" = \"--bucket=big\" ] && echo '{big}' && exit 0\nexit 2\n")).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, admin::DEFAULT_CONCURRENCY);
        let stats = named_stats(&admin, &["big".to_string(), "gone".to_string()], 4).await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(stats.keys().collect::<Vec<_>>(), ["big"]);
        assert_eq!(native::shard_units(&stats["big"], 100_000), [Some(0), Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn empty_bucket_names_are_refused() {
        // radosgw-admin takes --bucket= for every bucket: B=; scan -b "$B" must not scan the cluster as one
        assert!(Cli::try_parse_from(["rgw-integrity", "scan", "-b", ""]).is_err());
        assert!(Cli::try_parse_from(["rgw-integrity", "scan", "-b", "a", "--bucket="]).is_err());
        assert!(Cli::try_parse_from(["rgw-integrity", "list", "-b", ""]).is_err());
        assert!(Cli::try_parse_from(["rgw-integrity", "scan", "-b", "a"]).is_ok());
        assert!(named_buckets(&["".into()], None).is_err());

        let path = std::env::temp_dir().join(format!("rgwi-buckets-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::write(&path, "\n  \n").unwrap();
        assert!(named_buckets(&[], Some(&path)).is_err(), "a file of blank lines names no bucket");
        assert_eq!(named_buckets(&["a".into()], None).unwrap(), Some(vec!["a".to_string()]));
        std::fs::write(&path, " b \n\nc\n").unwrap();
        assert_eq!(named_buckets(&["a".into()], Some(&path)).unwrap(), Some(vec!["a".into(), "b".into(), "c".into()]));
        assert_eq!(named_buckets(&[], None).unwrap(), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn pools_are_split_as_rgw_gap_list_splits_them() {
        // rgw-gap-list.py -p 'data non-ec', with an escaped space and a doubled one
        let cli = Cli::try_parse_from(["rgw-integrity", "scan", "-p", "a  b ", "-p", "c:ns", "--pool", r"d\ e f\\ g"]).unwrap();
        let Cmd::Scan(args) = cli.command else { panic!("not a scan") };
        let pools = args.ceph.pools();
        assert_eq!(pools, ["a", "b", "c:ns", r"d\ e", r"f\\", "g"]);
        assert_eq!(store::parse_pool(&pools[3]), ("d e".to_string(), String::new()));
        let cli = Cli::try_parse_from(["rgw-integrity", "scan", "-p", " "]).unwrap();
        let Cmd::Scan(args) = cli.command else { panic!("not a scan") };
        assert!(args.ceph.pools().is_empty());
    }

    #[test]
    fn stat_pools_never_guess() {
        let zone = || admin::ZonePools {
            data: vec!["z.data".into(), "z.cold".into()],
            extra: vec!["z.non-ec".into(), "z.cold".into()],
            index: [("default-placement".to_string(), "z.index".to_string())].into(),
        };
        let pool = ["p".to_string()];
        let (data, z) = stat_pools(Ok(zone()), &[]).unwrap();
        assert_eq!(data, ["z.data", "z.cold", "z.non-ec"]);
        assert_eq!(z.index["default-placement"], "z.index");
        let (data, z) = stat_pools(Ok(zone()), &pool).unwrap();
        assert_eq!((data, z.extra), (vec!["p".to_string()], zone().extra));

        // an unreadable zone, or one with no data pools, is an error without --pool
        let err = stat_pools(Err(anyhow::anyhow!("EACCES")), &[]).unwrap_err().to_string();
        assert!(err.contains("EACCES") && err.contains("--pool"), "{err}");
        let (data, z) = stat_pools(Err(anyhow::anyhow!("EACCES")), &pool).unwrap();
        assert_eq!(data, pool);
        assert_eq!(z.index["default-placement"], "default.rgw.buckets.index");
        let extra_only = admin::ZonePools { data: Vec::new(), ..zone() };
        assert!(stat_pools(Ok(extra_only.clone()), &[]).is_err(), "an extra pool is not a head pool");
        assert_eq!(stat_pools(Ok(extra_only), &pool).unwrap().0, pool);
    }

    #[test]
    fn work_pools_are_specs() {
        assert_eq!(work_pool(Some(r"w\:x".into()), "ceph:db/state").as_deref(), Some(r"w\:x"), "given as a spec");
        assert_eq!(work_pool(None, "ceph:db:ns/state").as_deref(), Some("db"));
        // libcephsqlite's pool is a name, not a spec
        let spec = work_pool(None, r"ceph:a\b/state").unwrap();
        assert_eq!(store::parse_pool(&spec), (r"a\b".to_string(), String::new()));
        assert_eq!(work_pool(None, "file:/tmp/state.db"), None);
    }

    fn scan_args(args: &[&str]) -> ScanArgs {
        match Cli::try_parse_from(["rgw-integrity", "scan"].iter().chain(args)).unwrap().command {
            Cmd::Scan(a) => a,
            _ => unreachable!(),
        }
    }

    #[test]
    fn bucket_lists_split_as_rgw_gap_list() {
        let names = |v: &[&str]| named_buckets(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), None).unwrap().unwrap();
        assert_eq!(names(&["b1  b2", "b3"]), ["b1", "b2", "b3"], "no empty name between two spaces");
        assert_eq!(names(&[" b1\tb2 "]), ["b1", "b2"]);
        let a = scan_args(&["-b", "b1 b2"]);
        assert_eq!(named_buckets(&a.bucket, None).unwrap().unwrap(), ["b1", "b2"]);
        // clap takes -b " " as not empty; split, it names no bucket, and must not become every bucket
        assert!(named_buckets(&scan_args(&["-b", " "]).bucket, None).is_err());
        assert!(named_buckets(&["a".into(), " ".into()], None).is_err());

        // a Swift container may have a space in its name: -l lines are not split
        let path = std::env::temp_dir().join(format!("rgwi-buckets-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::write(&path, " my container \nc\n").unwrap();
        assert_eq!(named_buckets(&["a b".into()], Some(&path)).unwrap().unwrap(), ["a", "b", "my container", "c"]);
        // a bucket named twice, in -b or in -b and -l, is one unit, where it was first named
        assert_eq!(names(&["a a", "b", "a"]), ["a", "b"]);
        assert_eq!(named_buckets(&["c b".into()], Some(&path)).unwrap().unwrap(), ["c", "b", "my container"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn match_prefixes_are_normalised() {
        assert_eq!(scan_args(&["-m", " logs/ "]).checks.options().match_prefix.as_deref(), Some("logs/"));
        assert_eq!(scan_args(&["-m", " "]).checks.options().match_prefix, None);
        assert_eq!(scan_args(&["-m", ""]).checks.options().match_prefix, None);
        assert_eq!(scan_args(&[]).checks.options().match_prefix, None);
        assert_eq!(scan_args(&["--prefix", "logs/"]).checks.options().match_prefix.as_deref(), Some("logs/"));

        // M=; scan --find-orphans -m "$M" is every key, as rgw-gap-list takes a blank -m
        for m in ["", "  "] {
            let a = scan_args(&["--find-orphans", "-m", m]);
            assert!(a.orphans_scope(&a.checks.options()).is_ok(), "-m {m:?}");
        }
        let a = scan_args(&["--find-orphans", "-m", "logs/"]);
        assert!(a.orphans_scope(&a.checks.options()).is_err());
        let a = scan_args(&["--find-orphans", "-b", "b1"]);
        assert!(a.orphans_scope(&a.checks.options()).is_err());
    }

    /// A scope orphans cannot be told in is refused before the scan opens
    /// its files, connects or says what it lists.
    #[tokio::test]
    async fn orphan_scopes_are_refused_first() {
        let (a, b) = (temp("findings"), temp("missing"));
        let (j, o) = (a.display().to_string(), b.display().to_string());
        let args = scan_args(&["--find-orphans", "-m", "logs/", "--radosgw-admin", "false", "-J", &j, "-o", &o]);
        let e = format!("{:#}", scan(args).await.unwrap_err());
        assert!(e.contains("--find-orphans needs every bucket's references"), "{e}");
        assert!(!a.exists() && !b.exists());
    }

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rgwi-{name}-{}-{}", std::process::id(), rand::random::<u32>()))
    }

    #[test]
    fn outcome() {
        let c = |failed, errored, interrupted: Option<&str>| {
            Coverage { units: 10, failed, errored, interrupted: interrupted.map(str::to_string) }
        };
        assert!(c(0, 0, None).complete());
        assert_eq!(c(0, 0, None).outcome(), None);
        // a scan whose units failed or had errors is no clean result
        let (m, code) = c(2, 0, None).outcome().unwrap();
        assert_eq!((m.as_str(), code), ("Incomplete: 2 of 10 bucket unit(s) failed, so they are not fully checked; see the log", EXIT_INCOMPLETE));
        let (m, code) = c(0, 3, None).outcome().unwrap();
        assert!(m.starts_with("Incomplete: 3 of 10 bucket unit(s) had errors"), "{m}");
        assert_eq!(code, EXIT_INCOMPLETE);
        assert!(!c(0, 3, None).complete());
        let (m, _) = c(2, 3, None).outcome().unwrap();
        assert!(m.starts_with("Incomplete: 2 of 10 bucket unit(s) failed and 3 had errors"), "{m}");
        // an interrupt is told apart, and still says what failed
        let (m, code) = c(0, 0, Some("4 bucket unit(s) were not scanned")).outcome().unwrap();
        assert_eq!((m.as_str(), code), ("Interrupted: 4 bucket unit(s) were not scanned", EXIT_INTERRUPTED));
        let (m, code) = c(1, 0, Some("4 bucket unit(s) were not scanned")).outcome().unwrap();
        assert!(m.starts_with("Interrupted: 4 bucket unit(s) were not scanned; 1 of 10 bucket unit(s) failed"), "{m}");
        assert_eq!(code, EXIT_INTERRUPTED);
    }

    /// A refused command line exits with clap's status: not one a scan
    /// that ran exits with, which says its files hold what it found.
    #[test]
    fn exit_statuses_are_not_clap_s() {
        for args in [&["-a", "3600"][..], &["-b", ""], &["--state", "s", "-a", "1", "--find-orphans"], &["--no-such-flag"]] {
            let e = Cli::try_parse_from(["rgw-integrity", "scan"].iter().chain(args)).err().expect("refused");
            assert!(![EXIT_INCOMPLETE, EXIT_INTERRUPTED].map(i32::from).contains(&e.exit_code()), "{args:?}: {}", e.exit_code());
        }
        assert_eq!(Cli::try_parse_from(["rgw-integrity", "scan", "--help"]).err().unwrap().exit_code(), 0);
        for (code, what) in [(EXIT_INCOMPLETE, "when some units failed"), (EXIT_INTERRUPTED, "when a signal stopped it")] {
            assert!(SCAN_EXIT_STATUS.contains(&format!("{code} {what}")), "{code} {what}");
        }
    }

    #[test]
    fn outputs_are_locked() {
        let (a, b, other) = (temp("findings"), temp("missing"), temp("other"));
        std::fs::write(&a, "earlier\n").unwrap();
        let mut first = Output::open(&a, &b).unwrap();
        // a second scan in the same directory neither truncates nor unlinks the first's files
        let e = format!("{:#}", Output::open(&a, &other).err().expect("-J is locked"));
        assert!(e.contains("in use by another rgw-integrity scan; give this one another -J"), "{e}");
        let e = format!("{:#}", Output::open(&other, &b).err().expect("-o is locked"));
        assert!(e.contains("another -o"), "{e}");
        assert!(!other.exists(), "the refused scan leaves no file of its own");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "earlier\n", "opening truncates nothing");
        first.start().unwrap();
        writeln!(first.findings, "mine").unwrap();
        drop(first);
        // dropped, it flushes, keeps what holds lines and removes what holds none
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "mine\n");
        assert!(!b.exists());

        // let go, the files are another scan's
        let second = Output::open(&a, &b).unwrap();
        assert!(!is_empty(&second.findings) && is_empty(&second.missing));
        drop(second);
        assert!(a.exists(), "a scan that fails before start() keeps an earlier scan's lines");
        let e = format!("{:#}", Output::open(&a, &a).err().expect("one file for both"));
        assert!(e.contains("-J and -o name the same file"), "{e}");
        for p in [a, b, other] {
            std::fs::remove_file(p).ok();
        }
    }

    /// A -O scan that cannot read its orphans file, or every bucket's
    /// markers, keeps an earlier scan's -J and -o.
    #[tokio::test]
    async fn listed_orphans_read_before_start() {
        let (a, b, listed) = (temp("findings"), temp("missing"), temp("orphans"));
        let engine = Engine {
            store: Arc::new(store::MockStore::new(1, 0)),
            // no radosgw-admin: bucket stats cannot be read
            admin: Arc::new(Admin::new("/nonexistent/radosgw-admin".into(), None, None, admin::DEFAULT_CONCURRENCY)),
            ctx: Arc::new(Context::default()),
            gc: RwLock::default(),
            gc_min_wait: 7200,
            limiter: limiter::Limiter::new(8),
            opts: Options::default(),
            partitions: None,
            segments: Default::default(),
        };
        std::fs::write(&listed, "M__shadow_.x_1\n").unwrap();
        for path in [temp("typo"), listed.clone()] {
            std::fs::write(&a, "earlier\n").unwrap();
            std::fs::write(&b, "s3://b/k MISSING M_k\n").unwrap();
            let mut out = Output::open(&a, &b).unwrap();
            assert!(classify_listed(&engine, &path, &mut out).await.is_err());
            drop(out);
            assert_eq!(std::fs::read_to_string(&a).unwrap(), "earlier\n", "{}", path.display());
            assert_eq!(std::fs::read_to_string(&b).unwrap(), "s3://b/k MISSING M_k\n");
        }
        for p in [a, b, listed] {
            std::fs::remove_file(p).ok();
        }
    }

    /// Partitions an interrupted scan left under --work-dir are not the next
    /// one's: a reference of the first hides no orphan the second lists.
    #[tokio::test]
    async fn work_dirs_are_each_scan_s() {
        let parent = temp("work-dir");
        let tail = "M__shadow_.tail_1".to_string();
        let first = work_dir(&parent, 100).unwrap();
        let mut refs = detect::Refs::new(4);
        refs.add(&tail);
        refs.flush(&shuffle::LocalShuffle::new(first.clone()).unwrap(), 0, "local").await.unwrap();
        assert!(work_dir(&parent, 100).is_err(), "never one that is there");
        let second = work_dir(&parent, 200).unwrap();
        assert!(second.starts_with(&parent) && second != first);
        let shuffle = shuffle::LocalShuffle::new(second).unwrap();
        let mut listing = detect::Listing::new(4);
        listing.add(vec![tail.clone()], &shuffle, 0, "local").await.unwrap();
        listing.finish(&shuffle, 0, "local").await.unwrap();
        let mut orphans = Vec::new();
        for p in 0..4 {
            orphans.extend(detect::join(&shuffle, 0, p, &["local".to_string()]).await.unwrap().0);
        }
        assert_eq!(orphans, [tail]);
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn empty_outputs_go() {
        let (a, b, c) = (temp("findings"), temp("missing"), temp("absent"));
        std::fs::write(&a, "").unwrap();
        std::fs::write(&b, "kept\n").unwrap();
        remove_empty(&[a.clone(), b.clone(), c]);
        assert!(!a.exists() && b.exists());
        std::fs::remove_file(b).ok();
    }

    fn record(bucket: &str, shard: Option<u32>, shards: Option<u64>, finished: i64, errors: usize) -> UnitRecord {
        UnitRecord {
            bucket: bucket.into(),
            shard,
            shards,
            finished,
            rados_objects: 5,
            gaps: 1,
            findings: 1,
            errors,
            scope: "s".into(),
            found: vec![finding::Finding::new(finding::Class::DataLoss, "missing", bucket)],
            missing: vec![format!("s3://{bucket}/k MISSING oid")],
            segments_left_to: BTreeSet::new(),
            segments_followed: false,
        }
    }

    #[test]
    fn maxage_skips() {
        let (now, maxage) = (10_000, 3600);
        let skip = |r: &UnitRecord, shards| recently_finished(Some(r), shards, "s", None, now, maxage);
        assert!(skip(&record("b", None, None, now - 60, 0), None), "finished cleanly, recently");
        assert!(skip(&record("b", None, Some(3), now - 3600, 0), Some(5)), "a whole bucket, however sharded");
        assert!(!skip(&record("b", None, None, now - 60, 1), None), "finished with errors");
        assert!(!skip(&record("b", None, None, now - 3601, 0), None), "too long ago");
        assert!(skip(&record("b", Some(2), Some(11), now - 60, 0), Some(11)));
        assert!(!skip(&record("b", Some(2), Some(11), now - 60, 0), Some(13)), "resharded since");
        assert!(!skip(&record("b", Some(2), Some(11), now - 60, 0), None));
        assert!(!recently_finished(Some(&record("b", None, None, now - 60, 0)), None, "other checks", None, now, maxage));
        assert!(!recently_finished(None, None, "s", None, now, maxage), "never finished");
        assert!(recently_finished(Some(&record("b", None, None, 0, 0)), None, "s", None, now, u64::MAX));

        // the latest record of each unit counts: a rescan with errors undoes a clean one
        let lines: Vec<String> = [record("b", None, None, 100, 0), record("b", None, None, 200, 3), record("b", Some(1), Some(2), 150, 0)]
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        let text = format!("{}\n{}\n{{\"bucket\":\"trunc\n{}\n", lines[1], lines[0], lines[2]);
        let (latest, more) = latest_records(&text);
        assert_eq!(latest.len(), 2, "the line cut short is passed over");
        assert!(more);
        assert_eq!(latest[&("b".to_string(), None)], record("b", None, None, 200, 3));
        assert_eq!(latest[&("b".to_string(), Some(1))], record("b", Some(1), Some(2), 150, 0));
        assert!(!latest_records(&format!("{}\n{}\n", lines[1], lines[2])).1, "nothing to cut");
        // a record that does not carry its unit's lines cannot be written again: its unit is rescanned
        let bare = r#"{"bucket":"b","shard":null,"shards":null,"finished":100,"rados_objects":1,"gaps":0,"findings":0,"errors":0,"scope":"s"}"#;
        assert!(latest_records(bare).0.is_empty());

        // a record made before the buckets relied on for Swift segments were recorded: rescanned
        let mut old: serde_json::Value = serde_json::to_value(record("b", None, None, 100, 0)).unwrap();
        old.as_object_mut().unwrap().retain(|k, _| !k.starts_with("segments_"));
        assert!(latest_records(&old.to_string()).0.is_empty());

        // segments left to a bucket the scan lists are checked there, if it still does
        let names = |n: &[&str]| n.iter().map(|b| b.to_string()).collect::<HashSet<String>>();
        let left = UnitRecord { segments_left_to: ["S".to_string()].into(), ..record("A", None, None, now - 60, 0) };
        let skip = |r: &UnitRecord, named: Option<&HashSet<String>>| recently_finished(Some(r), None, "s", named, now, maxage);
        assert!(skip(&left, Some(&names(&["A", "S"]))));
        assert!(!skip(&left, Some(&names(&["A"]))), "S is neither scanned nor followed");
        assert!(skip(&left, None), "every bucket");
        assert!(skip(&record("A", None, None, now - 60, 0), Some(&names(&["A"]))));
        // followed ones' lines may be another unit's, reported once, or this scan's again
        let followed = UnitRecord { segments_followed: true, ..record("A", None, None, now - 60, 0) };
        assert!(!skip(&followed, Some(&names(&["A"]))));
        assert!(!skip(&followed, Some(&names(&["A", "S"]))));

        // a prefix is part of the checks
        let o = Options::default();
        assert_eq!(scope_of(&o), scope_of(&Options { threads: 7, ..o.clone() }));
        assert_ne!(scope_of(&o), scope_of(&Options { match_prefix: Some("logs/".into()), ..o.clone() }));
    }

    #[test]
    fn resumed_files_hold_no_stale_lines() {
        // an earlier scan found A and B missing an object; A was repaired, and is rescanned clean, while B is skipped
        let (a, b) = (temp("findings"), temp("missing"));
        let earlier = [record("A", None, None, 100, 0), record("B", None, None, 100, 0)];
        std::fs::write(&a, earlier.iter().map(|r| serde_json::to_string(&r.found[0]).unwrap() + "\n").collect::<String>()).unwrap();
        std::fs::write(&b, "s3://A/k MISSING oid\ns3://B/k MISSING oid\n").unwrap();
        let mut out = Output::open(&a, &b).unwrap();
        out.start().unwrap();
        out.carry(&earlier[1]).unwrap();
        assert_eq!((out.gaps, out.tally.classes.values().sum::<u64>()), (1, 1), "the skipped unit's lines are counted");
        drop(out);
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "s3://B/k MISSING oid\n");
        let found = std::fs::read_to_string(&a).unwrap();
        assert_eq!(found.lines().map(|l| serde_json::from_str::<finding::Finding>(l).unwrap().bucket).collect::<Vec<_>>(), ["B"]);
        for p in [a, b] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn state_file() {
        let path = temp("state");
        let line = |r: &UnitRecord| serde_json::to_string(r).unwrap();
        std::fs::write(&path, format!("{}\n{}\n{{\"bucket\":", line(&record("a", None, None, 4, 0)), line(&record("a", None, None, 5, 0)))).unwrap();
        let mut state = State::open(&path).unwrap();
        assert_eq!(state.latest.len(), 1);
        // cut to the latest record of each unit, so the lines records carry do not pile up
        assert_eq!(std::fs::read_to_string(&path).unwrap(), line(&record("a", None, None, 5, 0)) + "\n");
        assert!(State::open(&path).is_err(), "one scan at a time records in it");
        state.record(&record("b", Some(0), Some(2), 6, 0)).unwrap();
        drop(state);
        let state = State::open(&path).unwrap();
        assert_eq!(state.latest.len(), 2, "the next record starts a line of its own");
        assert_eq!(state.latest[&("b".to_string(), Some(0))], record("b", Some(0), Some(2), 6, 0));
        drop(state);
        // a record whose newline a kill lost still ends its line
        std::fs::write(&path, line(&record("a", None, None, 5, 0))).unwrap();
        let mut state = State::open(&path).unwrap();
        state.record(&record("b", None, None, 6, 0)).unwrap();
        assert_eq!(latest_records(&std::fs::read_to_string(&path).unwrap()).0.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unresolved_ledger() {
        assert_eq!(unresolved_refs(0, 0, true), None, "every unit scanned");
        assert!(unresolved_refs(3, 0, true).is_some(), "a signal left units");
        assert!(unresolved_refs(0, 2, true).is_some(), "--maxage skipped units");
        assert_eq!(unresolved_refs(3, 2, false), None, "no references to resolve");
    }

    #[test]
    fn work_dir_goes() {
        let dir = temp("work");
        std::fs::create_dir_all(dir.join("p0")).unwrap();
        std::fs::write(dir.join("p0/x"), "x").unwrap();
        drop(RemoveOnDrop(dir.clone()));
        assert!(!dir.exists());
    }

    #[test]
    fn state_flags() {
        let parse = |a: &[&str]| Cli::try_parse_from(["rgw-integrity", "scan"].iter().chain(a));
        assert!(parse(&["--state", "s.jsonl"]).is_ok());
        assert!(parse(&["--state", "s.jsonl", "-a", "3600"]).is_ok());
        assert!(parse(&["-a", "3600"]).is_err(), "--maxage needs --state");
        assert!(parse(&["--state", "s", "-a", "3600", "--find-orphans"]).is_err(), "orphans need every bucket");
        assert!(parse(&["--state", "s", "-O", "orphans.txt"]).is_err());
    }

    #[test]
    fn status() {
        let running: BTreeMap<String, Arc<AtomicU64>> =
            [("a".to_string(), Arc::new(AtomicU64::new(7))), ("b#3".to_string(), Arc::new(AtomicU64::new(5)))].into();
        running["a"].fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            status_lines(&running, 4, 10, 100),
            [
                "[status] a: 8 RADOS objects checked so far",
                "[status] b#3: 5 RADOS objects checked so far",
                "[status] 4 of 10 bucket unit(s) done, 2 running; 113 RADOS objects checked",
            ]
        );
    }

}
