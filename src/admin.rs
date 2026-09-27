//! The radosgw-admin commands the checks run: listings that need RGW's own
//! decoding of manifests and index entries.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{Semaphore, mpsc};

use crate::json_stream;
use crate::oid::parse_time;

/// Separates radoslist's fields: a byte no UTF-8 text holds, so no key
/// ( RGW takes only UTF-8 names ) and no bucket name can.  A RADOS object's
/// name holds its key, so a separator a key could hold would split it.
const FS: u8 = 0xff;

/// The user radoslist runs as in a tenant: radosgw-admin takes --tenant only
/// with a --uid ( "--tenant is set, but there's no user ID" ), and bucket
/// radoslist reads no more of the user than whether it exists.
const TENANT_UID: &str = "rgw-integrity";

/// How many radosgw-admin commands run() runs at once, by default.
pub const DEFAULT_CONCURRENCY: usize = 16;

/// The bytes of a streamed command's stderr kept for its error: the reason
/// radosgw-admin gives comes last.
const STDERR_TAIL: usize = 2048;

/// Read a child's stderr on a thread, so a chatty child cannot block on a
/// full pipe, keeping only its last `limit` bytes.
fn stderr_tail(child: &mut Child, limit: usize) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    let mut err = child.stderr.take()?;
    Some(std::thread::spawn(move || {
        let (mut tail, mut buf) = (Vec::new(), [0u8; 8192]);
        while let Ok(n @ 1..) = err.read(&mut buf) {
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > 2 * limit {
                tail.drain(..tail.len() - limit);
            }
        }
        tail.drain(..tail.len().saturating_sub(limit));
        tail
    }))
}

/// What a failed command said on stderr, on one line, without the warning
/// every radosgw-admin run with the experimental features prints.
fn stderr_reason(tail: Option<std::thread::JoinHandle<Vec<u8>>>) -> String {
    let tail = tail.and_then(|t| t.join().ok()).unwrap_or_default();
    let text = String::from_utf8_lossy(&tail);
    let reason = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.contains("dangerous and experimental")).collect::<Vec<_>>().join(" ");
    if reason.is_empty() { String::new() } else { format!(": {reason}") }
}

/// A streamed command's child, killed and reaped if it is dropped before
/// it is waited for: when its reader goes away or its output cannot be
/// read.  std's Child is neither, and radosgw-admin ( SIGPIPE blocked by
/// global_init ) would read the cluster to the end of its listing with
/// nobody reading, then stay a zombie of a long-lived client or server.
struct Reaped(Child);

impl Reaped {
    fn spawn(cmd: &mut Command) -> Result<Reaped> {
        Ok(Reaped(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("running radosgw-admin")?))
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.0.wait()
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        // once waited for, neither signals it again: std keeps its status
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, Clone)]
pub struct Admin {
    pub program: String,
    pub conf: Option<PathBuf>,
    pub id: Option<String>,
    /// bounds the commands run() has running at once: per-object lookups
    /// ( index_entry, tail_prefixes, lc get, ... ), which can come from every
    /// group of every bucket in flight, and per-bucket calls ( bucket stats,
    /// bucket list, zone get, metadata get ); the streams ( stream(),
    /// radoslist() ) take none
    permits: Arc<Semaphore>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct BucketStats {
    pub bucket: String,
    #[serde(default)]
    pub tenant: String,
    pub id: String,
    pub marker: String,
    #[serde(default)]
    pub index_type: String,
    #[serde(default)]
    pub index_generation: u64,
    #[serde(default)]
    pub num_shards: u64,
    #[serde(default)]
    pub placement_rule: Value,
    #[serde(default)]
    pub usage: Value,
}

impl BucketStats {
    /// the name 'bucket list' uses
    pub fn name(&self) -> String {
        if self.tenant.is_empty() { self.bucket.clone() } else { format!("{}/{}", self.tenant, self.bucket) }
    }

    pub fn placement(&self) -> String {
        let rule = match &self.placement_rule {
            Value::String(s) => s.clone(),
            Value::Object(o) => o.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string(),
            _ => String::new(),
        };
        let name = rule.split('/').next().unwrap_or_default();
        if name.is_empty() { "default-placement".into() } else { name.into() }
    }

    pub fn num_objects(&self) -> u64 {
        self.usage.as_object().map_or(0, |u| u.values().filter_map(|c| c.get("num_objects")?.as_u64()).sum())
    }
}

/// Every bucket: the stats `bucket stats` gives, and the names `bucket list`
/// gives that it left out.  RGWBucketAdminOp::info skips, and still exits 0,
/// a bucket whose instance or index header it cannot read ( rgw_bucket.cc
/// bucket_stats() ): the damaged bucket a scan should look at.
#[derive(Debug, Clone, Default)]
pub struct AllBuckets {
    pub stats: Vec<BucketStats>,
    /// sorted
    pub unstatted: Vec<String>,
}

impl AllBuckets {
    /// Orphan detection tells a live bucket's objects by its marker, which
    /// only its stats give: an error when a bucket has none, since its
    /// objects would be taken for orphans.
    pub fn require_stats(&self) -> Result<()> {
        let n = self.unstatted.len();
        if n == 0 {
            return Ok(());
        }
        let shown = self.unstatted.iter().take(10).map(String::as_str).collect::<Vec<_>>().join(", ");
        let more = if n > 10 { format!(" and {} more", n - 10) } else { String::new() };
        bail!("radosgw-admin bucket stats could not read {n} bucket(s) ( {shown}{more} ): orphans cannot be told without their markers, as their objects would be taken for orphans");
    }

    /// Say that a bucket with no stats is scanned without them: the scan
    /// asks again, and records why they cannot be read.
    pub fn warn_unstatted(bucket: &str) {
        tracing::warn!("{bucket}: radosgw-admin bucket list names it, but bucket stats left it out ( its instance or index header could not be read ); scanning it without stats");
    }

    /// Every bucket's name, sorted, those with no stats too; and the stats
    /// by name.
    pub fn by_name(self) -> (Vec<String>, HashMap<String, BucketStats>) {
        let mut names: Vec<String> = self.stats.iter().map(BucketStats::name).chain(self.unstatted).collect();
        names.sort();
        (names, self.stats.into_iter().map(|s| (s.name(), s)).collect())
    }

    /// Every bucket's stats by marker, which orphans are classified by; an
    /// error as require_stats() gives.
    pub fn markers(self) -> Result<HashMap<String, BucketStats>> {
        self.require_stats()?;
        Ok(self.stats.into_iter().map(|s| (s.marker.clone(), s)).collect())
    }
}

/// The names both listings give that no stats name, sorted.  A bucket
/// removed while the stats were read is in only the first; one created,
/// only the second.
fn unstatted(before: Vec<String>, after: &[String], stats: &[BucketStats]) -> Vec<String> {
    let after: std::collections::HashSet<&str> = after.iter().map(String::as_str).collect();
    let statted: std::collections::HashSet<String> = stats.iter().map(BucketStats::name).collect();
    let mut names: Vec<String> = before.into_iter().filter(|b| after.contains(b.as_str()) && !statted.contains(b)).collect();
    names.sort();
    names.dedup();
    names
}

/// The zone's pools, as specs escaped by rgw_pool::to_str() ( see
/// store::parse_pool() ).
#[derive(Debug, Clone, Default)]
pub struct ZonePools {
    /// every placement target's data pools, the default placement's STANDARD first
    pub data: Vec<String>,
    pub extra: Vec<String>,
    pub index: HashMap<String, String>,
}

impl ZonePools {
    /// The pools of a `radosgw-admin zone get` dump.  A placement's data pools
    /// are its storage classes' ( RGWZonePlacementInfo::dump() ); a zone written
    /// before storage classes has one `data_pool` instead, which
    /// RGWZonePlacementInfo::decode_json() still reads as STANDARD's.
    pub fn from_zone(zone: &Value) -> ZonePools {
        let mut pools = ZonePools::default();
        let mut placements: Vec<&Value> = zone["placement_pools"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
        placements.sort_by_key(|p| p["key"] != "default-placement");
        fn add(pools: &mut Vec<String>, pool: Option<&str>) {
            if let Some(pool) = pool.filter(|p| !p.is_empty()) {
                if !pools.iter().any(|d| d == pool) {
                    pools.push(pool.to_string());
                }
            }
        }
        for p in placements {
            let val = &p["val"];
            if let (Some(key), Some(index)) = (p["key"].as_str(), val["index_pool"].as_str()) {
                pools.index.insert(key.to_string(), index.to_string());
            }
            if let Some(classes) = val["storage_classes"].as_object() {
                let mut names: Vec<&String> = classes.keys().collect();
                names.sort_by_key(|c| *c != "STANDARD");
                for sc in names {
                    add(&mut pools.data, classes[sc]["data_pool"].as_str());
                }
            } else {
                add(&mut pools.data, val["data_pool"].as_str());
            }
            add(&mut pools.extra, val["data_extra_pool"].as_str());
        }
        pools
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcObj {
    #[serde(default)]
    pub oid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcEntry {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub objs: Vec<GcObj>,
}

/// One entry of `bi list`, with the fields the checks read.  An OLH entry
/// ( kind "olh" ) names the current version in `instance`, flags it a
/// delete marker as a listing entry would, is `pending` while its log holds
/// ops not yet applied to the OLH object, and takes its epoch's time as
/// `mtime` ( a counter before 21, which gives none ).
#[derive(Debug, Clone, Default)]
pub struct IndexEntry {
    pub kind: String,
    pub name: String,
    pub instance: String,
    pub exists: bool,
    pub flags: u64,
    pub pending: bool,
    pub tag: String,
    pub etag: String,
    pub mtime: String,
    /// an OLH's epoch
    pub epoch: u64,
    /// an OLH whose last version is gone, and whose OLH object is being removed
    pub pending_removal: bool,
}

pub const FLAG_DELETE_MARKER: u64 = 0x4;
pub const FLAG_VER_MARKER: u64 = 0x8;

impl IndexEntry {
    pub fn from_value(v: &Value) -> IndexEntry {
        let e = &v["entry"];
        let s = |x: &Value| x.as_str().unwrap_or_default().to_string();
        let nonempty = |x: &Value| x.as_array().is_some_and(|p| !p.is_empty()) || x.as_object().is_some_and(|p| !p.is_empty());
        if v["type"] == "olh" {
            // rgw_bucket_olh_entry::dump(): the key under "key", a pending
            // log of ( epoch, ops ) pairs
            let dm = e["delete_marker"].as_bool().unwrap_or(false);
            return IndexEntry {
                kind: "olh".into(),
                name: s(&e["key"]["name"]),
                instance: s(&e["key"]["instance"]),
                exists: e["exists"].as_bool().unwrap_or(false),
                flags: if dm { FLAG_DELETE_MARKER } else { 0 },
                pending: nonempty(&e["pending_log"]),
                tag: s(&e["tag"]),
                etag: String::new(),
                mtime: s(&e["epoch_timestamp"]),
                epoch: e["epoch"].as_u64().unwrap_or(0),
                pending_removal: e["pending_removal"].as_bool().unwrap_or(false),
            };
        }
        IndexEntry {
            kind: s(&v["type"]),
            name: s(&e["name"]),
            instance: s(&e["instance"]),
            exists: e["exists"].as_bool().unwrap_or(false),
            flags: e["flags"].as_u64().unwrap_or(0),
            pending: nonempty(&e["pending_map"]),
            tag: s(&e["tag"]),
            etag: s(&e["meta"]["etag"]),
            mtime: s(&e["meta"]["mtime"]),
            ..Default::default()
        }
    }

    pub fn is_delete_marker(&self) -> bool {
        self.flags & FLAG_DELETE_MARKER != 0
    }

    /// Whether this is the listing entry of ( name, instance ): a versioned
    /// key's placeholder ( flag VER_MARKER ) or OLH is not.
    pub fn lists(&self, name: &str, instance: &str) -> bool {
        (self.kind == "plain" || self.kind == "instance") && self.name == name && self.instance == instance && self.flags & FLAG_VER_MARKER == 0
    }

    /// Whether this is part of a versioned key's bookkeeping: its
    /// placeholder, one of its versions or its OLH.
    pub fn versioned(&self) -> bool {
        self.kind == "olh" || self.flags & FLAG_VER_MARKER != 0 || !self.instance.is_empty()
    }

    /// The same fields, from a natively decoded entry.
    pub fn from_dir(e: &crate::decode::DirEntry) -> IndexEntry {
        IndexEntry {
            kind: "plain".into(),
            name: e.name.clone(),
            instance: e.instance.clone(),
            exists: e.exists,
            flags: e.flags as u64,
            pending: e.pending > 0,
            tag: e.tag.clone(),
            etag: e.etag.clone(),
            mtime: crate::oid::iso(e.mtime),
            ..Default::default()
        }
    }

    pub fn mtime(&self) -> Option<i64> {
        parse_time(&self.mtime)
    }
}

/// Whether `b` can start the name of an RGW RADOS object: `<marker>_`, a
/// bucket marker holding neither '_' nor '\n'.
fn rados_name(b: &[u8]) -> bool {
    b.iter().position(|c| *c == b'_' || *c == b'\n').is_some_and(|i| i > 0 && b[i] == b'_')
}

/// radoslist --rgw-obj-fs's records, `oid FS bucket FS key \n` each, as
/// (oid, bucket, key).  FS frames the bucket, but a key may hold '\n', and
/// then the next record's oid follows the key after one of several: it is
/// the one a RADOS object's name can start after.  An error if none or
/// more than one can, rather than a record that names the wrong object.
struct Records<R: BufRead> {
    pieces: std::iter::Peekable<std::io::Split<R>>,
    /// the next record's oid, read with the key before it
    oid: Option<Vec<u8>>,
    /// nothing after an error is framed
    failed: bool,
}

impl<R: BufRead> Records<R> {
    fn new(reader: R) -> Records<R> {
        Records { pieces: reader.split(FS).peekable(), oid: None, failed: false }
    }

    fn piece(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.pieces.next().transpose()?)
    }

    fn record(&mut self, oid: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let show = |b: &[u8]| String::from_utf8_lossy(b).escape_debug().to_string();
        if !rados_name(&oid) {
            bail!("radoslist wrote {:?}, which names no RADOS object of RGW's", show(&oid));
        }
        let (Some(bucket), Some(mut rest)) = (self.piece()?, self.piece()?) else {
            bail!("radoslist's output ends in the record of {:?}", show(&oid));
        };
        if self.pieces.peek().is_none() {
            // the last record
            if rest.pop() != Some(b'\n') {
                bail!("radoslist's output ends in the key of {:?}", show(&oid));
            }
            return Ok((oid, bucket, rest));
        }
        let at: Vec<usize> = (0..rest.len()).filter(|&i| rest[i] == b'\n' && rados_name(&rest[i + 1..])).collect();
        match at[..] {
            [i] => {
                self.oid = Some(rest.split_off(i + 1));
                rest.pop();
                Ok((oid, bucket, rest))
            }
            [] => bail!("radoslist wrote {:?} after the bucket of {:?}, which holds no RADOS object of RGW's", show(&rest), show(&oid)),
            _ => bail!(
                "the key of {:?} holds line breaks, so radoslist's {:?} can be split into a key and the next RADOS object {} ways; list natively",
                show(&oid),
                show(&rest),
                at.len()
            ),
        }
    }
}

impl<R: BufRead> Iterator for Records<R> {
    type Item = Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let oid = match self.oid.take() {
            Some(oid) => oid,
            None => match self.piece() {
                Ok(Some(oid)) => oid,
                Ok(None) => return None,
                Err(e) => {
                    self.failed = true;
                    return Some(Err(e));
                }
            },
        };
        let record = self.record(oid);
        self.failed = record.is_err();
        Some(record)
    }
}

/// A radosgw-admin command that failed: what it said, and its exit status
/// ( an errno: radosgw-admin exits with posix_errortrans() of its error ).
#[derive(Debug)]
pub struct Failed {
    pub code: Option<i32>,
    message: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failed {}

/// Whether a command failed with ENOENT.
fn enoent(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Failed>().is_some_and(|f| f.code == Some(libc::ENOENT))
}

impl Admin {
    /// An Admin running at most `concurrency` ( at least 1 ) commands through
    /// run() at once.
    pub fn new(program: String, conf: Option<PathBuf>, id: Option<String>, concurrency: usize) -> Admin {
        let permits = Arc::new(Semaphore::new(concurrency.clamp(1, Semaphore::MAX_PERMITS)));
        Admin { program, conf, id, permits }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.program);
        if let Some(conf) = &self.conf {
            cmd.arg("-c").arg(conf);
        }
        if let Some(id) = &self.id {
            cmd.arg("--id").arg(id);
        }
        cmd.args(args);
        cmd
    }

    /// Run a command to completion and return its output; an error if it fails.
    /// Waits while the Admin's limit of commands are running.
    pub async fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let _permit = self.permits.acquire().await.context("the radosgw-admin limit is closed")?;
        let mut cmd = tokio::process::Command::from(self.command(args));
        let out = cmd.output().await.with_context(|| format!("running {}", self.program))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.lines().filter(|l| !l.contains("dangerous and experimental")).collect::<Vec<_>>().join(" ");
            let message = format!("{} {} failed ( {} ): {}", self.program, args.join(" "), out.status, err.chars().rev().take(300).collect::<String>().chars().rev().collect::<String>());
            return Err(Failed { code: out.status.code(), message }.into());
        }
        Ok(out.stdout)
    }

    /// Run a command through run() ( and its limit ) and parse the JSON it prints.
    pub async fn json<T: DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        let out = self.run(args).await?;
        let text = String::from_utf8_lossy(&out);
        serde_json::from_str(&text).with_context(|| format!("parsing the output of {}", args.join(" ")))
    }

    /// Stream the elements of the JSON array a command prints.  The channel
    /// ends with an error if the command fails.  Not under run()'s limit: a
    /// stream lives as long as its unit, which holds one at a time.  The
    /// command is killed if the reader goes away, or its output does not parse.
    pub fn stream<T: DeserializeOwned + Send + 'static>(&self, args: &[&str]) -> mpsc::Receiver<Result<T>> {
        let (tx, rx) = mpsc::channel(4096);
        let mut cmd = self.command(args);
        let what = args.join(" ");
        tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<()> {
                let mut child = Reaped::spawn(&mut cmd)?;
                let stderr = stderr_tail(&mut child.0, STDERR_TAIL);
                let stdout = child.0.stdout.take().expect("piped");
                json_stream::for_each(stdout, |item: T| {
                    tx.blocking_send(Ok(item)).map_err(|_| anyhow::anyhow!("the reader went away"))
                })?;
                let status = child.wait()?;
                if !status.success() {
                    bail!("radosgw-admin {what} failed ( {status} ){}", stderr_reason(stderr));
                }
                Ok(())
            })();
            if let Err(e) = result {
                let _ = tx.blocking_send(Err(e));
            }
        });
        rx
    }

    /// radoslist's records: (RADOS object, bucket, key), all of one S3
    /// object's together; `bucket`'s first, then those of the buckets its
    /// Swift manifests name ( and `bucket` again for segments in it ).  With
    /// --rgw-obj-fs, radoslist leaves out open uploads' parts.
    ///
    /// radoslist names each bucket without its tenant, and looks up the
    /// buckets a manifest names in the tenant it runs in ( as Swift does ):
    /// so a tenant's `tenant/b` is listed as b under --tenant, and each
    /// record's bucket gets the tenant back, as the scan names buckets.  A
    /// record keeps its own bucket, since a manifest's segments are in the
    /// bucket it names; its RADOS object's marker tells nothing, since a
    /// copy's tail keeps its source bucket's.  Not under run()'s limit, and
    /// killed if the reader goes away, as stream() is.
    pub fn radoslist(&self, bucket: &str) -> mpsc::Receiver<Result<(String, String, String)>> {
        let (tx, rx) = mpsc::channel(16384);
        let (tenant, name) = bucket.split_once('/').unwrap_or(("", bucket));
        let mut cmd = self.command(&["bucket", "radoslist"]);
        cmd.arg(OsStr::from_bytes(&[b"--rgw-obj-fs=".as_slice(), &[FS]].concat()));
        if !tenant.is_empty() {
            cmd.arg(format!("--tenant={tenant}")).arg(format!("--uid={TENANT_UID}"));
        }
        cmd.arg(format!("--bucket={name}"));
        let (bucket, tenant) = (bucket.to_string(), tenant.to_string());
        tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<()> {
                let mut child = Reaped::spawn(&mut cmd)?;
                // radoslist ends a listing it could not finish with its reason, and "RESULTS ARE NOT RELIABLE"
                let stderr = stderr_tail(&mut child.0, STDERR_TAIL);
                let reader = BufReader::with_capacity(1 << 20, child.0.stdout.take().expect("piped"));
                for record in Records::new(reader) {
                    let (oid, b, key) = record.with_context(|| format!("reading radosgw-admin bucket radoslist --bucket={bucket}"))?;
                    let text = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
                    let b = if tenant.is_empty() { text(b) } else { format!("{tenant}/{}", text(b)) };
                    if tx.blocking_send(Ok((text(oid), b, text(key)))).is_err() {
                        return Ok(());
                    }
                }
                let status = child.wait()?;
                if !status.success() {
                    bail!("radosgw-admin bucket radoslist --bucket={bucket} failed ( {status} ){}", stderr_reason(stderr));
                }
                Ok(())
            })();
            if let Err(e) = result {
                let _ = tx.blocking_send(Err(e));
            }
        });
        rx
    }

    pub async fn zone_pools(&self) -> Result<ZonePools> {
        Ok(ZonePools::from_zone(&self.json(&["zone", "get"]).await?))
    }

    pub async fn bucket_stats(&self, bucket: &str) -> Result<BucketStats> {
        self.json(&["bucket", "stats", &format!("--bucket={bucket}")]).await
    }

    /// A bucket's stats; None if there is no such bucket.  bucket stats
    /// exits with ENOENT for one ( ERR_NO_SUCH_BUCKET, which
    /// posix_errortrans() maps to it ), but so it does for a bucket whose
    /// instance is gone ( RGWBucketAdminOp::info maps that ENOENT to
    /// ERR_NO_SUCH_BUCKET too ) or, before 20, one missing an index shard: a
    /// damaged bucket.  So only a bucket with no entrypoint either, which
    /// `metadata get` reads without its instance or index, is taken for one
    /// that does not exist; any other failure is an error.
    pub async fn find_bucket_stats(&self, bucket: &str) -> Result<Option<BucketStats>> {
        let e = match self.bucket_stats(bucket).await {
            Ok(st) => return Ok(Some(st)),
            Err(e) if enoent(&e) => e,
            Err(e) => return Err(e),
        };
        match self.run(&["metadata", "get", &format!("bucket:{bucket}")]).await {
            Err(m) if enoent(&m) => Ok(None),
            Ok(_) => Err(e.context(format!("bucket {bucket} has an entrypoint, but its stats cannot be read ( its instance or index is missing )"))),
            Err(m) => Err(e.context(format!("bucket {bucket}'s stats cannot be read, nor whether it has an entrypoint: {m:#}"))),
        }
    }

    /// every bucket's stats, from one call
    pub fn all_bucket_stats(&self) -> mpsc::Receiver<Result<BucketStats>> {
        self.stream(&["bucket", "stats"])
    }

    /// every bucket's name ( tenant/bucket, as BucketStats::name() ), from
    /// the bucket metadata keys: no bucket's instance or index is read
    pub async fn bucket_list(&self) -> Result<Vec<String>> {
        self.json(&["bucket", "list"]).await
    }

    /// Every bucket's stats, and the names `bucket list` gives on both sides
    /// of reading them that have none.
    pub async fn all_buckets(&self) -> Result<AllBuckets> {
        let before = self.bucket_list().await?;
        let mut stats = Vec::new();
        let mut rx = self.all_bucket_stats();
        while let Some(st) = rx.recv().await {
            stats.push(st?);
        }
        let after = self.bucket_list().await?;
        let unstatted = unstatted(before, &after, &stats);
        Ok(AllBuckets { stats, unstatted })
    }

    /// The index entries of one index name ( escaped, as the index holds
    /// it ): its listing entries, and a versioned key's placeholder, versions
    /// and OLH.  An error if radosgw-admin fails, so a failed lookup does not
    /// read as a key that is gone.  Each is a radosgw-admin process that
    /// reads every shard of the bucket's index: run()'s limit ( the one
    /// --admin-concurrency sets ) keeps a bucket with many misses from
    /// starting thousands, and is the only one they wait for.
    pub async fn index_entries(&self, bucket: &str, name: &str) -> Result<Vec<IndexEntry>> {
        let entries: Vec<Value> = self.json(&["bi", "list", &format!("--bucket={bucket}"), &format!("--object={name}")]).await?;
        Ok(entries.iter().map(IndexEntry::from_value).filter(|e| e.name == name).collect())
    }

    pub fn bi_list(&self, bucket: &str) -> mpsc::Receiver<Result<Value>> {
        self.stream(&["bi", "list", &format!("--bucket={bucket}")])
    }

    pub fn gc_list(&self) -> mpsc::Receiver<Result<GcEntry>> {
        self.stream(&["gc", "list", "--include-all"])
    }

    /// whether the bucket's lifecycle has an AbortIncompleteMultipartUpload rule
    pub async fn has_mp_expiration(&self, bucket: &str) -> bool {
        let Ok(lc) = self.json::<Value>(&["lc", "get", &format!("--bucket={bucket}")]).await else { return false };
        lc["rule_map"].as_array().is_some_and(|rules| {
            rules.iter().any(|r| {
                let mp = &r["rule"]["mp_expiration"];
                [&mp["days"], &mp["date"]].iter().any(|v| match v {
                    Value::String(s) => !s.is_empty(),
                    Value::Number(n) => n.as_u64().is_some_and(|n| n > 0),
                    _ => false,
                })
            })
        })
    }

    /// the name prefixes of an object's tail objects, from its manifest
    pub async fn tail_prefixes(&self, bucket: &str, name: &str, instance: &str) -> Vec<String> {
        let mut args = vec!["object".to_string(), "stat".into(), format!("--bucket={bucket}"), format!("--object={name}")];
        if !instance.is_empty() {
            args.push(format!("--object-version={instance}"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let Ok(stat) = self.json::<Value>(&args).await else { return Vec::new() };
        let manifest = &stat["manifest"];
        let (Some(prefix), Some(marker)) = (manifest["prefix"].as_str(), manifest["tail_placement"]["bucket"]["marker"].as_str()) else {
            return Vec::new();
        };
        let multipart =
            manifest["rules"].as_array().is_some_and(|r| r.iter().any(|r| r["val"]["part_size"].as_u64().unwrap_or(0) > 0));
        if multipart {
            vec![format!("{marker}__multipart_{prefix}."), format!("{marker}__shadow_{prefix}.")]
        } else {
            vec![format!("{marker}__shadow_{prefix}")]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn zone_pools_of_both_placement_layouts() {
        // a squid zone, and one placement as a zone written before storage classes has it
        let zone: Value = serde_json::from_str(
            r#"{"placement_pools": [
                {"key": "fast", "val": {"index_pool": "z.fast.index", "data_pool": "z.fast.data", "data_extra_pool": "z.non-ec"}},
                {"key": "default-placement", "val": {"index_pool": "z.index", "storage_classes": {
                    "COLD": {"data_pool": "z.cold"}, "GLACIER": {}, "STANDARD": {"data_pool": "z.data"}},
                    "data_extra_pool": "z.non-ec", "index_type": 0, "inline_data": true}},
                {"key": "empty", "val": {"index_pool": "z.empty.index", "storage_classes": {"STANDARD": {}},
                    "data_pool": "ignored", "data_extra_pool": ""}}
            ]}"#,
        )
        .unwrap();
        let pools = ZonePools::from_zone(&zone);
        assert_eq!(pools.data, ["z.data", "z.cold", "z.fast.data"]);
        assert_eq!(pools.extra, ["z.non-ec"]);
        assert_eq!(pools.index.len(), 3);
        assert_eq!(pools.index["fast"], "z.fast.index");
        assert!(ZonePools::from_zone(&serde_json::json!({})).data.is_empty());
    }

    fn stats(tenant: &str, bucket: &str) -> BucketStats {
        serde_json::from_value(serde_json::json!({ "bucket": bucket, "tenant": tenant, "id": format!("id-{bucket}"), "marker": format!("m-{bucket}") })).unwrap()
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unstatted_names_are_in_both_listings() {
        let st = [stats("", "b1"), stats("t", "b2")];
        // t/b2 is named as bucket list names it; gone was removed, new created, while the stats were read
        let got = unstatted(names(&["zz", "b1", "t/b2", "gone", "damaged"]), &names(&["b1", "t/b2", "damaged", "new", "zz"]), &st);
        assert_eq!(got, names(&["damaged", "zz"]));
        assert!(unstatted(names(&["b1", "t/b2"]), &names(&["b1", "t/b2"]), &st).is_empty());
    }

    #[test]
    fn orphans_need_every_marker() {
        let all = AllBuckets { stats: vec![stats("", "b1")], unstatted: Vec::new() };
        assert_eq!(all.markers().unwrap().keys().collect::<Vec<_>>(), vec!["m-b1"]);
        let all = AllBuckets { stats: vec![stats("", "b1")], unstatted: names(&["t/b2"]) };
        let e = all.require_stats().unwrap_err().to_string();
        assert!(e.contains("t/b2"), "{e}");
        assert!(all.markers().is_err());
        let many = AllBuckets { stats: Vec::new(), unstatted: (0..12).map(|i| format!("b{i:02}")).collect() };
        let e = many.require_stats().unwrap_err().to_string();
        assert!(e.contains("12 bucket(s)") && e.contains("b09") && !e.contains("b10") && e.contains("and 2 more"), "{e}");
    }

    /// A radosgw-admin whose bucket stats leaves out a bucket bucket list names.
    #[tokio::test]
    async fn all_buckets_names_what_bucket_stats_left_out() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-admin-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("radosgw-admin");
        let script = concat!(
            "#!/bin/sh\n",
            "case \"$1 $2\" in\n",
            "\"bucket list\") echo '[\"b1\", \"t/b2\"]' ;;\n",
            "\"bucket stats\") echo 'error getting bucket stats bucket=b2 ret=-5' >&2; echo '[{\"bucket\": \"b1\", \"id\": \"i1\", \"marker\": \"m1\"}]' ;;\n",
            "*) exit 1 ;;\n",
            "esac\n"
        );
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, DEFAULT_CONCURRENCY);
        let all = admin.all_buckets().await.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(all.stats.iter().map(BucketStats::name).collect::<Vec<_>>(), names(&["b1"]));
        assert_eq!(all.unstatted, names(&["t/b2"]));
        assert!(all.require_stats().is_err(), "orphans are not told without t/b2's marker");
        let (queue, stats) = all.by_name();
        assert_eq!(queue, names(&["b1", "t/b2"]), "t/b2 is scanned, without stats");
        assert!(stats.contains_key("b1") && !stats.contains_key("t/b2"));
    }

    /// run() has no more than its limit of commands running at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-admin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("running")).unwrap();
        let program = dir.join("radosgw-admin");
        // each run records how many are running, itself included
        let script = "#!/bin/sh\nd=$(dirname \"$0\")\nmkdir \"$d/running/$$\"\nls \"$d/running\" | wc -l >> \"$d/counts\"\nsleep 0.1\nrmdir \"$d/running/$$\"\necho '{}'\n";
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, 4);
        let calls = (0..64).map(|_| admin.json::<Value>(&["bucket", "stats"]));
        for r in futures::future::join_all(calls).await {
            r.unwrap();
        }
        let counts = std::fs::read_to_string(dir.join("counts")).unwrap();
        let counts: Vec<usize> = counts.lines().map(|l| l.trim().parse().unwrap()).collect();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(counts.len(), 64);
        let max = counts.into_iter().max().unwrap();
        assert!((2..=4).contains(&max), "{max} running at once");
    }

    /// Index lookups wait for run()'s limit alone: as many run at once as
    /// it lets, more than a fixed limit of their own would.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn index_lookups_take_the_admin_limit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-lookups-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(dir.join("running")).unwrap();
        let program = dir.join("radosgw-admin");
        // each lookup records how many are running, itself included, and waits for the others to start
        let script = "#!/bin/sh\nd=$(dirname \"$0\")\nmkdir \"$d/running/$$\"\nls \"$d/running\" | wc -l >> \"$d/counts\"\nsleep 0.5\nrmdir \"$d/running/$$\"\necho '[]'\n";
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, 24);
        let lookups = (0..48).map(|i| {
            let admin = admin.clone();
            async move { admin.index_entries("b", &format!("k{i}")).await }
        });
        for r in futures::future::join_all(lookups).await {
            assert!(r.unwrap().is_empty());
        }
        let counts = std::fs::read_to_string(dir.join("counts")).unwrap();
        let max = counts.lines().map(|l| l.trim().parse::<usize>().unwrap()).max().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!((17..=24).contains(&max), "{max} running at once");
    }

    /// A limit of 0 is taken as 1, not as a limit nothing gets through.
    #[test]
    fn zero_concurrency_is_one() {
        let admin = Admin::new("radosgw-admin".into(), None, None, 0);
        assert_eq!(admin.permits.available_permits(), 1);
    }

    /// A radosgw-admin that prints `stdout`, says `stderr` and exits 5.
    fn failing(name: &str, stdout: impl AsRef<[u8]>, stderr: &str) -> (Admin, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-admin-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("out"), stdout).unwrap();
        std::fs::write(dir.join("err"), stderr).unwrap();
        let program = dir.join("radosgw-admin");
        std::fs::write(&program, "#!/bin/sh\nd=$(dirname \"$0\")\ncat \"$d/out\"\ncat \"$d/err\" >&2\nexit 5\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        (Admin::new(program.display().to_string(), None, None, DEFAULT_CONCURRENCY), dir)
    }

    /// radosgw-admin exits with ENOENT for a bucket that does not exist, and
    /// has no entrypoint for it: no stats, and no error.  It exits so too for
    /// a bucket whose instance or index shard is gone, which has one: an
    /// error, as is any other failure, with its reason.
    #[tokio::test]
    async fn missing_buckets_have_no_stats() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-admin-{}-nobucket", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("radosgw-admin");
        // what radosgw-admin says: ERR_NO_SUCH_BUCKET, a read_stats() ENOENT, and metadata get's ENOENT
        let script = r#"#!/bin/sh
nobucket() { echo 'failure: (2002) Unknown error 2002: ' >&2; exit 2; }
nokey() { echo "ERROR: can't get key: (2) No such file or directory" >&2; exit 2; }
case "$*" in
'bucket stats --bucket=gone'|'bucket stats --bucket=noinstance'|'bucket stats --bucket=t/unsure') nobucket ;;
'bucket stats --bucket=noshard') echo 'error getting bucket stats bucket=noshard ret=-2' >&2; echo 'failure: (2) No such file or directory: ' >&2; exit 2 ;;
'metadata get bucket:gone') nokey ;;
'metadata get bucket:noinstance'|'metadata get bucket:noshard') echo '{"key": "bucket:x", "data": {}}' ;;
*) echo 'ERROR: timed out' >&2; exit 110 ;;
esac
"#;
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, DEFAULT_CONCURRENCY);
        assert!(admin.find_bucket_stats("gone").await.unwrap().is_none());
        for damaged in ["noinstance", "noshard"] {
            let err = format!("{:#}", admin.find_bucket_stats(damaged).await.expect_err(damaged));
            assert!(err.starts_with(&format!("bucket {damaged} has an entrypoint")) && err.contains(&format!("--bucket={damaged} failed ( exit status: 2 )")), "{err}");
        }
        let err = format!("{:#}", admin.find_bucket_stats("t/unsure").await.unwrap_err());
        assert!(err.contains("nor whether it has an entrypoint") && err.contains("metadata get bucket:t/unsure failed ( exit status: 110 ): ERROR: timed out"), "{err}");
        let err = admin.find_bucket_stats("slow").await.unwrap_err();
        assert_eq!(err.downcast_ref::<Failed>().and_then(|f| f.code), Some(110));
        assert!(format!("{err:#}").ends_with("( exit status: 110 ): ERROR: timed out"), "{err:#}");
        std::fs::remove_dir_all(dir).ok();
    }

    /// Whether process `pid` is gone within 5 s: neither running nor left a
    /// zombie; if not, it is killed and reaped here.
    async fn reaped(pid: i32) -> bool {
        for _ in 0..100 {
            // a zombie still takes a signal: only a reaped child does not
            if unsafe { libc::kill(pid, 0) } != 0 {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        false
    }

    /// A radosgw-admin that, as global_init has it, takes no SIGPIPE: it
    /// writes its pid, prints `stdout` and waits on, for a reader or a kill.
    fn lingering(name: &str, stdout: impl AsRef<[u8]>) -> (Admin, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-admin-{}-{name}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("out"), stdout).unwrap();
        let program = dir.join("radosgw-admin");
        std::fs::write(&program, "#!/bin/sh\ntrap '' PIPE\nd=$(dirname \"$0\")\necho $$ > \"$d/pid\"\ncat \"$d/out\"\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        (Admin::new(program.display().to_string(), None, None, DEFAULT_CONCURRENCY), dir)
    }

    fn pid_of(dir: &std::path::Path) -> i32 {
        std::fs::read_to_string(dir.join("pid")).unwrap().trim().parse().unwrap()
    }

    /// A streamed command whose reader goes away, or whose output does not
    /// parse, is killed and reaped: it neither reads on for nobody nor
    /// stays a zombie.
    #[tokio::test]
    async fn abandoned_commands_are_reaped() {
        let records: Vec<u8> = (0..200_000).flat_map(|i| [format!("M_k{i}").as_bytes(), &[FS], b"b", &[FS], format!("k{i}\n").as_bytes()].concat()).collect();
        let (admin, dir) = lingering("radoslist", records);
        let mut rx = admin.radoslist("b");
        assert!(rx.recv().await.unwrap().is_ok());
        drop(rx);
        assert!(reaped(pid_of(&dir)).await, "radoslist's child, its reader gone");
        std::fs::remove_dir_all(dir).ok();

        let array = format!("[{}{{\"a\": 1}}]", "{\"a\": 1}, ".repeat(100_000));
        let (admin, dir) = lingering("stream", array);
        let mut rx = admin.stream::<Value>(&["bi", "list"]);
        assert!(rx.recv().await.unwrap().is_ok());
        drop(rx);
        assert!(reaped(pid_of(&dir)).await, "a stream's child, its reader gone");
        std::fs::remove_dir_all(dir).ok();

        let (admin, dir) = lingering("unparsed", "[{\"a\": 1}, {\"a\": x");
        let mut rx = admin.stream::<Value>(&["bi", "list"]);
        assert!(rx.recv().await.unwrap().is_ok());
        assert!(rx.recv().await.unwrap().is_err(), "the output does not parse");
        assert!(reaped(pid_of(&dir)).await, "a stream's child whose output does not parse");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn failures_carry_the_reason() {
        // radosgw-admin says why on stderr; the exit status alone does not
        let chatter = "x".repeat(3 * STDERR_TAIL);
        let stderr = format!("{chatter}\nWARNING: dangerous and experimental features enabled\nERROR: bucket radoslist failed to finish\n");
        let records = [b"M_k1".as_slice(), &[FS], b"b", &[FS], b"k1\nM_k2", &[FS], b"b", &[FS], b"k2\n"].concat();
        let (admin, dir) = failing("radoslist", records, &stderr);
        let mut rx = admin.radoslist("b");
        let mut listed = Vec::new();
        let mut error = None;
        while let Some(r) = rx.recv().await {
            match r {
                Ok((oid, _, _)) => listed.push(oid),
                Err(e) => error = Some(format!("{e:#}")),
            }
        }
        assert_eq!(listed, ["M_k1", "M_k2"]);
        let error = error.expect("a failed radoslist ends with an error");
        assert!(error.ends_with("ERROR: bucket radoslist failed to finish"), "{error}");
        assert!(!error.contains("dangerous"), "{error}");
        assert!(error.len() < STDERR_TAIL + 200, "only the tail is kept");

        let (admin, dir2) = failing("stream", "[{\"a\":1}]", "ERROR: could not list\n");
        let mut rx = admin.stream::<Value>(&["bucket", "stats"]);
        assert!(rx.recv().await.unwrap().is_ok());
        let error = format!("{:#}", rx.recv().await.unwrap().unwrap_err());
        assert!(error.ends_with("( exit status: 5 ): ERROR: could not list"), "{error}");
        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_dir_all(dir2).ok();
    }

    #[test]
    fn olh_entry() {
        // rgw_bucket_olh_entry::dump() of a link not yet applied, before 21 ( the epoch a counter )
        let v = json!({ "type": "olh", "idx": "\u{80}1001_k", "entry": {
            "key": { "name": "k", "instance": "V1" }, "delete_marker": true, "epoch": 3, "epoch_timestamp": "0.000003",
            "pending_log": [{ "key": 3, "val": [{ "epoch": 3, "op": "link_olh", "op_tag": "T", "key": { "name": "k", "instance": "V1" } }] }],
            "tag": "OT", "exists": true, "pending_removal": false,
        } });
        let e = IndexEntry::from_value(&v);
        assert_eq!((e.kind.as_str(), e.name.as_str(), e.instance.as_str(), e.tag.as_str()), ("olh", "k", "V1", "OT"));
        assert!(e.exists && e.is_delete_marker() && e.pending && !e.pending_removal);
        assert_eq!((e.epoch, e.mtime()), (3, None));
        assert!(e.versioned() && !e.lists("k", "V1"));
        // from 21 on, the epoch is a time; and the log applied
        let mut v = v;
        v["entry"]["epoch_timestamp"] = json!("2024-05-06T07:08:09.123456Z");
        v["entry"]["pending_log"] = json!([]);
        v["entry"]["delete_marker"] = json!(false);
        let e = IndexEntry::from_value(&v);
        assert!(!e.pending && !e.is_delete_marker());
        assert_eq!(e.mtime(), crate::oid::parse_time("2024-05-06T07:08:09Z"));
    }

    /// radoslist --rgw-obj-fs's output of these records.
    fn output(records: &[(&str, &str, &str)]) -> Vec<u8> {
        records.iter().flat_map(|(oid, b, key)| [oid.as_bytes(), b.as_bytes(), key.as_bytes()].join(&FS).into_iter().chain(*b"\n")).collect()
    }

    /// The records read from `out`, as text; an error as `Err`.
    fn read(out: &[u8]) -> Vec<Result<(String, String, String), String>> {
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        Records::new(out).map(|r| r.map(|(o, b, k)| (text(o), text(b), text(k))).map_err(|e| format!("{e:#}"))).collect()
    }

    fn ok(records: &[(&str, &str, &str)]) -> Vec<Result<(String, String, String), String>> {
        records.iter().map(|(o, b, k)| Ok((o.to_string(), b.to_string(), k.to_string()))).collect()
    }

    #[test]
    fn radoslist_records() {
        let records = [
            ("M_k", "b", "k"),
            // the old separator, \x1f, in a key: in its oid too
            ("M_ctl\u{1f}", "b", "ctl\u{1f}"),
            ("M_a\u{1f}b\u{1f}c", "b", "a\u{1f}b\u{1f}c"),
            // a tab, and a key that looks like a record's fields
            ("M_x\tb\ty", "b", "x\tb\ty"),
            // a version: its head escaped, its key with the instance
            ("M__:v1_k", "b", "k[v1]"),
            ("M__:v1__u", "b", "_u[v1]"),
            // a multipart object's parts and stripes, and a copy's tail with its source's marker
            ("M__multipart_k.2~u.1", "b", "k"),
            ("M__shadow_k.2~u.1_1", "b", "k"),
            ("SRC__shadow_.x_1", "b", "k"),
            // a manifest's segments, in another bucket
            ("S_seg", "segs", "seg"),
        ];
        assert_eq!(read(&output(&records)), ok(&records));
        assert!(read(b"").is_empty());
    }

    #[test]
    fn radoslist_line_breaks() {
        // a key with line breaks: the next record's oid starts after one of them
        let records = [("M_a\nb", "b", "a\nb"), ("M_c", "b", "c"), ("M_\nd\n", "b", "\nd\n"), ("M_e\n", "b", "e\n")];
        assert_eq!(read(&output(&records)), ok(&records));
        // after either of these a RADOS object's name can start: M_z's, or x_y\nM_z's
        let got = read(&output(&[("M_a\nx_y", "b", "a\nx_y"), ("M_z", "b", "z"), ("M_k", "b", "k")]));
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].as_ref().is_err_and(|e| e.contains("2 ways")), "{got:?}");
    }

    #[test]
    fn radoslist_not_records() {
        let err = |out: &[u8]| {
            let got = read(out);
            assert!(matches!(&got[..], [Err(_)]), "{:?}: {got:?}", String::from_utf8_lossy(out));
        };
        // radoslist without fields, as without --rgw-obj-fs
        err(b"M_k\n");
        err(b"M_k\nM_j\n");
        // cut short
        err(&output(&[("M_k", "b", "k")])[..6]);
        err(&output(&[("M_k", "b", "k")])[..5]);
        // no marker, or none before '_'
        err(&output(&[("k", "b", "k")]));
        err(&output(&[("_k", "b", "k")]));
        // what follows a key is no RADOS object's name
        err(b"M_k\xffb\xffk\nj\xffb\xffj\n");
        let mut out = output(&[("M_k", "b", "k")]);
        out.extend(output(&[("_j", "b", "j")]));
        assert!(matches!(&read(&out)[..], [Err(_)]));
    }

    /// A radosgw-admin that writes bucket radoslist's records as it would
    /// with the separator it is given, and refuses --tenant without --uid
    /// as it does: of tb, its lines with the bucket's name alone, a copied
    /// object's tail with its source's marker, and a segment in segs.
    #[cfg(unix)]
    #[tokio::test]
    async fn radoslist_names_the_tenant() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-radoslist-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("radosgw-admin");
        let script = r#"#!/bin/sh
LC_ALL=C; export LC_ALL
tenant= uid= bucket= fs=
for a; do case $a in --rgw-obj-fs=*) fs=${a#--rgw-obj-fs=};; --tenant=*) tenant=${a#--tenant=};; --uid=*) uid=${a#--uid=};; --bucket=*) bucket=${a#--bucket=};; esac; done
if [ -n "$tenant" ] && [ -z "$uid" ]; then echo "ERROR: --tenant is set, but there's no user ID" >&2; exit 22; fi
r() { printf '%s%s%s%s%s\n' "$1" "$fs" "$2" "$fs" "$3"; }
case "$tenant:$bucket" in
t1:tb|:tb) r M_k tb k; r SRC__shadow_.x_1 tb k; r S_seg segs seg; r M_j tb j ;;
*) echo "no bucket $tenant:$bucket" >&2; exit 2 ;;
esac
"#;
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, DEFAULT_CONCURRENCY);
        let seeds = |bucket: &'static str| {
            let admin = admin.clone();
            async move {
                let mut rx = crate::native::radoslist_seeds(admin.radoslist(bucket));
                let mut got = Vec::new();
                while let Some(s) = rx.recv().await {
                    let s = s.unwrap();
                    got.push((s.bucket, s.key, s.oids));
                }
                got
            }
        };
        let (tenanted, plain) = (seeds("t1/tb").await, seeds("tb").await);
        std::fs::remove_dir_all(&dir).unwrap();
        let seed = |b: &str, k: &str, oids: &[&str]| (b.to_string(), k.to_string(), oids.iter().map(|o| o.to_string()).collect::<Vec<_>>());
        // the copied tail is k's, whatever its marker; the segment is segs' in the tenant
        assert_eq!(
            tenanted,
            [seed("t1/tb", "k", &["M_k", "SRC__shadow_.x_1"]), seed("t1/segs", "seg", &["S_seg"]), seed("t1/tb", "j", &["M_j"])]
        );
        assert_eq!(plain, [seed("tb", "k", &["M_k", "SRC__shadow_.x_1"]), seed("segs", "seg", &["S_seg"]), seed("tb", "j", &["M_j"])]);
    }
}
