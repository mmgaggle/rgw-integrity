//! The checks: the gap check, one S3 object at a time, and the checks for the
//! other artifacts known RGW races leave behind.  The gap check is
//! rgw-gap-list.py's ( stat each RADOS object a bucket's listing names, in
//! every pool, and list what is missing from all ); the classification, and
//! every other check, are rgw-integrity's own: the published rgw-gap-list.py
//! ( v2.2, v3.0 ) has none.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{OnceCell, Semaphore};
use tokio::task::JoinSet;

use crate::admin::{Admin, BucketStats, IndexEntry};
use crate::finding::{Candidate, Class, Confidence, Context, Finding, Tally, cause};
use crate::limiter::Limiter;
use crate::oid::{Kind, Oid, decode_refcount, iso, key_oid, parse_oid, parse_time, split_key, survives_gc, tag_text};
use crate::store::{PoolId, Pools, Stat, Store, strerror};

pub const XATTR_IDTAG: &str = "user.rgw.idtag";
pub const XATTR_TAIL_TAG: &str = "user.rgw.tail_tag";
pub const XATTR_ETAG: &str = "user.rgw.etag";
pub const XATTR_MP_COMPLETION_TAG: &str = "user.rgw.mp_completion_tag";
pub const XATTR_REFCOUNT: &str = "refcount";

use Confidence::{High, Low, Medium};

/// A key as the listings write it: `name`, or `name[instance]`.
fn entry_key(name: &str, instance: &str) -> String {
    if instance.is_empty() { name.to_string() } else { format!("{name}[{instance}]") }
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    /// skip findings on objects younger than this many seconds, for a later
    /// scan to report ( their gaps are still listed )
    pub grace: i64,
    /// compare each index entry's ETag with its head's
    pub check_index: bool,
    /// read each tail object's refcount; with a prefix, also those of the
    /// objects outside it, whose heads may carry the references
    pub refcount: bool,
    /// read each bucket's open multipart uploads from its index
    pub uploads: bool,
    /// only S3 objects whose key starts with this; a native listing reads
    /// only the index entries under it, unless the refcount check or orphan
    /// detection needs every head
    pub match_prefix: Option<String>,
    /// concurrent head reads of the index check
    pub threads: usize,
    /// find orphans: RADOS objects in the data pools that no bucket references
    #[serde(default)]
    pub orphans: bool,
    /// how buckets are listed: natively, from the index and the manifests,
    /// shard by shard, following Swift large objects' segments into their
    /// buckets; or with radosgw-admin bucket radoslist
    #[serde(default)]
    pub listing: Listing,
    /// the scan lists every bucket, as one that names none does: a native
    /// listing follows a Swift large object's segments into no bucket, but
    /// for the keys outside the prefix
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub every_bucket: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Listing {
    #[default]
    Native,
    Radoslist,
}

impl Options {
    /// Whether the scan covers an S3 key ( `name` or `name[instance]` ): every
    /// check reports only on the keys the prefix covers.
    pub fn covers(&self, key: &str) -> bool {
        self.match_prefix.as_deref().is_none_or(|p| key.starts_with(p))
    }
}

/// A key prefix as the CLI, the API and the dashboard take it: trimmed, as
/// rgw-gap-list strips its -m, and none when blank, so `-m "$P"` with an unset
/// or stray-spaced `P` checks every key rather than almost none.  Still a
/// plain prefix, not rgw-gap-list's word-boundary regex.
pub fn normalise_prefix(p: Option<&str>) -> Option<String> {
    p.map(str::trim).filter(|p| !p.is_empty()).map(str::to_string)
}

impl Default for Options {
    fn default() -> Self {
        Options {
            grace: 3600,
            check_index: false,
            refcount: false,
            uploads: true,
            match_prefix: None,
            threads: 32,
            orphans: false,
            listing: Listing::Native,
            every_bucket: false,
        }
    }
}

/// A snapshot of the GC queue: each queued object's (tag, due time).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GcIndex {
    pub map: HashMap<String, Vec<(String, Option<i64>)>>,
    pub entries: usize,
    pub taken: i64,
}

impl GcIndex {
    pub async fn load(admin: &Admin) -> Result<GcIndex> {
        let mut gc = GcIndex { taken: now(), ..Default::default() };
        let mut rx = admin.gc_list();
        while let Some(entry) = rx.recv().await {
            let entry = entry?;
            gc.entries += 1;
            let tag = entry.tag.trim_end_matches('\0').to_string();
            let due = parse_time(&entry.time);
            for obj in entry.objs {
                gc.map.entry(obj.oid).or_default().push((tag.clone(), due));
            }
        }
        Ok(gc)
    }
}

/// References on tail objects, for the refcount check: those a copy or dedup
/// took, and the tags of the heads that name each object.  Merged across
/// buckets, since a copy's head can be in another bucket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RefLedger {
    pub needed: BTreeMap<String, (String, BTreeSet<String>)>,
    pub carried: BTreeMap<String, BTreeSet<String>>,
}

impl RefLedger {
    pub fn merge(&mut self, other: RefLedger) {
        for (oid, (bucket, tags)) in other.needed {
            self.needed.entry(oid).or_insert_with(|| (bucket, BTreeSet::new())).1.extend(tags);
        }
        for (oid, tags) in other.carried {
            self.carried.entry(oid).or_default().extend(tags);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.needed.is_empty()
    }

    /// References no head carries.
    pub fn resolve(&self, ctx: &Context) -> Vec<Finding> {
        let mut out = Vec::new();
        for (oid, (bucket, tags)) in &self.needed {
            let carried = self.carried.get(oid);
            let stale: Vec<&String> = tags.iter().filter(|t| carried.is_none_or(|c| !c.contains(*t))).collect();
            if stale.is_empty() {
                continue;
            }
            let f = Finding::new(Class::LatentLeak, "unheld_reference", bucket)
                .oids(std::slice::from_ref(oid))
                .evidence(json!({ "unheld_tags": stale }))
                .hint("once the objects that name this tail are deleted, it is never freed; a copy in a bucket this scan did not cover may still hold the reference");
            out.push(ctx.rank(
                f,
                vec![
                    cause("lost-copy", High, "a copy that lost its race took this reference, and no head carries its tag".to_string()),
                    cause("dedup", Medium, "dedup takes references with the target's tail tag".to_string()),
                ],
                None,
            ));
        }
        out
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BucketReport {
    pub bucket: String,
    pub rados_objects: u64,
    pub gaps: u64,
    pub findings: Vec<Finding>,
    /// the `s3://bucket/key MISSING <oid>` lines of rgw-gap-list, but for
    /// what is no gap: a delete marker's head, radoslist's misnamed OLH, a
    /// key a native listing saw that is no longer in the index
    pub missing: Vec<String>,
    pub tally: Tally,
    pub refs: RefLedger,
    pub seconds: f64,
    pub errors: Vec<String>,
    /// the bucket's references, by partition, when the scan finds orphans
    #[serde(skip)]
    pub references: Option<crate::detect::Refs>,
    /// a join's objects that nothing references, to classify with the rest
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

#[derive(Debug, Clone)]
struct Upload {
    key: String,
    meta: bool,
    parts: BTreeSet<u64>,
}

#[derive(Default)]
struct Out {
    findings: Vec<Finding>,
    /// the findings' fingerprints: a null version's head, which the listing
    /// yields as its key's OLH too, as radoslist does, is found once
    fingerprints: HashSet<String>,
    missing: Vec<String>,
    /// the lines in `missing`: that null version's lost objects are one line
    /// each, as a server's gap list keeps them
    lines: HashSet<String>,
    tally: Tally,
    refs: RefLedger,
    gaps: u64,
    errors: Vec<String>,
}

struct Bucket {
    name: String,
    stats: Option<BucketStats>,
    marker: String,
    start: i64,
    /// the index shard the unit lists, when it lists only one: its uploads
    /// are that shard's, and heads in the others name uploads too
    shard: Option<u32>,
    uploads: HashMap<String, Upload>,
    named: Mutex<HashSet<String>>,
    lc_mp: OnceCell<bool>,
    out: Mutex<Out>,
    rados_objects: Arc<AtomicU64>,
    /// the RADOS objects found missing so far, as `out.gaps` counts them
    gaps: Arc<AtomicU64>,
}

impl Bucket {
    fn emit(&self, f: Finding) {
        let mut out = self.out.lock().unwrap();
        if !out.fingerprints.insert(f.fingerprint()) {
            return;
        }
        out.tally.add(&f);
        tracing::warn!(
            "[{}] s3://{}/{}: {}{}",
            f.class.as_str().to_uppercase(),
            f.bucket,
            f.key.as_deref().unwrap_or(""),
            f.check,
            f.top_cause().map(|c| format!(", likely {} ({})", c.cause, c.confidence.as_str())).unwrap_or_default()
        );
        out.findings.push(f);
    }

    fn skip(&self, reason: &str) {
        self.out.lock().unwrap().tally.skip(reason);
    }

    /// Something the checks could not read: the bucket was not fully checked.
    fn error(&self, e: String) {
        self.out.lock().unwrap().errors.push(e);
    }
}

struct Group {
    bucket: String,
    key: String,
    /// a Swift large object's segment the native listing followed into its
    /// bucket: that bucket's index placement
    followed: Option<String>,
    oids: Vec<String>,
    /// the index entry, from a native listing, and the shard it is in
    entry: Option<crate::decode::DirEntry>,
    shard: Option<String>,
    uploads: BTreeSet<String>,
    /// the uploads its head names that are open, each with its meta
    /// object's bucket marker and key
    open_uploads: BTreeMap<String, (String, String)>,
    /// those the bucket's listing of open uploads does not reach, to look
    /// up by their meta objects ( process_group )
    unlisted_uploads: BTreeMap<String, (String, String)>,
    gc: Vec<(String, Vec<(String, Option<i64>)>)>,
    present: Vec<(String, PoolId)>,
    missing: Vec<String>,
}

impl Group {
    fn new(bucket: String, key: String) -> Group {
        Group {
            bucket,
            key,
            followed: None,
            oids: Vec::new(),
            entry: None,
            shard: None,
            uploads: BTreeSet::new(),
            open_uploads: BTreeMap::new(),
            unlisted_uploads: BTreeMap::new(),
            gc: Vec::new(),
            present: Vec::new(),
            missing: Vec::new(),
        }
    }

    fn head(&self) -> Option<&String> {
        self.oids.iter().find(|o| parse_oid(o).kind == Kind::Head)
    }

    fn gc_tags(&self) -> Vec<String> {
        let tags: BTreeSet<&String> = self.gc.iter().flat_map(|(_, e)| e.iter().map(|(t, _)| t)).collect();
        tags.into_iter().cloned().collect()
    }
}

#[derive(Debug, Clone)]
struct HeadInfo {
    mtime: i64,
    idtag: Option<String>,
    tail_tag: Option<String>,
    etag: Option<String>,
}

impl HeadInfo {
    /// rewritten keeping an older tail, as a copy onto itself does
    fn keep_tail(&self) -> bool {
        matches!((&self.idtag, &self.tail_tag), (Some(i), Some(t)) if i != t)
    }
}

struct Meta {
    oid: String,
    mtime: i64,
    parts: BTreeSet<u64>,
    record: Option<String>,
}

/// What the index holds of a key whose head is missing.
#[derive(Debug)]
enum Indexed {
    /// its listing entry
    Entry(IndexEntry),
    /// no listing entry, but a versioned key's bookkeeping ( its entries,
    /// the OLH entry among them if it has one ): the head is the key's OLH
    Olh(Vec<IndexEntry>),
    /// the OLH of a versioned key starting with '_', which radoslist names
    /// from its escaped index name: an object that does not exist
    Misnamed,
    /// nothing: deleted since it was listed, or a key radoslist writes in
    /// a form no reading finds
    Gone,
}

/// Find a key as radoslist writes it in the index, with `lookup` ( the
/// entries of an index name ).  A key that ends in "[...]" is a version,
/// or a key of that name that is not: both are tried.  A key's null delete
/// marker a later version replaced is no answer for its head: that is the
/// OLH, which GET without versionId reads, and names the current version.
async fn indexed<F, Fut>(key: &str, lookup: F) -> Result<Indexed>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<IndexEntry>>>,
{
    // radoslist writes the key; the index holds it escaped
    let escape = |n: &str| if n.starts_with('_') { format!("_{n}") } else { n.to_string() };
    let (name, instance) = split_key(key);
    let mut ways = Vec::new();
    // radoslist writes no "[]" for an empty instance
    if !instance.is_empty() {
        ways.push((escape(name), instance));
    }
    ways.push((escape(key), ""));
    let mut olh = None;
    for (name, instance) in &ways {
        let entries = lookup(name.clone()).await?;
        if let Some(e) = entries.iter().find(|e| e.lists(name, instance)) {
            // the null delete marker stays listed ( demoted ) once a version
            // replaces it, and the OLH entry then names that version
            let replaced = instance.is_empty() && e.is_delete_marker() && entries.iter().any(|o| o.kind == "olh" && o.exists && !o.is_delete_marker());
            if !replaced {
                return Ok(Indexed::Entry(e.clone()));
            }
        }
        if instance.is_empty() && entries.iter().any(IndexEntry::versioned) {
            olh = Some(entries);
        }
    }
    if let Some(entries) = olh {
        return Ok(Indexed::Olh(entries));
    }
    // the index name of a key starting with '_' starts with "__"
    if key.starts_with("__") && lookup(key.to_string()).await?.iter().any(IndexEntry::versioned) {
        return Ok(Indexed::Misnamed);
    }
    Ok(Indexed::Gone)
}

pub struct Engine {
    pub store: Arc<dyn Store>,
    pub admin: Arc<Admin>,
    pub ctx: Arc<Context>,
    pub gc: RwLock<Arc<GcIndex>>,
    pub gc_min_wait: i64,
    pub limiter: Arc<Limiter>,
    pub opts: Options,
    /// the partitions of the scan's orphan detection, which bucket scans
    /// file their references in
    pub partitions: Option<u32>,
    /// the buckets the native listing follows Swift large objects' segments into
    pub segments: crate::native::Segments,
}

fn copy_self_why() -> String {
    "the head's tail tag differs from its ID tag: it was rewritten keeping an older tail, as a copy onto itself does".into()
}

impl Engine {
    fn young(&self, ts: Option<i64>) -> bool {
        ts.is_some_and(|t| t > now() - self.opts.grace)
    }

    pub fn set_gc(&self, gc: Arc<GcIndex>) {
        *self.gc.write().unwrap() = gc;
    }

    /// A head's mtime and tags; None if it does not exist.  Err: what could
    /// not be read, which says nothing of whether it exists.
    async fn head_info(&self, oid: &str) -> Result<Option<HeadInfo>, String> {
        let (pool, mtime) = match self.store.locate(oid, Pools::Data).await {
            Stat::Found { pool, mtime, .. } => (pool, mtime),
            Stat::Missing => return Ok(None),
            Stat::Error(r) => return Err(format!("stat of the head {oid}: {}", strerror(r))),
        };
        let get = |name| async move {
            match self.store.getxattr(pool, oid, name).await {
                Ok(v) => Ok(v.map(|v| tag_text(&v))),
                Err(e) => Err(format!("reading {name} of the head {oid}: {e:#}")),
            }
        };
        let (idtag, tail_tag, etag) = tokio::join!(get(XATTR_IDTAG), get(XATTR_TAIL_TAG), get(XATTR_ETAG));
        Ok(Some(HeadInfo { mtime, idtag: idtag?, tail_tag: tail_tag?, etag: etag? }))
    }

    /// An upload's meta object; None if it does not exist ( the upload is
    /// closed ).  Err: what could not be read.
    async fn read_meta(&self, marker: &str, key: &str, upload: &str) -> Result<Option<Meta>, String> {
        let oid = format!("{marker}__multipart_{key}.{upload}.meta");
        let (pool, mtime) = match self.store.locate(&oid, Pools::ExtraFirst).await {
            Stat::Found { pool, mtime, .. } => (pool, mtime),
            Stat::Missing => return Ok(None),
            Stat::Error(r) => return Err(format!("stat of {oid}: {}", strerror(r))),
        };
        let keys = match self.store.omap_keys(pool, &oid, "part.").await {
            Ok(Some(keys)) => keys,
            // deleted since the stat
            Ok(None) => return Ok(None),
            Err(e) => return Err(format!("reading the parts of {oid}: {e:#}")),
        };
        let parts = keys.iter().filter_map(|k| k.strip_prefix("part.")?.parse().ok()).collect();
        let record = match self.store.getxattr(pool, &oid, XATTR_MP_COMPLETION_TAG).await {
            Ok(v) => v.map(|v| tag_text(&v)),
            Err(e) => return Err(format!("reading {XATTR_MP_COMPLETION_TAG} of {oid}: {e:#}")),
        };
        Ok(Some(Meta { oid, mtime, parts, record }))
    }

    /// The bucket's open uploads and their parts' entries, from its index:
    /// only keys in the multipart namespace, filtered by the OSDs.  All of
    /// them, under a prefix too: a head under it may name the upload of a
    /// key outside it ( a copy shares its source's tail ).
    async fn list_open_uploads(&self, stats: &BucketStats, shard: Option<u32>) -> Result<HashMap<String, Upload>> {
        let mut uploads: HashMap<String, Upload> = HashMap::new();
        if !stats.index_type.is_empty() && stats.index_type != "Normal" {
            return Ok(uploads);
        }
        let placement = stats.placement();
        for oid in crate::native::shard_objects(stats, shard) {
            let Some(keys) = self.store.index_keys(&placement, &oid, "_multipart_").await? else {
                anyhow::bail!("index object {oid} of {} not found", stats.name());
            };
            for k in keys {
                let Some(rest) = k.strip_prefix("_multipart_") else { continue };
                let Some((head, last)) = rest.rsplit_once('.') else { continue };
                let Some((key, upload)) = head.rsplit_once('.') else { continue };
                let u = uploads.entry(upload.to_string()).or_insert_with(|| Upload { key: key.to_string(), meta: false, parts: BTreeSet::new() });
                if last == "meta" {
                    u.meta = true;
                } else if let Ok(n) = last.parse() {
                    u.parts.insert(n);
                }
            }
        }
        Ok(uploads)
    }

    /// Whether a group is of another bucket than the one scanned: a large
    /// object's segment, followed into its bucket or listed there by radoslist.
    fn elsewhere(bucket: &Bucket, g: &Group) -> bool {
        g.followed.is_some() || g.bucket != bucket.name
    }

    /// Where to learn whether an upload a head names ( `o`, one of its
    /// multipart objects ) is open: the bucket's listing of its open
    /// uploads, if it reaches it; if not, the upload's meta object, looked
    /// up.  It does not reach an upload in another bucket's index ( a
    /// segment's ), nor one of a key in another shard than the unit's ( a
    /// copy shares its source's tail ).  A copy of another bucket's object,
    /// whose tail carries that bucket's marker, names an upload of no
    /// listing's: not looked up, as a scan of the whole bucket does not.
    fn place_upload(&self, bucket: &Bucket, g: &mut Group, o: &Oid) {
        let (Some(upload), Some(key)) = (o.upload, o.key) else { return };
        if Self::elsewhere(bucket, g) {
            g.unlisted_uploads.insert(upload.to_string(), (o.marker.to_string(), key.to_string()));
            return;
        }
        match bucket.uploads.get(upload) {
            Some(u) if u.meta => {
                g.open_uploads.insert(upload.to_string(), (bucket.marker.clone(), u.key.clone()));
            }
            Some(_) => {}
            None => {
                if let (Some(shard), Some(st)) = (bucket.shard, &bucket.stats)
                    && o.marker == bucket.marker
                    && crate::native::shard_of(key, st.num_shards) != shard as usize
                {
                    g.unlisted_uploads.insert(upload.to_string(), (o.marker.to_string(), key.to_string()));
                }
            }
        }
    }

    /// Scan one bucket.  `stats` saves a `bucket stats` call when the caller
    /// has them.
    pub async fn scan_bucket(self: &Arc<Self>, name: &str, stats: Option<BucketStats>) -> Result<BucketReport> {
        self.scan_bucket_with(name, stats, Arc::default(), None).await
    }

    /// The same, counting the RADOS objects listed in `progress` as it goes.
    /// `shard`: only that index shard of the bucket.
    pub async fn scan_bucket_with(
        self: &Arc<Self>,
        name: &str,
        stats: Option<BucketStats>,
        progress: Arc<AtomicU64>,
        shard: Option<u32>,
    ) -> Result<BucketReport> {
        self.scan_bucket_counting(name, stats, progress, Arc::default(), shard).await
    }

    /// The same, counting as well the RADOS objects found missing in `gaps`
    /// as it goes ( the report's gaps, so far ).
    pub async fn scan_bucket_counting(
        self: &Arc<Self>,
        name: &str,
        stats: Option<BucketStats>,
        progress: Arc<AtomicU64>,
        gaps: Arc<AtomicU64>,
        shard: Option<u32>,
    ) -> Result<BucketReport> {
        let started = Instant::now();
        let mut errors = Vec::new();
        let stats = match stats {
            Some(s) => Some(s),
            None => match self.admin.bucket_stats(name).await {
                Ok(s) => Some(s),
                // without them the bucket is listed with radoslist, and its
                // open uploads' parts ( which radoslist leaves out ) not found
                Err(e) if self.partitions.is_some() => anyhow::bail!("{e:#}; without its open uploads' parts, orphans cannot be told"),
                Err(e) => {
                    errors.push(format!("{e:#}; skipping the upload and index checks"));
                    None
                }
            },
        };
        let mut uploads = HashMap::new();
        if let (true, Some(st)) = (self.opts.uploads, &stats) {
            let listed = match self.list_open_uploads(st, shard).await {
                Ok(u) => Ok(u),
                // resharded since the stats were read?
                Err(e) => match self.admin.bucket_stats(name).await {
                    Ok(fresh) if fresh.index_generation != st.index_generation || fresh.num_shards != st.num_shards => {
                        self.list_open_uploads(&fresh, shard).await
                    }
                    _ => Err(e),
                },
            };
            match listed {
                Ok(u) => uploads = u,
                // radoslist leaves out open uploads' parts, which these name ( a
                // native listing reads them from the index )
                Err(e) if self.partitions.is_some() && self.opts.listing != Listing::Native => {
                    anyhow::bail!("{e:#}; without its open uploads' parts, orphans cannot be told")
                }
                Err(e) => errors.push(format!("{e:#}")),
            }
        }
        let marker = stats.as_ref().map(|s| s.marker.clone()).unwrap_or_default();
        let bucket = Arc::new(Bucket {
            name: name.to_string(),
            stats,
            marker,
            start: now(),
            shard,
            uploads,
            named: Mutex::default(),
            lc_mp: OnceCell::new(),
            out: Mutex::new(Out { errors, ..Default::default() }),
            rados_objects: progress,
            gaps,
        });

        let gc = self.gc.read().unwrap().clone();
        let native = self.opts.listing == Listing::Native && bucket.stats.is_some();
        if self.opts.listing == Listing::Native && !native {
            // a note, not an error: the failed `bucket stats` is already one
            tracing::warn!("{name}: no bucket stats, so listed with radoslist");
            bucket.skip("native listing, for want of bucket stats");
        }
        let mut rx = match (&bucket.stats, native) {
            (Some(st), true) => self.native_seeds(st.clone(), shard),
            _ if shard.is_some() => anyhow::bail!("a shard of {name} can only be listed natively"),
            _ => crate::native::radoslist_seeds(self.admin.radoslist(name)),
        };
        let mut tasks = JoinSet::new();
        // bound the S3 objects in flight, so a fast listing cannot outrun the stats
        let groups = Arc::new(Semaphore::new(4096));
        let mut references = self.partitions.map(crate::detect::Refs::new);
        // whether the listing read every head of the unit, and what each
        // names: else finalize_uploads cannot tell an upload no head names
        let mut listed_all = true;
        while let Some(seed) = rx.recv().await {
            let seed = match seed {
                Ok(s) => s,
                Err(e) => {
                    // a partial listing would make orphans of what it missed
                    if references.is_some() {
                        return Err(e.context(format!("listing {name}")));
                    }
                    bucket.out.lock().unwrap().errors.push(format!("{e:#}"));
                    listed_all = false;
                    break;
                }
            };
            if let Some(err) = &seed.error {
                if references.is_some() {
                    anyhow::bail!("{err}; without it, orphans cannot be told");
                }
                bucket.out.lock().unwrap().errors.push(err.clone());
                // a head of the bucket's ( not an open upload's parts, a note, or a segment followed )
                if !seed.parts && !seed.oids.is_empty() && seed.followed.is_none() {
                    listed_all = false;
                }
            }
            if let Some(why) = seed.skipped {
                bucket.skip(why);
            }
            // a note of what the listing could not follow: nothing to check
            if seed.oids.is_empty() && !seed.parts {
                continue;
            }
            if let Some(r) = references.as_mut() {
                for oid in &seed.oids {
                    r.add(oid);
                }
            }
            // an upload's meta object or part entry names its upload; only a head
            // ( a completed object ) makes it one this check reaches.  Open
            // uploads' parts are references; their uploads are checked on their own
            let object = !seed.parts && seed.oids.iter().any(|o| parse_oid(o).kind == Kind::Head);
            let mut g = Group::new(seed.bucket, seed.key);
            g.followed = seed.followed;
            if object {
                for oid in &seed.oids {
                    let o = parse_oid(oid);
                    if let (Some(upload), true) = (o.upload, o.kind.is_multipart()) {
                        g.uploads.insert(upload.to_string());
                        if self.opts.uploads {
                            self.place_upload(&bucket, &mut g, &o);
                        }
                    }
                }
                // named even outside the prefix, so finalize_uploads does not take
                // a completed object's upload for one no head names
                if !g.open_uploads.is_empty() {
                    bucket.named.lock().unwrap().extend(g.open_uploads.keys().cloned());
                }
            }
            // what a native listing under the prefix holds outside it: open
            // uploads' parts, and the OLH of a name the prefix runs into "["
            // after; one that needs every head, or radoslist's, holds all.  A
            // large object's segment followed into its bucket is checked with it
            if g.followed.is_none() && !self.opts.covers(&g.key) {
                // its head may still carry a reference a tail in the prefix needs
                if object && self.opts.refcount {
                    g.oids = seed.oids;
                    g.present = seed.found;
                    let permit = groups.clone().acquire_owned().await?;
                    let (engine, bucket) = (self.clone(), bucket.clone());
                    tasks.spawn(async move {
                        engine.carry_group(&bucket, g).await;
                        drop(permit);
                    });
                }
                continue;
            }
            bucket.rados_objects.fetch_add(seed.oids.len() as u64, Ordering::Relaxed);
            if seed.parts {
                continue;
            }
            g.entry = seed.entry;
            g.shard = seed.shard;
            g.present = seed.found;
            for oid in seed.oids {
                if let Some(entries) = gc.map.get(&oid) {
                    g.gc.push((oid.clone(), entries.clone()));
                }
                g.oids.push(oid);
            }
            let permit = groups.clone().acquire_owned().await?;
            let (engine, bucket) = (self.clone(), bucket.clone());
            tasks.spawn(async move {
                engine.process_group(&bucket, g).await;
                drop(permit);
            });
        }
        while let Some(r) = tasks.join_next().await {
            r?;
        }

        // radoslist --rgw-obj-fs leaves out open uploads' parts: name them here
        if let (false, Some(refs), Some(st)) = (native, references.as_mut(), &bucket.stats) {
            let listed;
            let uploads = if self.opts.uploads {
                &bucket.uploads
            } else {
                listed = self.list_open_uploads(st, None).await?;
                &listed
            };
            for (upload, u) in uploads.iter().filter(|(_, u)| u.meta) {
                let meta = format!("_multipart_{}.{upload}.meta", u.key);
                let Some(seed) = self.parts_seed(name, &st.marker, &meta).await else { continue };
                if let Some(err) = seed.error {
                    anyhow::bail!("{err}; without it, orphans cannot be told");
                }
                bucket.rados_objects.fetch_add(seed.oids.len() as u64, Ordering::Relaxed);
                for oid in &seed.oids {
                    refs.add(oid);
                }
            }
        }

        if bucket.stats.is_some() {
            self.finalize_uploads(&bucket, listed_all).await;
            if self.opts.check_index && !native {
                if let Err(e) = self.check_index(&bucket).await {
                    bucket.out.lock().unwrap().errors.push(format!("index check: {e:#}"));
                }
            }
        }

        let bucket = Arc::try_unwrap(bucket).map_err(|_| anyhow::anyhow!("a check of {name} is still running"))?;
        let out = bucket.out.into_inner().unwrap();
        Ok(BucketReport {
            bucket: name.to_string(),
            rados_objects: bucket.rados_objects.load(Ordering::Relaxed),
            gaps: out.gaps,
            findings: out.findings,
            missing: out.missing,
            tally: out.tally,
            refs: out.refs,
            seconds: started.elapsed().as_secs_f64(),
            errors: out.errors,
            references,
            candidates: Vec::new(),
        })
    }

    async fn process_group(&self, bucket: &Bucket, mut g: Group) {
        // the uploads no listing of this scan reaches are open if their meta objects are there
        for (upload, (marker, key)) in std::mem::take(&mut g.unlisted_uploads) {
            let meta = {
                let _permit = self.limiter.acquire().await;
                self.read_meta(&marker, &key, &upload).await
            };
            match meta {
                Ok(Some(_)) => {
                    g.open_uploads.insert(upload, (marker, key));
                }
                Ok(None) => {}
                Err(e) => bucket.error(e),
            }
        }
        // what the listing found needs no stat
        let unseen: Vec<String> = g.oids.iter().filter(|o| !g.present.iter().any(|(p, _)| p == *o)).cloned().collect();
        let stats: Vec<(String, Stat)> = futures::stream::iter(unseen)
            .map(|oid| async move {
                let _permit = self.limiter.acquire().await;
                let s = self.store.stat(&oid).await;
                (oid, s)
            })
            .buffer_unordered(256)
            .collect()
            .await;
        for (oid, s) in stats {
            match s {
                Stat::Found { pool, .. } => g.present.push((oid, pool)),
                Stat::Missing => g.missing.push(oid),
                Stat::Error(r) => {
                    let e = std::io::Error::from_raw_os_error(-r);
                    bucket.out.lock().unwrap().errors.push(format!("stat of {oid}: {e}"));
                }
            }
        }
        let head = g.head().cloned();
        if let (true, Some(e), Some(h)) = (self.opts.check_index, g.entry.clone(), head.as_deref()) {
            if g.missing.is_empty() {
                self.check_entry(bucket, &g, &e, h).await;
            }
        }
        if !g.missing.is_empty() {
            // rgw-gap-list's lines, but for what is no gap at all; a followed
            // segment's once a scan
            if self.classify_missing(bucket, &g, head.as_deref()).await {
                let lines: Vec<String> = g
                    .missing
                    .iter()
                    .map(|oid| format!("s3://{}/{} MISSING {oid}", g.bucket, g.key))
                    .filter(|l| g.followed.is_none() || self.segments.first(l))
                    .collect();
                let mut out = bucket.out.lock().unwrap();
                let lines: Vec<String> = lines.into_iter().filter(|l| out.lines.insert(l.clone())).collect();
                out.gaps += lines.len() as u64;
                bucket.gaps.store(out.gaps, Ordering::Relaxed);
                out.missing.extend(lines);
            }
        } else if !g.gc.is_empty() {
            self.check_pending_loss(bucket, &g, head.as_deref()).await;
        }
        for (upload, (marker, key)) in &g.open_uploads {
            self.check_open_upload(bucket, &g, head.as_deref(), upload, marker, key).await;
        }
        if self.opts.refcount {
            self.refcount_group(bucket, &g, head.as_deref(), true).await;
        }
    }

    /// Whether the group's bucket has an AbortIncompleteMultipartUpload rule.
    async fn lc_mp(&self, bucket: &Bucket, g: &Group) -> bool {
        if Self::elsewhere(bucket, g) {
            return self.segment_lc_mp(&g.bucket).await;
        }
        *bucket.lc_mp.get_or_init(|| self.admin.has_mp_expiration(&bucket.name)).await
    }

    /// Report a group's finding: a followed segment's once a scan
    /// ( Segments::first ), however many large objects name it.
    fn emit(&self, bucket: &Bucket, g: &Group, f: Finding) {
        if g.followed.is_none() || self.segments.first(&f.fingerprint()) {
            bucket.emit(f);
        }
    }

    /// abort_lag: seconds from the head write to the abort that queued the
    /// parts for GC, while GC still holds them.  An abort within minutes
    /// raced the completion; a later one found an upload the completion had
    /// left open.  requeued: GC holds the parts under another head's tag, as
    /// when a retried completion replaces the head it wrote before.
    async fn multipart_causes(
        &self,
        bucket: &Bucket,
        g: &Group,
        keep_tail: bool,
        by_abort: bool,
        abort_lag: Option<i64>,
        requeued: bool,
    ) -> Vec<Candidate> {
        let uploads = g.uploads.iter().cloned().collect::<Vec<_>>().join(", ");
        let lc = self.lc_mp(bucket, g).await;
        let raced = abort_lag.is_some_and(|l| l.abs() < 600);
        let left = (by_abort && !raced) || !g.open_uploads.is_empty() || (requeued && !keep_tail);
        let lag = abort_lag.map(|l| format!("; the abort came {l} s after the head write")).unwrap_or_default();
        let why = if requeued && !keep_tail {
            format!("a write of this key queued for GC the parts its head names, as a retried completion of upload {uploads} does")
        } else {
            format!("look in the RGW ops or access log for AbortMultipartUpload, or another CompleteMultipartUpload, of upload {uploads} after the object's mtime{lag}")
        };
        let lc_why = if lc { "the bucket has an AbortIncompleteMultipartUpload rule" } else { "the bucket has no AbortIncompleteMultipartUpload rule now" };
        let mut causes = vec![
            cause("mp-meta-left", if left { High } else { Medium }, why),
            cause("lc-abort", if !lc { Low } else if raced { High } else { Medium }, format!("{lc_why}{lag}")),
            cause("abort-race", if raced { High } else { Medium }, format!("look for AbortMultipartUpload of upload {uploads} while it was being completed{lag}")),
            cause("ix-fail", Low, None),
            cause("dedup", Low, None),
        ];
        if keep_tail {
            causes.push(cause("copy-self", High, copy_self_why()));
        }
        causes
    }

    fn atomic_causes(keep_tail: bool) -> Vec<Candidate> {
        if keep_tail {
            vec![cause("copy-self", High, copy_self_why()), cause("dedup", Medium, None), cause("ix-fail", Low, None)]
        } else {
            vec![cause("ix-fail", Medium, None), cause("dedup", Medium, None), cause("copy-self", Low, None)]
        }
    }

    /// Why a listing entry whose head is missing is not reported, and
    /// whether the miss is a gap all the same ( not judged yet ); None:
    /// report it.
    fn excuse(e: &IndexEntry, young: bool) -> Option<(&'static str, bool)> {
        if e.name.starts_with("_multipart_") {
            // a meta object lives in the data-extra pool, where the stat does not look
            return Some(("an open upload's meta object or part", !e.name.ends_with(".meta")));
        }
        if e.is_delete_marker() {
            return Some(("delete marker", false));
        }
        if e.pending {
            return Some(("index op in flight", true));
        }
        if young {
            return Some(("younger than the grace period", true));
        }
        None
    }

    /// Why a versioned key's missing OLH object is not reported: no OLH
    /// entry, ops not yet applied to the OLH object or its removal under
    /// way, an OLH with no versions left, a current version that is a delete
    /// marker ( GET answers 404 either way ), or a key too young.  None:
    /// report it.
    fn olh_excuse(olh: Option<&IndexEntry>, young: bool) -> Option<&'static str> {
        let Some(o) = olh else { return Some("a versioned key's OLH") };
        if o.pending || o.pending_removal {
            return Some("index op in flight");
        }
        if !o.exists {
            return Some("a versioned key's OLH");
        }
        if o.is_delete_marker() {
            return Some("delete marker");
        }
        if young {
            return Some("younger than the grace period");
        }
        None
    }

    /// The listing entry a native listing read, read again from its shard
    /// ( a followed segment's, in its own bucket's placement ): None if it is
    /// gone.  One bi_list call, of its name only.
    async fn entry_again(&self, bucket: &Bucket, g: &Group, e: &crate::decode::DirEntry) -> Result<Option<IndexEntry>> {
        let placement = g.followed.clone().or_else(|| bucket.stats.as_ref().map(BucketStats::placement));
        let (Some(placement), Some(shard)) = (placement, g.shard.as_deref()) else { anyhow::bail!("no index shard to read it from") };
        let _permit = self.limiter.acquire().await;
        let mut marker = Vec::new();
        loop {
            let out = self
                .store
                .index_exec(&placement, shard, "rgw", "bi_list", crate::decode::bi_list_named_op(&e.name, &marker, 1000))
                .await?
                .ok_or_else(|| anyhow::anyhow!("index shard {shard} does not exist"))?;
            let (page, truncated) = crate::decode::bi_list_ret(&out)?;
            for (kind, _, data) in &page {
                if *kind != 1 {
                    continue;
                }
                let again = IndexEntry::from_dir(&crate::decode::DirEntry::decode(data)?);
                if again.lists(&e.name, &e.instance) {
                    return Ok(Some(again));
                }
            }
            match page.last() {
                Some((_, last, _)) if truncated => marker = last.clone(),
                _ => return Ok(None),
            }
        }
    }

    /// Classify the missing objects of a group; whether they are a gap, to
    /// list as rgw-gap-list does.  A delete marker's head ( radoslist lists
    /// it ), radoslist's misnamed OLH, and a key a native listing saw that
    /// the index no longer holds are not; what is too young, in flight or
    /// otherwise not judged is.  A versioned key's missing OLH object is an
    /// inconsistency as a listed key's missing head is: GET answers 404.
    async fn classify_missing(&self, bucket: &Bucket, g: &Group, head: Option<&str>) -> bool {
        if head.is_none_or(|h| g.missing.iter().any(|m| m == h)) {
            let indexed = match &g.entry {
                Some(e) => {
                    let listed = IndexEntry::from_dir(e);
                    if let Some((why, gap)) = Self::excuse(&listed, self.young(listed.mtime())) {
                        bucket.skip(why);
                        return gap;
                    }
                    // the listing read the entry before the head was looked
                    // for: a key deleted since has neither
                    match self.entry_again(bucket, g, e).await {
                        Ok(Some(again)) => Indexed::Entry(again),
                        Ok(None) => {
                            bucket.skip("deleted during the scan");
                            return false;
                        }
                        Err(err) => {
                            bucket.out.lock().unwrap().errors.push(format!("reading the index entry of s3://{}/{} again: {err:#}", g.bucket, g.key));
                            Indexed::Entry(listed)
                        }
                    }
                }
                // in the bucket radoslist names, which a manifest's segments may not share
                None => match indexed(&g.key, |name| async move { self.admin.index_entries(&g.bucket, &name).await }).await {
                    Ok(i) => i,
                    Err(err) => {
                        // unjudged, so still a gap
                        bucket.out.lock().unwrap().errors.push(format!("index entry of s3://{}/{}: {err:#}", g.bucket, g.key));
                        return true;
                    }
                },
            };
            let entry = match indexed {
                Indexed::Entry(e) => e,
                Indexed::Olh(entries) => {
                    // the OLH object is written after its entry and versions
                    // are: date it by its epoch, where that is a time, or its newest version
                    let when = entries.iter().filter_map(IndexEntry::mtime).max();
                    let olh = entries.iter().find(|e| e.kind == "olh");
                    if let Some(why) = Self::olh_excuse(olh, self.young(when)) {
                        bucket.skip(why);
                        return true;
                    }
                    let olh = olh.expect("excused otherwise");
                    let listed = entries.iter().any(|e| e.lists(&olh.name, &olh.instance));
                    let hint = "GET without versionId answers 404; its versions remain, each read by its versionId";
                    let mut f = Finding::new(Class::Inconsistency, "olh_missing", &g.bucket)
                        .key(&g.key)
                        .evidence(json!({ "olh_epoch": olh.epoch, "olh_tag": olh.tag, "current_instance": olh.instance, "current_listed": listed }))
                        .hint(if listed { format!("ListObjects lists this key and {hint}") } else { hint.to_string() });
                    if let Some(h) = head {
                        f = f.oids(&[h.to_string()]);
                    }
                    self.emit(bucket, g, self.ctx.rank(f, Vec::new(), when));
                    return true;
                }
                Indexed::Misnamed => {
                    bucket.skip("radoslist's misnamed OLH");
                    return false;
                }
                Indexed::Gone => {
                    // deleted since, or misread: radoslist's line is all there is to go by
                    bucket.skip("not in the index");
                    return true;
                }
            };
            let when = entry.mtime();
            if let Some((why, gap)) = Self::excuse(&entry, self.young(when)) {
                bucket.skip(why);
                return gap;
            }
            let mut f = Finding::new(Class::Inconsistency, "listed_without_head", &g.bucket)
                .key(&g.key)
                .evidence(json!({ "entry_etag": entry.etag, "entry_mtime": entry.mtime, "entry_tag": entry.tag }))
                .hint("ListObjects lists this key and GET answers 404");
            if let Some(h) = head {
                f = f.oids(&[h.to_string()]);
            }
            let why = "a delete, put, delete sequence whose completions arrived out of order leaves a listed key with no head";
            self.emit(bucket, g, self.ctx.rank(f, vec![cause("stale-entry", Medium, why.to_string())], when));
            return true;
        }
        // what a head names is missing: a gap, judged or not
        let head = head.expect("checked above");
        let info = match self.head_info(head).await {
            Ok(Some(info)) => info,
            Ok(None) => {
                bucket.skip("head deleted during the scan");
                return true;
            }
            // unjudged, so still a gap
            Err(e) => {
                bucket.error(e);
                return true;
            }
        };
        if info.mtime >= bucket.start - 1 {
            bucket.skip("rewritten during the scan");
            return true;
        }
        if self.young(Some(info.mtime)) {
            bucket.skip("younger than the grace period");
            return true;
        }
        let multipart = g.missing.iter().any(|o| parse_oid(o).kind.is_multipart());
        let tags = g.gc_tags();
        let by_abort = tags.iter().any(|t| g.uploads.contains(t));
        let causes = if multipart {
            self.multipart_causes(bucket, g, info.keep_tail(), by_abort, None, false).await
        } else {
            Self::atomic_causes(info.keep_tail())
        };
        let mut evidence = json!({ "missing": g.missing.len(), "of": g.oids.len(), "head_idtag": info.idtag, "head_tail_tag": info.tail_tag });
        if !g.uploads.is_empty() {
            evidence["upload_ids"] = json!(g.uploads);
        }
        if !tags.is_empty() {
            evidence["gc_tags"] = json!(tags);
        }
        let f = Finding::new(Class::DataLoss, "missing_data", &g.bucket)
            .key(&g.key)
            .oids(&g.missing)
            .evidence(evidence)
            .hint("GET of this object fails where the missing objects start");
        self.emit(bucket, g, self.ctx.rank(f, causes, Some(info.mtime)));
        true
    }

    async fn check_pending_loss(&self, bucket: &Bucket, g: &Group, head: Option<&str>) {
        let mut doomed = Vec::new();
        let mut due = Vec::new();
        for (oid, entries) in &g.gc {
            let pool = g.present.iter().find(|(o, _)| o == oid).map(|(_, p)| *p);
            let refcount = match pool {
                Some(p) => match self.read_refcount(p, oid).await {
                    Ok(rc) => rc,
                    // whether GC frees it is unknown: not judged
                    Err(e) => {
                        bucket.error(e);
                        continue;
                    }
                },
                None => None,
            };
            if !survives_gc(entries.iter().map(|(t, _)| t.as_str()), refcount.as_ref()) {
                doomed.push(oid.clone());
                due.extend(entries.iter().filter_map(|(_, d)| *d));
            }
        }
        if doomed.is_empty() {
            return;
        }
        let info = match head {
            Some(h) => self.head_info(h).await,
            None => Ok(None),
        };
        let info = match info {
            Ok(Some(info)) => info,
            Ok(None) => return bucket.skip("deleted during the scan"),
            Err(e) => return bucket.error(e),
        };
        if info.mtime >= bucket.start - 1 {
            return bucket.skip("rewritten during the scan");
        }
        let tags = g.gc_tags();
        let by_abort = tags.iter().any(|t| g.uploads.contains(t));
        let due = due.into_iter().min();
        let multipart = doomed.iter().any(|o| parse_oid(o).kind.is_multipart());
        let causes = if multipart {
            // a GC entry is due rgw_gc_obj_min_wait after it was queued
            let lag = due.filter(|_| by_abort).map(|d| d - self.gc_min_wait - info.mtime);
            self.multipart_causes(bucket, g, info.keep_tail(), by_abort, lag, !by_abort).await
        } else {
            Self::atomic_causes(info.keep_tail())
        };
        let f = Finding::new(Class::PendingLoss, "queued_for_gc", &g.bucket)
            .key(&g.key)
            .oids(&doomed)
            .evidence(json!({
                "gc_tags": tags, "gc_due": due.map(iso), "queued_by_abort": by_abort,
                "head_idtag": info.idtag, "head_tail_tag": info.tail_tag,
            }))
            .hint("GC deletes these once its entries are due; escalate before then");
        self.emit(bucket, g, self.ctx.rank(f, causes, Some(info.mtime)));
    }

    /// A listed head names the parts of an upload that is still open, whose
    /// meta object is that of `key` in the bucket of `marker`.
    async fn check_open_upload(&self, bucket: &Bucket, g: &Group, head: Option<&str>, upload: &str, marker: &str, key: &str) {
        let info = match head {
            Some(h) => self.head_info(h).await,
            None => Ok(None),
        };
        let info = match info {
            Ok(Some(info)) => info,
            Ok(None) => return,
            Err(e) => return bucket.error(e),
        };
        if self.young(Some(info.mtime)) {
            return bucket.skip("younger than the grace period");
        }
        let meta = match self.read_meta(marker, key, upload).await {
            Ok(Some(meta)) => meta,
            Ok(None) => return bucket.skip("upload closed during the scan"),
            Err(e) => return bucket.error(e),
        };
        let evidence = json!({
            "upload_id": upload, "meta_oid": meta.oid, "meta_mtime": iso(meta.mtime),
            "head_idtag": info.idtag, "completion_record": meta.record,
        });
        if meta.record.is_some() && meta.record == info.idtag {
            let f = Finding::new(Class::Inconsistency, "completed_upload_open", &g.bucket)
                .key(&g.key)
                .upload(upload)
                .evidence(evidence)
                .hint("this build records completions, so an abort of the upload deletes only its meta object");
            let c = cause("mp-meta-left", High, "the upload's completion record matches the head".to_string());
            return self.emit(bucket, g, self.ctx.rank(f, vec![c], Some(info.mtime)));
        }
        let f = Finding::new(Class::AtRisk, "completed_upload_open", &g.bucket)
            .key(&g.key)
            .upload(upload)
            .evidence(evidence)
            .hint(format!("do not abort upload {upload} or retry its completion, and keep lifecycle's AbortIncompleteMultipartUpload from reaching it: each frees this object's data"));
        let causes = vec![
            cause("mp-meta-left", High, "the completion wrote the head, and the upload's meta object was never deleted".to_string()),
            cause("ix-fail", Medium, None),
        ];
        self.emit(bucket, g, self.ctx.rank(f, causes, Some(info.mtime)));
    }

    /// Open uploads no listed head names: all their parts should be indexed.
    /// Only those of keys the scan covers.  `listed_all`: the unit's listing
    /// read every head it holds, and what each names.
    async fn finalize_uploads(&self, bucket: &Bucket, listed_all: bool) {
        let named = bucket.named.lock().unwrap().clone();
        let mut outside = None;
        let mut uploads: Vec<(&String, &Upload)> =
            bucket.uploads.iter().filter(|(id, u)| u.meta && !named.contains(*id) && self.opts.covers(&u.key)).collect();
        uploads.sort_by_key(|(id, _)| *id);
        for (upload, u) in uploads {
            let meta = match self.read_meta(&bucket.marker, &u.key, upload).await {
                Ok(Some(meta)) => meta,
                // closed since it was listed
                Ok(None) => continue,
                Err(e) => {
                    bucket.error(e);
                    continue;
                }
            };
            if self.young(Some(meta.mtime)) {
                bucket.skip("younger than the grace period");
                continue;
            }
            let unindexed: Vec<u64> = meta.parts.difference(&u.parts).copied().collect();
            if unindexed.is_empty() {
                continue;
            }
            match self.named_outside(bucket, listed_all, &mut outside, upload).await {
                Some(false) => {}
                Some(true) => continue,
                // a head not read may name it, and GC would then free a completed object's data
                None => {
                    bucket.skip("an upload with unindexed parts, not every head that may name it read");
                    continue;
                }
            }
            let f = Finding::new(Class::Inconsistency, "part_entries_missing", &bucket.name)
                .key(&u.key)
                .upload(upload.as_str())
                .evidence(json!({
                    "parts": meta.parts.len(), "unindexed_parts": unindexed.iter().take(100).collect::<Vec<_>>(),
                    "meta_mtime": iso(meta.mtime),
                }))
                .hint("bucket stats undercount these parts until the upload is completed or aborted; no data is lost");
            let c = cause("refused-complete", High, "the upload's meta object lists parts that have no bucket index entries".to_string());
            bucket.emit(self.ctx.rank(f, vec![c], Some(meta.mtime)));
        }
    }

    /// Whether a head the unit's listing did not read names the upload;
    /// None: not known.  A native listing under a prefix reads no head
    /// outside it, and one of a shard none in the others, where a copy may
    /// share the upload's tail; a listing that failed partway, or could not
    /// read what a head names, missed what it did not read.  `outside`: the
    /// uploads every head of the bucket names, and whether all were read,
    /// from a native listing of every shard: once, the first time it is
    /// needed, for this unit ( each unit of a bucket scanned a shard at a
    /// time reads it again, as the server leases a bucket's units to any
    /// client ), and only for an upload whose parts lack index entries and
    /// that no head the unit read names.  A head whose manifest could not be
    /// read is an error of the unit, and leaves unjudged an upload no other
    /// head names.
    async fn named_outside(&self, bucket: &Bucket, listed_all: bool, outside: &mut Option<(HashSet<String>, bool)>, upload: &str) -> Option<bool> {
        let native = self.opts.listing == Listing::Native;
        if listed_all && bucket.shard.is_none() && !(native && !self.listing_prefix().is_empty()) {
            // the listing read every head of the bucket
            return Some(false);
        }
        let st = bucket.stats.as_ref().filter(|_| native)?;
        if outside.is_none() {
            let read = match self.uploads_named(st).await {
                Ok((named, errors)) => {
                    let all = errors.is_empty();
                    let mut out = bucket.out.lock().unwrap();
                    out.errors.extend(errors.into_iter().map(|e| format!("reading the uploads the heads of {} name: {e}", bucket.name)));
                    (named, all)
                }
                Err(e) => {
                    bucket.out.lock().unwrap().errors.push(format!("reading the uploads the heads of {} name: {e:#}", bucket.name));
                    (HashSet::new(), false)
                }
            };
            *outside = Some(read);
        }
        let (named, all) = outside.as_ref().expect("read above");
        if named.contains(upload) { Some(true) } else { all.then_some(false) }
    }

    /// A native listing's index entry against its head: a stale entry lists
    /// an older object than the head holds.
    async fn check_entry(&self, bucket: &Bucket, g: &Group, e: &crate::decode::DirEntry, head: &str) {
        if e.name.starts_with("_multipart_") || e.pending > 0 || e.is_delete_marker() {
            return;
        }
        let info = match self.head_info(head).await {
            Ok(Some(info)) => info,
            Ok(None) => return,
            Err(e) => return bucket.error(e),
        };
        if info.mtime >= bucket.start - 1 || self.young(Some(info.mtime)) {
            return;
        }
        if info.etag.is_none() || info.etag.as_deref() == Some(e.etag.as_str()) {
            return;
        }
        let f = Finding::new(Class::Inconsistency, "stale_entry", &g.bucket)
            .key(&g.key)
            .evidence(json!({
                "entry_etag": e.etag, "entry_mtime": iso(e.mtime), "entry_tag": e.tag,
                "head_etag": info.etag, "head_idtag": info.idtag, "head_mtime": iso(info.mtime),
            }))
            .hint("ListObjects reports the older object's ETag and size; re-link the key from its head (radosgw-admin object reindex, where available)");
        let causes = vec![
            cause("stalled-write", Medium, "a write that stalled past the pending-op expiry leaves the index listing the object it replaced".to_string()),
            cause("stale-entry", Medium, "completions applied out of order leave the index listing an older object".to_string()),
        ];
        self.emit(bucket, g, self.ctx.rank(f, causes, Some(info.mtime)));
    }

    /// Index entries that list an older object than their head holds: those
    /// of keys the scan covers.
    async fn check_index(&self, bucket: &Bucket) -> Result<()> {
        let mut seen = HashSet::new();
        let mut rx = self.admin.bi_list(&bucket.name);
        let mut entries = Vec::new();
        loop {
            let item = rx.recv().await;
            let done = item.is_none();
            if let Some(item) = item {
                let e = IndexEntry::from_value(&item?);
                // bi list names the entry as the index holds it: escaped, or in a namespace
                let key = crate::decode::Key::from_index(&e.name, &e.instance);
                if (e.kind == "plain" || e.kind == "instance")
                    && key.ns.is_empty()
                    && e.exists
                    && !e.pending
                    && !e.is_delete_marker()
                    && self.opts.covers(&entry_key(&key.name, &e.instance))
                    && seen.insert((e.name.clone(), e.instance.clone()))
                {
                    entries.push((key, e));
                }
            }
            if done || entries.len() >= 4096 {
                let batch = std::mem::take(&mut entries);
                let results: Vec<(crate::decode::Key, IndexEntry, Result<Option<HeadInfo>, String>)> = futures::stream::iter(batch)
                    .map(|(key, e)| async move {
                        let _permit = self.limiter.acquire().await;
                        let oid = format!("{}_{}", bucket.marker, key_oid(&key.name, &key.instance));
                        let info = self.head_info(&oid).await;
                        (key, e, info)
                    })
                    .buffer_unordered(self.opts.threads.max(1))
                    .collect()
                    .await;
                for (key, e, info) in results {
                    let info = match info {
                        Ok(Some(info)) => info,
                        Ok(None) => continue,
                        Err(err) => {
                            bucket.error(err);
                            continue;
                        }
                    };
                    if info.mtime >= bucket.start - 1 || self.young(Some(info.mtime)) {
                        continue;
                    }
                    if info.etag.is_none() || info.etag.as_deref() == Some(e.etag.as_str()) {
                        continue;
                    }
                    let f = Finding::new(Class::Inconsistency, "stale_entry", &bucket.name)
                        .key(entry_key(&key.name, &e.instance))
                        .evidence(json!({
                            "entry_etag": e.etag, "entry_mtime": e.mtime, "entry_tag": e.tag,
                            "head_etag": info.etag, "head_idtag": info.idtag, "head_mtime": iso(info.mtime),
                        }))
                        .hint("ListObjects reports the older object's ETag and size; re-link the key from its head (radosgw-admin object reindex, where available)");
                    let causes = vec![
                        cause("stalled-write", Medium, "a write that stalled past the pending-op expiry leaves the index listing the object it replaced".to_string()),
                        cause("stale-entry", Medium, "completions applied out of order leave the index listing an older object".to_string()),
                    ];
                    bucket.emit(self.ctx.rank(f, causes, Some(info.mtime)));
                }
            }
            if done {
                return Ok(());
            }
        }
    }

    /// A tail object's references; None if it has none, or is gone.  Err:
    /// what could not be read or decoded.
    async fn read_refcount(&self, pool: PoolId, oid: &str) -> Result<Option<crate::oid::Refcount>, String> {
        match self.store.getxattr(pool, oid, XATTR_REFCOUNT).await {
            Ok(None) => Ok(None),
            Ok(Some(b)) => decode_refcount(&b).map(Some).map_err(|e| format!("decoding the refcount of {oid}: {e:#}")),
            Err(e) => Err(format!("reading the refcount of {oid}: {e:#}")),
        }
    }

    /// References on this object's tail objects, and the tags its head carries.
    /// `needed`: false for an object the scan does not cover, whose head only
    /// carries references.
    async fn refcount_group(&self, bucket: &Bucket, g: &Group, head: Option<&str>, needed: bool) {
        let tails: Vec<(String, PoolId)> = g.present.iter().filter(|(o, _)| parse_oid(o).kind != Kind::Head).cloned().collect();
        if tails.is_empty() {
            return;
        }
        let refs: Vec<(String, BTreeSet<String>)> = futures::stream::iter(tails)
            .map(|(oid, pool)| async move {
                let _permit = self.limiter.acquire().await;
                let rc = self.read_refcount(pool, &oid).await;
                (oid, rc)
            })
            .buffer_unordered(64)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|(oid, rc)| match rc {
                Ok(rc) => Some((oid, rc?.tags().cloned().collect::<BTreeSet<String>>())),
                // an unread reference is no clean check: the bucket keeps its findings
                Err(e) => {
                    bucket.error(e);
                    None
                }
            })
            .filter(|(_, tags)| !tags.is_empty())
            .collect();
        if refs.is_empty() {
            return;
        }
        let info = match head {
            Some(h) => self.head_info(h).await,
            None => Ok(None),
        };
        let carried: BTreeSet<String> = match info {
            Ok(i) => i.map(|i| [i.idtag, i.tail_tag].into_iter().flatten().collect()).unwrap_or_default(),
            // what the head carries is unknown: its tails' references are not judged
            Err(e) => return bucket.error(e),
        };
        if !needed && carried.is_empty() {
            return;
        }
        let mut out = bucket.out.lock().unwrap();
        for (oid, tags) in refs {
            if needed {
                out.refs.needed.entry(oid.clone()).or_insert_with(|| (g.bucket.clone(), BTreeSet::new())).1.extend(tags);
            }
            out.refs.carried.entry(oid).or_default().extend(carried.iter().cloned());
        }
    }

    /// An object outside the scan's prefix, for the refcount check: a copy of
    /// an object inside it, or its source, names the same tail objects, and
    /// its head may carry a reference they hold.  No gap check, no findings.
    async fn carry_group(&self, bucket: &Bucket, mut g: Group) {
        let unseen: Vec<String> =
            g.oids.iter().filter(|o| parse_oid(o).kind != Kind::Head && !g.present.iter().any(|(p, _)| p == *o)).cloned().collect();
        let stats: Vec<(String, Stat)> = futures::stream::iter(unseen)
            .map(|oid| async move {
                let _permit = self.limiter.acquire().await;
                let s = self.store.stat(&oid).await;
                (oid, s)
            })
            .buffer_unordered(256)
            .collect()
            .await;
        for (oid, s) in stats {
            match s {
                Stat::Found { pool, .. } => g.present.push((oid, pool)),
                Stat::Missing => {}
                Stat::Error(r) => {
                    let e = std::io::Error::from_raw_os_error(-r);
                    bucket.out.lock().unwrap().errors.push(format!("stat of {oid}: {e}"));
                }
            }
        }
        let head = g.head().cloned();
        self.refcount_group(bucket, &g, head.as_deref(), false).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::DirEntry;
    use crate::store::{MockObject, MockStore};

    #[test]
    fn prefixes_are_trimmed_and_blank_is_none() {
        assert_eq!(normalise_prefix(None), None);
        assert_eq!(normalise_prefix(Some("")), None);
        assert_eq!(normalise_prefix(Some("   ")), None);
        assert_eq!(normalise_prefix(Some(" \tlogs/ \n")).as_deref(), Some("logs/"));
        assert_eq!(normalise_prefix(Some("a b")).as_deref(), Some("a b"), "inner spaces are the prefix's");
        let o = Options { match_prefix: normalise_prefix(Some("logs ")), ..Options::default() };
        assert!(o.covers("logs/x") && o.covers("logsx") && !o.covers("log"), "a plain prefix, not a word");
    }

    const MARKER: &str = "m1";

    fn stats() -> BucketStats {
        serde_json::from_value(json!({ "bucket": "b", "id": "id1", "marker": MARKER })).unwrap()
    }

    fn object(xattrs: &[(&str, &[u8])], omap: &[&str]) -> MockObject {
        MockObject {
            size: 1,
            mtime: 1000,
            xattrs: xattrs.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect(),
            omap: omap.iter().map(|k| k.to_string()).collect(),
        }
    }

    /// cls_refcount's encoding of these references
    fn refcount(refs: &[&str]) -> Vec<u8> {
        let mut body = (refs.len() as u32).to_le_bytes().to_vec();
        for r in refs {
            body.extend((r.len() as u32).to_le_bytes());
            body.extend(r.as_bytes());
            body.push(1);
        }
        let mut out = vec![1, 1];
        out.extend((body.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }

    /// Scan bucket b with radoslist, through a radosgw-admin that prints
    /// `radoslist` ( key, oid ) for bucket radoslist and `bi` for bi list.
    async fn scan(name: &str, store: MockStore, opts: Options, radoslist: &[(&str, &str)], bi: serde_json::Value) -> BucketReport {
        scan_counting(name, store, opts, radoslist, bi, Arc::default()).await
    }

    /// The same, counting the gaps in `gaps` as it goes.
    async fn scan_counting(name: &str, store: MockStore, opts: Options, radoslist: &[(&str, &str)], bi: serde_json::Value, gaps: Arc<AtomicU64>) -> BucketReport {
        scan_exiting(name, store, opts, radoslist, bi, gaps, 0).await
    }

    /// The same, bucket radoslist exiting with `code` once it has printed its records.
    async fn scan_exiting(
        name: &str,
        store: MockStore,
        opts: Options,
        radoslist: &[(&str, &str)],
        bi: serde_json::Value,
        gaps: Arc<AtomicU64>,
        code: i32,
    ) -> BucketReport {
        scan_with(name, store, opts, radoslist, bi, gaps, code, Setup::default()).await.unwrap()
    }

    /// What else a test scan runs with.
    struct Setup {
        gc: GcIndex,
        partitions: Option<u32>,
        /// the bucket stats the caller has ( none: `bucket stats` fails )
        stats: Option<BucketStats>,
    }

    impl Default for Setup {
        fn default() -> Self {
            Setup { gc: GcIndex::default(), partitions: None, stats: Some(stats()) }
        }
    }

    /// The same, as `setup` says.
    #[allow(clippy::too_many_arguments)]
    async fn scan_with(
        name: &str,
        store: MockStore,
        opts: Options,
        radoslist: &[(&str, &str)],
        bi: serde_json::Value,
        gaps: Arc<AtomicU64>,
        code: i32,
        setup: Setup,
    ) -> Result<BucketReport> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-scan-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lines: Vec<u8> = radoslist.iter().flat_map(|(key, oid)| record(oid, "b", key)).collect();
        std::fs::write(dir.join("radoslist"), lines).unwrap();
        std::fs::write(dir.join("bi"), bi.to_string()).unwrap();
        let program = dir.join("radosgw-admin");
        let script = format!("#!/bin/sh\nd=$(dirname \"$0\")\ncase \"$1 $2\" in\n\"bucket radoslist\") cat \"$d/radoslist\"; exit {code} ;;\n\"bi list\") cat \"$d/bi\" ;;\n*) exit 1 ;;\nesac\n");
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let engine = Arc::new(Engine {
            store: Arc::new(store),
            admin: Arc::new(Admin::new(program.display().to_string(), None, None, crate::admin::DEFAULT_CONCURRENCY)),
            ctx: Arc::new(Context { catalog: crate::finding::Catalog::builtin(), ..Default::default() }),
            gc: RwLock::new(Arc::new(setup.gc)),
            gc_min_wait: 7200,
            limiter: Limiter::new(64),
            opts: Options { listing: Listing::Radoslist, ..opts },
            partitions: setup.partitions,
            segments: Default::default(),
        });
        let report = engine.scan_bucket_counting("b", setup.stats, Arc::default(), gaps, None).await;
        std::fs::remove_dir_all(&dir).unwrap();
        report
    }

    /// Findings as ( check, key ), sorted.
    fn keys(findings: &[Finding]) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = findings.iter().map(|f| (f.check.clone(), f.key.clone().unwrap_or_default())).collect();
        v.sort();
        v
    }

    fn prefixed(opts: &Options) -> Options {
        Options { match_prefix: Some("logs/".into()), ..opts.clone() }
    }

    /// What a full scan finds of the keys under logs/, a scan of logs/ finds.
    fn assert_scoped(full: &[(String, String)], scoped: &[(String, String)]) {
        let want: Vec<(String, String)> = full.iter().filter(|(_, k)| k.starts_with("logs/")).cloned().collect();
        assert_eq!(scoped, want.as_slice());
    }

    #[tokio::test]
    async fn prefix_scopes_uploads() {
        // data/big was completed and its upload's meta object left behind; so
        // was logs/b's, which archive/b, a copy, names since logs/b was deleted
        let mut store = MockStore::new(1, 1);
        let mut index = Vec::new();
        let mut radoslist = Vec::new();
        for (key, upload, heads) in [("data/big", "U1", &["data/big"][..]), ("logs/b", "U2", &["archive/b"][..])] {
            store.put(1, &format!("{MARKER}__multipart_{key}.{upload}.meta"), object(&[], &["part.1"]));
            store.put(0, &format!("{MARKER}__multipart_{key}.{upload}.1"), object(&[], &[]));
            index.push(format!("_multipart_{key}.{upload}.meta"));
            for h in heads {
                store.put(0, &format!("{MARKER}_{h}"), object(&[(XATTR_IDTAG, b"t")], &[]));
                radoslist.push((*h, format!("{MARKER}_{h}")));
                radoslist.push((*h, format!("{MARKER}__multipart_{key}.{upload}.1")));
            }
        }
        store.index.insert(("default-placement".into(), ".dir.id1".into()), index);
        store.put(0, &format!("{MARKER}_logs/a"), object(&[], &[]));
        radoslist.push(("logs/a", format!("{MARKER}_logs/a")));
        let radoslist: Vec<(&str, &str)> = radoslist.iter().map(|(k, o)| (*k, o.as_str())).collect();
        let opts = Options::default();
        let run = |name: &'static str, opts: Options| {
            let (store, radoslist) = (MockStore { objects: store.objects.clone(), index: store.index.clone(), ..MockStore::new(1, 1) }, radoslist.clone());
            async move { keys(&scan(name, store, opts, &radoslist, json!([])).await.findings) }
        };
        let full = run("uploads-full", opts.clone()).await;
        let c = |k: &str| ("completed_upload_open".to_string(), k.to_string());
        assert_eq!(full, vec![c("archive/b"), c("data/big")]);
        assert_scoped(&full, &run("uploads-logs", prefixed(&opts)).await);
    }

    #[tokio::test]
    async fn prefix_scopes_references() {
        // archive/a is a copy of logs/a: its tag holds their tail; data/c's
        // tail holds a tag no head carries
        let mut store = MockStore::new(1, 0);
        let tail_a = format!("{MARKER}__shadow_logs/a.2~x_1");
        let tail_c = format!("{MARKER}__shadow_data/c.2~y_1");
        store.put(0, &format!("{MARKER}_logs/a"), object(&[(XATTR_IDTAG, b"tagA")], &[]));
        store.put(0, &format!("{MARKER}_archive/a"), object(&[(XATTR_IDTAG, b"tagB")], &[]));
        store.put(0, &tail_a, object(&[(XATTR_REFCOUNT, &refcount(&["", "tagB"]))], &[]));
        store.put(0, &format!("{MARKER}_data/c"), object(&[(XATTR_IDTAG, b"tagC")], &[]));
        store.put(0, &tail_c, object(&[(XATTR_REFCOUNT, &refcount(&["", "lost"]))], &[]));
        let radoslist = [
            ("archive/a", format!("{MARKER}_archive/a")),
            ("archive/a", tail_a.clone()),
            ("data/c", format!("{MARKER}_data/c")),
            ("data/c", tail_c.clone()),
            ("logs/a", format!("{MARKER}_logs/a")),
            ("logs/a", tail_a.clone()),
        ];
        let radoslist: Vec<(&str, &str)> = radoslist.iter().map(|(k, o)| (*k, o.as_str())).collect();
        let opts = Options { refcount: true, ..Options::default() };
        let ctx = Context { catalog: crate::finding::Catalog::builtin(), ..Default::default() };
        let run = |name: &'static str, opts: Options| {
            let (store, radoslist) = (MockStore { objects: store.objects.clone(), ..MockStore::new(1, 0) }, radoslist.clone());
            let ctx = &ctx;
            async move {
                let r = scan(name, store, opts, &radoslist, json!([])).await;
                r.refs.resolve(ctx).iter().flat_map(|f| f.oids.clone()).collect::<Vec<_>>()
            }
        };
        assert_eq!(run("refs-full", opts.clone()).await, vec![tail_c.clone()]);
        assert!(run("refs-logs", prefixed(&opts)).await.is_empty(), "archive/a carries logs/a's reference");
        let data = Options { match_prefix: Some("data/".into()), ..opts.clone() };
        assert_eq!(run("refs-data", data).await, vec![tail_c]);
    }

    #[tokio::test]
    async fn unread_refcounts_are_errors() {
        // data/c's tail holds a tag no head carries: its refcount unread, or
        // undecodable, is no clean check ( else a server retires the finding )
        let tail = format!("{MARKER}__shadow_data/c.2~y_1");
        let head = format!("{MARKER}_data/c");
        let store = || {
            let mut store = MockStore::new(1, 0);
            store.put(0, &head, object(&[(XATTR_IDTAG, b"tagC")], &[]));
            store.put(0, &tail, object(&[(XATTR_REFCOUNT, &refcount(&["", "lost"]))], &[]));
            store
        };
        let radoslist = [("data/c", head.as_str()), ("data/c", tail.as_str())];
        let opts = Options { refcount: true, ..Options::default() };
        let refs_errors = |r: BucketReport| {
            let errors: Vec<String> = r.errors.into_iter().filter(|e| e.contains("refcount")).collect();
            (r.refs.needed.keys().cloned().collect::<Vec<_>>(), errors)
        };
        assert_eq!(refs_errors(scan("rc-read", store(), opts.clone(), &radoslist, json!([])).await), (vec![tail.clone()], vec![]));
        let mut eio = store();
        eio.read_errors.insert((0, tail.clone()), -libc::EIO);
        let (needed, errors) = refs_errors(scan("rc-eio", eio, opts.clone(), &radoslist, json!([])).await);
        assert!(needed.is_empty());
        assert!(errors.len() == 1 && errors[0].starts_with(&format!("reading the refcount of {tail}")), "{errors:?}");
        let mut corrupt = store();
        corrupt.put(0, &tail, object(&[(XATTR_REFCOUNT, &[2, 1, 99, 0, 0, 0])], &[]));
        let (needed, errors) = refs_errors(scan("rc-corrupt", corrupt, opts, &radoslist, json!([])).await);
        assert!(needed.is_empty());
        assert!(errors.len() == 1 && errors[0].starts_with(&format!("decoding the refcount of {tail}")), "{errors:?}");
    }

    #[tokio::test]
    async fn unread_refcount_is_no_pending_loss() {
        // data/c's tail is queued for GC under its own tag, and a copy's
        // reference keeps it: none queued_for_gc, and none on a failed read
        let tail = format!("{MARKER}__shadow_data/c.2~y_1");
        let head = format!("{MARKER}_data/c");
        let store = || {
            let mut store = MockStore::new(1, 0);
            store.put(0, &head, object(&[(XATTR_IDTAG, b"tagC")], &[]));
            store.put(0, &tail, object(&[(XATTR_REFCOUNT, &refcount(&["", "copy"]))], &[]));
            store
        };
        let gc = || GcIndex { map: [(tail.clone(), vec![("".to_string(), Some(2000))])].into(), entries: 1, taken: 0 };
        let radoslist = [("data/c", head.as_str()), ("data/c", tail.as_str())];
        let run = |name: &'static str, store: MockStore| {
            let radoslist = radoslist;
            let setup = Setup { gc: gc(), ..Setup::default() };
            async move { scan_with(name, store, Options::default(), &radoslist, json!([]), Arc::default(), 0, setup).await.unwrap() }
        };
        let r = run("gc-held", store()).await;
        assert!(r.findings.is_empty() && r.errors.iter().all(|e| !e.contains("refcount")), "{:?} {:?}", keys(&r.findings), r.errors);
        let mut eio = store();
        eio.read_errors.insert((0, tail.clone()), -libc::EIO);
        let r = run("gc-eio", eio).await;
        assert!(r.findings.is_empty(), "{:?}", keys(&r.findings));
        assert!(r.errors.iter().any(|e| e.starts_with(&format!("reading the refcount of {tail}"))), "{:?}", r.errors);
    }

    #[tokio::test]
    async fn radoslist_orphans_need_the_open_uploads() {
        // radoslist leaves out open uploads' parts: when the bucket's uploads,
        // or its stats, cannot be read, the scan cannot serve orphan detection
        let head = format!("{MARKER}_k");
        let store = |index: bool| {
            let mut store = MockStore::new(1, 1);
            store.put(0, &head, object(&[(XATTR_IDTAG, b"t")], &[]));
            if index {
                store.index.insert(("default-placement".into(), ".dir.id1".into()), Vec::new());
            }
            store
        };
        let radoslist = [("k", head.as_str())];
        let run = |name: &'static str, store: MockStore, opts: Options, setup: Setup| {
            let radoslist = radoslist;
            async move { scan_with(name, store, opts, &radoslist, json!([]), Arc::default(), 0, setup).await }
        };
        let orphans = || Setup { partitions: Some(1), ..Setup::default() };
        let r = run("ro-listed", store(true), Options::default(), orphans()).await.unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let err = run("ro-unlisted", store(false), Options::default(), orphans()).await.unwrap_err();
        assert!(format!("{err:#}").contains("index object .dir.id1 of b not found; without its open uploads' parts"), "{err:#}");
        let err = run("ro-no-stats", store(true), Options::default(), Setup { stats: None, ..orphans() }).await.unwrap_err();
        assert!(format!("{err:#}").contains("without its open uploads' parts, orphans cannot be told"), "{err:#}");
        // without orphan detection, an error of the unit's
        let r = run("ro-plain", store(false), Options::default(), Setup::default()).await.unwrap();
        assert_eq!(r.errors, ["index object .dir.id1 of b not found"]);
        let r = run("ro-plain-stats", store(true), Options::default(), Setup { stats: None, ..Setup::default() }).await.unwrap();
        assert!(r.errors.iter().any(|e| e.ends_with("skipping the upload and index checks")), "{:?}", r.errors);
    }

    #[tokio::test]
    async fn prefix_scopes_index_check() {
        // data/x and logs/x are listed with an older ETag than their heads hold
        let mut store = MockStore::new(1, 0);
        let mut bi = Vec::new();
        let mut radoslist = Vec::new();
        for key in ["data/x", "logs/x", "logs/y"] {
            let etag: &[u8] = if key == "logs/y" { b"old" } else { b"new" };
            store.put(0, &format!("{MARKER}_{key}"), object(&[(XATTR_ETAG, etag)], &[]));
            radoslist.push((key, format!("{MARKER}_{key}")));
            bi.push(json!({ "type": "plain", "entry": { "name": key, "instance": "", "exists": true, "meta": { "etag": "old" } } }));
        }
        let radoslist: Vec<(&str, &str)> = radoslist.iter().map(|(k, o)| (*k, o.as_str())).collect();
        let opts = Options { check_index: true, ..Options::default() };
        let run = |name: &'static str, opts: Options| {
            let (store, radoslist, bi) = (MockStore { objects: store.objects.clone(), ..MockStore::new(1, 0) }, radoslist.clone(), json!(bi));
            async move { keys(&scan(name, store, opts, &radoslist, bi).await.findings) }
        };
        let full = run("index-full", opts.clone()).await;
        let stale = |k: &str| ("stale_entry".to_string(), k.to_string());
        assert_eq!(full, vec![stale("data/x"), stale("logs/x")]);
        assert_scoped(&full, &run("index-logs", prefixed(&opts)).await);
    }

    /// A directory removed when the test is done with it.
    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn engine(store: MockStore, admin: Admin, listing: Listing) -> Arc<Engine> {
        Arc::new(Engine {
            store: Arc::new(store),
            admin: Arc::new(admin),
            ctx: Arc::new(Context { catalog: crate::finding::Catalog::builtin(), ..Default::default() }),
            gc: RwLock::default(),
            gc_min_wait: 7200,
            limiter: Limiter::new(8),
            opts: Options { uploads: false, listing, ..Default::default() },
            partitions: None,
            segments: Default::default(),
        })
    }

    /// `bi list --object`'s JSON of the entries of a name
    fn bi(entries: &[(&str, &str, u64)]) -> String {
        let v: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, instance, flags)| {
                json!({ "type": "plain", "idx": name, "entry": {
                    "name": name, "instance": instance, "exists": true, "flags": flags, "pending_map": [], "tag": "T",
                    "meta": { "etag": "E", "mtime": "2020-01-01T00:00:00.000000Z" },
                } })
            })
            .collect();
        serde_json::to_string(&v).unwrap()
    }

    fn bi_list(object: &str) -> String {
        format!("bi list --bucket=b --object={object}")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn radoslist_misses() {
        let lines = [
            ("M_gone.txt", "gone.txt"),
            ("M__:DM_k", "k[DM]"),
            ("M_report[2024]", "report[2024]"),
            ("M_ver", "ver"),
            ("M____foo", "__foo"),
            ("M_del", "del"),
            ("M_err.txt", "err.txt"),
            ("M_ok", "ok"),
        ];
        let radoslist: Vec<u8> = lines.iter().flat_map(|(oid, key)| record(oid, "b", key)).collect();
        let mut olh: Vec<serde_json::Value> = serde_json::from_str(&bi(&[("ver", "", 8), ("ver", "V1", 1)])).unwrap();
        olh.push(json!({ "type": "olh", "idx": "ver", "entry": { "key": { "name": "ver", "instance": "V1" }, "epoch": 2 } }));
        let (admin, _dir) = fake_admin(&[
            ("bucket radoslist --rgw-obj-fs=* --bucket=b", radoslist),
            (&bi_list("gone.txt"), bi(&[("gone.txt", "", 0)]).into()),
            // a delete marker's head does not exist
            (&bi_list("k"), bi(&[("k", "", 8), ("k", "DM", 7)]).into()),
            // not a version: the key ends in brackets
            (&bi_list("report"), bi(&[]).into()),
            (&bi_list("report[2024]"), bi(&[("report[2024]", "", 0)]).into()),
            (&bi_list("ver"), serde_json::to_vec(&olh).unwrap()),
            // the OLH of versioned "_foo", named from its index name "__foo"
            (&bi_list("___foo"), bi(&[]).into()),
            (&bi_list("__foo"), bi(&[("__foo", "", 8), ("__foo", "V2", 1)]).into()),
            (&bi_list("del"), bi(&[]).into()),
        ]);
        let mut store = MockStore::new(1, 0);
        store.put(0, "M_ok", MockObject::default());
        let e = engine(store, admin, Listing::Radoslist);
        let stats: BucketStats = serde_json::from_value(json!({ "bucket": "b", "id": "ID", "marker": "M" })).unwrap();
        let r = e.scan_bucket("b", Some(stats)).await.unwrap();

        let mut missing = r.missing.clone();
        missing.sort();
        assert_eq!(
            missing,
            [
                "s3://b/del MISSING M_del",
                "s3://b/err.txt MISSING M_err.txt",
                "s3://b/gone.txt MISSING M_gone.txt",
                "s3://b/report[2024] MISSING M_report[2024]",
                "s3://b/ver MISSING M_ver"
            ]
        );
        assert_eq!(r.gaps, 5);
        let mut found: Vec<(&str, &str)> = r.findings.iter().map(|f| (f.check.as_str(), f.key.as_deref().unwrap_or(""))).collect();
        found.sort();
        assert_eq!(found, [("listed_without_head", "gone.txt"), ("listed_without_head", "report[2024]")]);
        let skipped: Vec<(&str, u64)> = r.tally.skipped.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(skipped, [("a versioned key's OLH", 1), ("delete marker", 1), ("not in the index", 1), ("radoslist's misnamed OLH", 1)]);
        // a failed lookup is an error, not a key deleted during the scan
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].contains("s3://b/err.txt"), "{:?}", r.errors);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_olh() {
        let fresh = iso(now());
        // a versioned key: its placeholder, a version and its OLH entry
        let key = |name: &str, flags: u64, mtime: &str, olh: serde_json::Value| {
            let mut v: Vec<serde_json::Value> = serde_json::from_str(&bi(&[(name, "", 8), (name, "V1", flags)])).unwrap();
            v[1]["entry"]["meta"]["mtime"] = json!(mtime);
            let mut entry = json!({
                "key": { "name": name, "instance": "V1" }, "delete_marker": false, "epoch": 2, "epoch_timestamp": "0.000002",
                "pending_log": [], "tag": "OT", "exists": true, "pending_removal": false,
            });
            entry.as_object_mut().unwrap().extend(olh.as_object().unwrap().clone());
            v.push(json!({ "type": "olh", "idx": name, "entry": entry }));
            (bi_list(name), serde_json::to_vec(&v).unwrap())
        };
        let old = "2020-01-01T00:00:00.000000Z";
        let log = json!([{ "key": 3, "val": [{ "epoch": 3, "op": "link_olh", "op_tag": "X", "key": { "name": "logged", "instance": "V1" } }] }]);
        let keys = [
            ("live", key("live", 3, old, json!({}))),
            // the last version's unlink: the OLH object is being removed
            ("removing", key("removing", 1, old, json!({ "exists": false, "pending_removal": true }))),
            // a link not yet applied to the OLH object
            ("logged", key("logged", 3, old, json!({ "pending_log": log }))),
            ("dm", key("dm", 7, old, json!({ "delete_marker": true }))),
            ("recent", key("recent", 3, &fresh, json!({}))),
            // an epoch that is a time ( from 21 on ) dates the OLH
            ("relinked", key("relinked", 3, old, json!({ "epoch": now() as u64 * 1_000_000_000, "epoch_timestamp": fresh }))),
        ];
        let radoslist: Vec<u8> = keys.iter().flat_map(|(k, _)| record(&format!("M_{k}"), "b", k)).collect();
        let mut answers = vec![("bucket radoslist --rgw-obj-fs=* --bucket=b".to_string(), radoslist)];
        answers.extend(keys.into_iter().map(|(_, a)| a));
        let answers: Vec<(&str, Vec<u8>)> = answers.iter().map(|(a, o)| (a.as_str(), o.clone())).collect();
        let (admin, _dir) = fake_admin(&answers);
        let e = engine(MockStore::new(1, 0), admin, Listing::Radoslist);
        let stats: BucketStats = serde_json::from_value(json!({ "bucket": "b", "id": "ID", "marker": "M" })).unwrap();
        let r = e.scan_bucket("b", Some(stats)).await.unwrap();

        assert_eq!(r.missing.len(), 6, "{:?}", r.missing);
        assert_eq!(r.gaps, 6);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let found: Vec<(&str, &str)> = r.findings.iter().map(|f| (f.check.as_str(), f.key.as_deref().unwrap_or(""))).collect();
        assert_eq!(found, [("olh_missing", "live")]);
        let f = &r.findings[0];
        assert_eq!(f.oids, ["M_live"]);
        assert_eq!((&f.evidence["current_instance"], &f.evidence["current_listed"]), (&json!("V1"), &json!(true)));
        assert!(f.hint.as_deref().is_some_and(|h| h.contains("404")), "{:?}", f.hint);
        let skipped: Vec<(&str, u64)> = r.tally.skipped.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(skipped, [("delete marker", 1), ("index op in flight", 2), ("younger than the grace period", 2)]);
    }

    #[tokio::test]
    async fn native_miss_reads_the_entry_again() {
        let listed = |name: &str| DirEntry { name: name.into(), exists: true, mtime: 1577836800, etag: "E".into(), ..Default::default() };
        let mut store = MockStore::new(1, 0);
        // old.txt was deleted after the listing read its entry, busy.txt is being written
        let busy = DirEntry { pending: 1, ..listed("busy.txt") };
        store.shards.insert(".dir.ID.0".into(), vec![listed("kept.txt"), busy, listed("other.txt")]);
        let e = engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native);
        let bucket = Bucket {
            name: "b".into(),
            stats: Some(serde_json::from_value(json!({ "bucket": "b", "id": "ID", "marker": "M" })).unwrap()),
            marker: "M".into(),
            start: now(),
            shard: None,
            uploads: HashMap::new(),
            named: Mutex::default(),
            lc_mp: OnceCell::new(),
            out: Mutex::default(),
            rados_objects: Arc::default(),
            gaps: Arc::default(),
        };
        // flaky.txt's shard cannot be read
        for (key, shard) in [("old.txt", ".dir.ID.0"), ("kept.txt", ".dir.ID.0"), ("busy.txt", ".dir.ID.0"), ("flaky.txt", ".dir.ID.1")] {
            let mut g = Group::new("b".into(), key.into());
            g.entry = Some(listed(key));
            g.shard = Some(shard.into());
            g.oids.push(format!("M_{key}"));
            e.process_group(&bucket, g).await;
        }
        let out = bucket.out.into_inner().unwrap();
        assert_eq!(out.missing, ["s3://b/kept.txt MISSING M_kept.txt", "s3://b/busy.txt MISSING M_busy.txt", "s3://b/flaky.txt MISSING M_flaky.txt"]);
        assert_eq!(out.gaps, 3);
        let found: Vec<&str> = out.findings.iter().map(|f| f.key.as_deref().unwrap_or("")).collect();
        // a failed read judges by the listing's entry
        assert_eq!(found, ["kept.txt", "flaky.txt"]);
        assert_eq!(out.tally.skipped.get("deleted during the scan"), Some(&1));
        assert_eq!(out.tally.skipped.get("index op in flight"), Some(&1));
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert!(out.errors[0].contains("s3://b/flaky.txt"), "{:?}", out.errors);
    }

    #[tokio::test]
    async fn bracketed_keys() {
        let index: HashMap<&str, Vec<IndexEntry>> = [
            ("x", vec![IndexEntry { kind: "plain".into(), name: "x".into(), ..Default::default() }]),
            ("f", vec![IndexEntry { kind: "plain".into(), name: "f".into(), instance: "v2".into(), ..Default::default() }]),
        ]
        .into();
        let lookup = |name: String| {
            let entries = index.get(name.as_str()).cloned().unwrap_or_default();
            async move { Ok(entries) }
        };
        // "x[]" is no version of "x"
        assert!(matches!(indexed("x[]", lookup).await.unwrap(), Indexed::Gone));
        assert!(matches!(indexed("f[v2]", lookup).await.unwrap(), Indexed::Entry(e) if e.instance == "v2"));
        let failing = |_: String| async { anyhow::bail!("bi list failed") };
        assert!(indexed("f[v2]", failing).await.is_err());
    }

    #[tokio::test]
    async fn gaps_are_counted_as_they_are_found() {
        // k's head is there, one of its two tail objects is not
        let mut store = MockStore::new(1, 0);
        let (head, tail, lost) = (format!("{MARKER}_k"), format!("{MARKER}__shadow_k.2~x_1"), format!("{MARKER}__shadow_k.2~x_2"));
        store.put(0, &head, object(&[(XATTR_IDTAG, b"t")], &[]));
        store.put(0, &tail, object(&[], &[]));
        let radoslist = [("k", head.as_str()), ("k", tail.as_str()), ("k", lost.as_str())];
        let gaps = Arc::new(AtomicU64::new(0));
        let r = scan_counting("gaps-live", store, Options::default(), &radoslist, json!([]), gaps.clone()).await;
        assert_eq!(r.missing, vec![format!("s3://b/k MISSING {lost}")]);
        assert_eq!((r.gaps, gaps.load(Ordering::Relaxed)), (1, 1));
    }

    #[test]
    fn ledger() {
        let ctx = Context { catalog: crate::finding::Catalog::builtin(), ..Default::default() };
        let mut a = RefLedger::default();
        a.needed.insert("o1".into(), ("b".into(), ["copy".to_string()].into()));
        a.needed.insert("o2".into(), ("b".into(), ["lost".to_string()].into()));
        a.carried.insert("o1".into(), ["src".to_string()].into());
        let mut b = RefLedger::default();
        b.carried.insert("o1".into(), ["copy".to_string()].into());
        a.merge(b);
        let found = a.resolve(&ctx);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].oids, vec!["o2".to_string()]);
        assert_eq!(found[0].causes[0].cause, "lost-copy");
    }

    #[tokio::test]
    async fn radoslist_fallback_is_no_error() {
        // `bucket stats` fails, so the native listing falls back to radoslist:
        // one error, the failed stats, and the fallback only a note
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-scan-{}-fallback", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("radosgw-admin");
        let script = format!("#!/bin/sh\ncase \"$1 $2\" in\n\"bucket radoslist\") printf '{MARKER}_k\\377b\\377k\\n' ;;\n*) exit 1 ;;\nesac\n");
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut store = MockStore::new(1, 0);
        store.put(0, &format!("{MARKER}_k"), object(&[], &[]));
        let engine = Arc::new(Engine {
            store: Arc::new(store),
            admin: Arc::new(Admin::new(program.display().to_string(), None, None, crate::admin::DEFAULT_CONCURRENCY)),
            ctx: Arc::new(Context { catalog: crate::finding::Catalog::builtin(), ..Default::default() }),
            gc: RwLock::default(),
            gc_min_wait: 7200,
            limiter: Limiter::new(64),
            opts: Options::default(),
            partitions: None,
            segments: Default::default(),
        });
        let report = engine.scan_bucket("b", None).await.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(report.rados_objects, 1, "listed with radoslist");
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert!(report.errors[0].contains("bucket stats"), "{:?}", report.errors);
        assert_eq!(report.tally.skipped.get("native listing, for want of bucket stats"), Some(&1));
    }

    /// An open upload under the prefix whose parts lack index entries, and
    /// whose object was copied outside the prefix: the copy names it, so a
    /// listing limited to the prefix reads the heads outside it before
    /// reporting the upload as one no head names.
    #[tokio::test]
    async fn finalize_reads_heads_outside_prefix() {
        use crate::decode::enc::{dir_entry_of, multipart_manifest};
        let stats: BucketStats = serde_json::from_value(json!({ "bucket": "b", "id": "B.1", "marker": "M.1" })).unwrap();
        let good = || multipart_manifest("M.1", "other", "logs/k.2~U", 2);
        let run = |prefix: Option<&str>, copy: Option<Vec<u8>>| {
            let mut store = MockStore::new(1, 1);
            let meta = "_multipart_logs/k.2~U.meta";
            let omap: BTreeMap<Vec<u8>, Vec<u8>> = [("other", dir_entry_of("other", "", 0)), (meta, dir_entry_of(meta, "", 0))]
                .into_iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v))
                .collect();
            store.bi = crate::native::shard_objects(&stats, None).into_iter().map(|o| (o, omap.clone())).collect();
            store.put(1, &format!("M.1_{meta}"), MockObject { mtime: 1000, omap: vec!["part.1".into(), "part.2".into()], ..Default::default() });
            if let Some(manifest) = copy {
                store.put(0, "M.1_other", MockObject { xattrs: [(crate::native::XATTR_MANIFEST.to_string(), manifest)].into(), ..Default::default() });
            }
            let engine = Engine {
                store: Arc::new(store),
                admin: Arc::new(Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY)),
                ctx: Arc::new(Context { catalog: crate::finding::Catalog::builtin(), ..Default::default() }),
                gc: RwLock::default(),
                gc_min_wait: 0,
                limiter: Limiter::new(8),
                opts: Options { match_prefix: prefix.map(str::to_string), ..Default::default() },
                partitions: None,
                segments: Default::default(),
            };
            let upload = Upload { key: "logs/k".into(), meta: true, parts: [1].into() };
            let bucket = Bucket {
                name: "b".into(),
                stats: Some(stats.clone()),
                marker: "M.1".into(),
                start: now(),
                shard: None,
                uploads: [("2~U".to_string(), upload)].into(),
                named: Mutex::default(),
                lc_mp: OnceCell::new(),
                out: Mutex::default(),
                rados_objects: Arc::default(),
                gaps: Arc::default(),
            };
            async move {
                engine.finalize_uploads(&bucket, true).await;
                let out = bucket.out.into_inner().unwrap();
                (out.findings.iter().map(|f| f.check.clone()).collect::<Vec<_>>(), out.errors)
            }
        };
        let none: Vec<String> = Vec::new();
        assert_eq!(run(Some("logs/"), None).await, (vec!["part_entries_missing".to_string()], none.clone()));
        assert_eq!(run(Some("logs/"), Some(good())).await, (vec![], none.clone()));
        // a full listing: the heads the scan listed are all there are
        assert_eq!(run(None, Some(good())).await, (vec!["part_entries_missing".to_string()], none));
        // a head outside the prefix whose manifest does not decode may name the upload: the unit is not complete
        let (found, errors) = run(Some("logs/"), Some(b"junk".to_vec())).await;
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(found.is_empty(), "not judged: {found:?}");
        assert!(errors[0].contains("the manifest of M.1_other does not decode"), "{errors:?}");
    }

    /// Under a prefix too, every open upload: a copy under it names the
    /// upload of its source outside it.
    #[tokio::test]
    async fn open_uploads_outside_prefix() {
        let stats: BucketStats = serde_json::from_value(json!({ "bucket": "b", "id": "B.1", "marker": "M.1" })).unwrap();
        let mut store = MockStore::new(1, 1);
        let keys = ["logs/a", "_multipart_logs/a.2~U.meta", "_multipart_other/y.2~V.meta", "_multipart_other/y.2~V.1"];
        for oid in crate::native::shard_objects(&stats, None) {
            store.index.insert((stats.placement(), oid), keys.iter().map(|k| k.to_string()).collect());
        }
        let e = engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native);
        let mut e = Arc::try_unwrap(e).ok().expect("unshared");
        e.opts.match_prefix = Some("logs/".into());
        let uploads = e.list_open_uploads(&stats, None).await.unwrap();
        let mut got: Vec<(&str, &str, bool)> = uploads.iter().map(|(id, u)| (id.as_str(), u.key.as_str(), u.meta)).collect();
        got.sort();
        assert_eq!(got, [("2~U", "logs/a", true), ("2~V", "other/y", true)]);
    }

    /// Bucket b ( id ID, marker M ), as a native scan of it begins.
    fn native_bucket() -> Bucket {
        Bucket {
            name: "b".into(),
            stats: Some(serde_json::from_value(json!({ "bucket": "b", "id": "ID", "marker": "M" })).unwrap()),
            marker: "M".into(),
            start: now(),
            shard: None,
            uploads: HashMap::new(),
            named: Mutex::default(),
            lc_mp: OnceCell::new(),
            out: Mutex::default(),
            rados_objects: Arc::default(),
            gaps: Arc::default(),
        }
    }

    /// The manifest of a 10 MiB PUT of `key` in bucket marker M: a 4 MiB
    /// head, then M__shadow_.<key>_1 and M__shadow_.<key>_2.
    fn manifest(key: &str) -> Vec<u8> {
        use crate::decode::{Bucket as B, Key, Manifest, Obj, Rule};
        const MB: u64 = 1 << 20;
        let bucket = B { tenant: String::new(), name: "b".into(), marker: "M".into(), bucket_id: "ID".into() };
        let obj = Obj { bucket: bucket.clone(), key: Key { name: key.into(), instance: String::new(), ns: String::new() } };
        let mut m = Manifest { obj_size: 10 * MB, obj, head_size: 4 * MB, max_head_size: 4 * MB, prefix: format!(".{key}_"), tail_bucket: bucket, ..Default::default() };
        m.rules.insert(0, Rule { start_ofs: 4 * MB, stripe_max_size: 4 * MB, ..Default::default() });
        crate::decode::enc::manifest(&m)
    }

    #[tokio::test]
    async fn native_head_errors() {
        // ok's second stripe is missing, and so is big's, whose head cannot be statted
        let listed = |name: &str| DirEntry { name: name.into(), exists: true, mtime: 1577836800, etag: "E".into(), ..Default::default() };
        let mut store = MockStore::new(1, 0);
        store.shards.insert(".dir.ID".into(), vec![listed("big"), listed("ok")]);
        for key in ["big", "ok"] {
            store.put(0, &format!("M_{key}"), object(&[(crate::native::XATTR_MANIFEST, &manifest(key))], &[]));
            store.put(0, &format!("M__shadow_.{key}_1"), object(&[], &[]));
        }
        store.fail(0, "M_big", -libc::EIO);
        let stats: BucketStats = serde_json::from_value(json!({ "bucket": "b", "id": "ID", "marker": "M" })).unwrap();
        let objects = store.objects.clone();
        let e = engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native);

        let mut rx = e.native_seeds(stats.clone(), None);
        let mut seeds = Vec::new();
        while let Some(seed) = rx.recv().await {
            seeds.push(seed.unwrap());
        }
        seeds.sort_by(|a, b| a.key.cmp(&b.key));
        // big's tail is unknown: an error, not an object of one head
        assert_eq!(seeds[0].oids, ["M_big"]);
        assert!(seeds[0].error.as_deref().is_some_and(|e| e.contains("stat of the head M_big")), "{:?}", seeds[0].error);
        assert_eq!(seeds[1].oids, ["M_ok", "M__shadow_.ok_1", "M__shadow_.ok_2"]);
        assert!(seeds[1].error.is_none());

        let r = e.scan_bucket("b", Some(stats.clone())).await.unwrap();
        assert_eq!(r.missing, ["s3://b/ok MISSING M__shadow_.ok_2"]);
        assert_eq!(r.gaps, 1);
        assert_eq!(keys(&r.findings), [("missing_data".to_string(), "ok".to_string())]);
        assert!(r.errors.iter().any(|e| e.contains("stat of the head M_big")), "{:?}", r.errors);

        // orphan detection cannot do without big's references
        let mut store = MockStore::new(1, 0);
        store.objects = objects;
        store.shards.insert(".dir.ID".into(), vec![listed("big"), listed("ok")]);
        store.fail(0, "M_big", -libc::EIO);
        let mut e = Arc::into_inner(engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native)).unwrap();
        e.partitions = Some(1);
        let err = Arc::new(e).scan_bucket("b", Some(stats)).await.unwrap_err();
        assert!(format!("{err:#}").contains("stat of the head M_big"), "{err:#}");
    }

    #[tokio::test]
    async fn stat_errors_are_no_gaps() {
        let mut store = MockStore::new(2, 0);
        let mut radoslist = Vec::new();
        for key in ["eio", "gone", "split", "unread"] {
            store.put(0, &format!("{MARKER}_{key}"), object(&[(XATTR_IDTAG, b"t")], &[]));
            radoslist.push((key, format!("{MARKER}_{key}")));
            radoslist.push((key, format!("{MARKER}__shadow_{key}.x_1")));
        }
        // eio's tail cannot be statted; gone's is in no pool; split's is not
        // in the first pool, and the second cannot be read
        store.fail(0, &format!("{MARKER}__shadow_eio.x_1"), -libc::EIO);
        store.fail(1, &format!("{MARKER}__shadow_split.x_1"), -libc::ETIMEDOUT);
        // unread's tail is missing, and its head's xattrs cannot be read
        store.read_errors.insert((0, format!("{MARKER}_unread")), -libc::EIO);
        let radoslist: Vec<(&str, &str)> = radoslist.iter().map(|(k, o)| (*k, o.as_str())).collect();
        let r = scan("stat-errors", store, Options { uploads: false, ..Options::default() }, &radoslist, json!([])).await;

        let mut missing = r.missing.clone();
        missing.sort();
        // unread's gap stands, unjudged
        assert_eq!(missing, [format!("s3://b/gone MISSING {MARKER}__shadow_gone.x_1"), format!("s3://b/unread MISSING {MARKER}__shadow_unread.x_1")]);
        assert_eq!(r.gaps, 2);
        assert_eq!(keys(&r.findings), [("missing_data".to_string(), "gone".to_string())]);
        let mut errors = r.errors.clone();
        errors.sort();
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors[0].starts_with(&format!("reading {XATTR_IDTAG} of the head {MARKER}_unread")), "{errors:?}");
        assert!(errors[1].starts_with(&format!("stat of {MARKER}__shadow_eio.x_1: ")), "{errors:?}");
        assert!(errors[2].starts_with(&format!("stat of {MARKER}__shadow_split.x_1: ")), "{errors:?}");
    }

    #[tokio::test]
    async fn unreadable_head_keeps_the_gap() {
        // the listing found k's head; its tail is missing, and the head cannot be statted again
        let mut store = MockStore::new(1, 0);
        store.put(0, "M_k", object(&[(XATTR_IDTAG, b"t")], &[]));
        store.fail(0, "M_k", -libc::EIO);
        let e = engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native);
        let bucket = native_bucket();
        let mut g = Group::new("b".into(), "k".into());
        g.entry = Some(DirEntry { name: "k".into(), exists: true, mtime: 1577836800, etag: "E".into(), ..Default::default() });
        g.shard = Some(".dir.ID".into());
        g.oids = vec!["M_k".into(), "M__shadow_.k_1".into()];
        g.present = vec![("M_k".into(), PoolId(0))];
        e.process_group(&bucket, g).await;
        let out = bucket.out.into_inner().unwrap();
        assert_eq!(out.missing, ["s3://b/k MISSING M__shadow_.k_1"]);
        assert_eq!(out.gaps, 1);
        assert!(out.findings.is_empty());
        assert!(out.tally.skipped.is_empty(), "{:?}", out.tally.skipped);
        assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
        assert!(out.errors[0].starts_with("stat of the head M_k: "), "{:?}", out.errors);
    }

    #[tokio::test]
    async fn unreadable_meta_is_no_closed_upload() {
        // two open uploads whose meta objects list a part the index does not
        // hold; U2's meta object cannot be statted
        let mut store = MockStore::new(1, 1);
        let mut index = Vec::new();
        for upload in ["U1", "U2"] {
            store.put(1, &format!("{MARKER}__multipart_k.{upload}.meta"), object(&[], &["part.1"]));
            index.push(format!("_multipart_k.{upload}.meta"));
        }
        store.fail(1, &format!("{MARKER}__multipart_k.U2.meta"), -libc::EIO);
        store.index.insert(("default-placement".into(), ".dir.id1".into()), index);
        let r = scan("meta-errors", store, Options::default(), &[], json!([])).await;
        assert_eq!(keys(&r.findings), [("part_entries_missing".to_string(), "k".to_string())]);
        assert_eq!(r.findings[0].upload_id.as_deref(), Some("U1"));
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].starts_with(&format!("stat of {MARKER}__multipart_k.U2.meta: ")), "{:?}", r.errors);
    }

    /// A record of radoslist --rgw-obj-fs, its fields between 0xff bytes.
    fn record(oid: &str, bucket: &str, key: &str) -> Vec<u8> {
        [oid.as_bytes(), bucket.as_bytes(), key.as_bytes()].join(&0xff).into_iter().chain(*b"\n").collect()
    }

    /// A radosgw-admin that prints the answer to each command line it is
    /// given ( a `*` in it matches anything, as radoslist's separator ), and
    /// fails any other; a shell script in a directory of its own.
    #[cfg(unix)]
    fn fake_admin<A: AsRef<[u8]>>(answers: &[(&str, A)]) -> (Admin, TempDir) {
        fake_admin_exiting(answers, 1)
    }

    /// The same, failing any other command with exit status `code`, as
    /// radosgw-admin exits with ENOENT ( 2 ) for a bucket that does not exist.
    #[cfg(unix)]
    fn fake_admin_exiting<A: AsRef<[u8]>>(answers: &[(&str, A)], code: i32) -> (Admin, TempDir) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-admin-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut script = String::from("#!/bin/sh\ncase \"$*\" in\n");
        for (i, (args, out)) in answers.iter().enumerate() {
            let file = dir.join(i.to_string());
            std::fs::write(&file, out).unwrap();
            script.push_str(&format!("'{}') cat '{}' ;;\n", args.replace('*', "'*'"), file.display()));
        }
        script.push_str(&format!("*) echo \"no answer to $*\" >&2; exit {code} ;;\nesac\n"));
        let program = dir.join("radosgw-admin");
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        (Admin::new(program.display().to_string(), None, None, crate::admin::DEFAULT_CONCURRENCY), TempDir(dir))
    }

    /// A tenant's bucket, listed with radoslist: its records name it without
    /// the tenant, a copied object's tail carries its source's marker, and a
    /// Swift manifest's segment is in another bucket of the tenant.
    #[cfg(unix)]
    #[tokio::test]
    async fn radoslist_tenant_bucket() {
        let radoslist: Vec<u8> = [("M_k", "tb", "k"), ("SRC__shadow_.x_1", "tb", "k"), ("S_seg", "segs", "seg")]
            .iter()
            .flat_map(|(oid, b, key)| record(oid, b, key))
            .collect();
        let (admin, _dir) = fake_admin(&[
            ("bucket radoslist --rgw-obj-fs=* --tenant=t1 --uid=rgw-integrity --bucket=tb", radoslist),
            // the segment's entry is in its own bucket
            ("bi list --bucket=t1/segs --object=seg", bi(&[("seg", "", 0)]).into()),
        ]);
        let mut store = MockStore::new(1, 0);
        store.put(0, "M_k", MockObject::default());
        let e = engine(store, admin, Listing::Radoslist);
        let stats: BucketStats = serde_json::from_value(json!({ "bucket": "tb", "tenant": "t1", "id": "ID", "marker": "M" })).unwrap();
        let r = e.scan_bucket("t1/tb", Some(stats)).await.unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let mut missing = r.missing.clone();
        missing.sort();
        assert_eq!(missing, ["s3://t1/segs/seg MISSING S_seg", "s3://t1/tb/k MISSING SRC__shadow_.x_1"]);
        let mut found: Vec<(&str, &str, &str)> = r.findings.iter().map(|f| (f.check.as_str(), f.bucket.as_str(), f.key.as_deref().unwrap_or(""))).collect();
        found.sort();
        assert_eq!(found, [("listed_without_head", "t1/segs", "seg"), ("missing_data", "t1/tb", "k")]);
    }

    #[tokio::test]
    async fn index_check_unescapes() {
        // bi list names keys starting with '_' as the index holds them, escaped
        let mut store = MockStore::new(1, 0);
        store.put(0, &format!("{MARKER}___foo"), object(&[(XATTR_ETAG, b"new")], &[]));
        store.put(0, &format!("{MARKER}__:v1__bar"), object(&[(XATTR_ETAG, b"new")], &[]));
        let entry = |kind: &str, name: &str, instance: &str| {
            json!({ "type": kind, "entry": { "name": name, "instance": instance, "exists": true, "meta": { "etag": "old" } } })
        };
        let bi = json!([entry("plain", "__foo", ""), entry("instance", "__bar", "v1")]);
        let radoslist = [("_foo", format!("{MARKER}___foo")), ("_bar[v1]", format!("{MARKER}__:v1__bar"))];
        let radoslist: Vec<(&str, &str)> = radoslist.iter().map(|(k, o)| (*k, o.as_str())).collect();
        let opts = Options { check_index: true, ..Options::default() };
        let run = |name: &'static str, opts: Options| {
            let (store, radoslist, bi) = (MockStore { objects: store.objects.clone(), ..MockStore::new(1, 0) }, radoslist.clone(), bi.clone());
            async move { keys(&scan(name, store, opts, &radoslist, bi).await.findings) }
        };
        let stale = |k: &str| ("stale_entry".to_string(), k.to_string());
        assert_eq!(run("unescape-full", opts.clone()).await, [stale("_bar[v1]"), stale("_foo")]);
        let foo = Options { match_prefix: Some("_f".into()), ..opts };
        assert_eq!(run("unescape-foo", foo).await, [stale("_foo")]);
    }

    /// An index entry of an object written long ago.
    fn old_entry(name: &str) -> DirEntry {
        DirEntry { name: name.into(), exists: true, mtime: 1577836800, etag: "E".into(), ..Default::default() }
    }

    fn stats_of(v: serde_json::Value) -> BucketStats {
        serde_json::from_value(v).unwrap()
    }

    /// The head of an SLO of segments at these paths.
    fn slo_head(paths: &[&str]) -> MockObject {
        object(&[(crate::native::XATTR_SLO_MANIFEST, &crate::decode::enc::slo_info(paths))], &[])
    }

    /// The same engine, changed.
    fn changed(e: Arc<Engine>, change: impl FnOnce(&mut Engine)) -> Arc<Engine> {
        let mut e = Arc::into_inner(e).expect("unshared");
        change(&mut e);
        Arc::new(e)
    }

    /// Every seed a native listing sends.
    async fn listed(e: &Arc<Engine>, stats: BucketStats, shard: Option<u32>) -> Vec<crate::native::Seed> {
        let mut rx = e.native_seeds(stats, shard);
        let mut seeds = Vec::new();
        while let Some(seed) = rx.recv().await {
            seeds.push(seed.expect("listing"));
        }
        seeds
    }

    /// The keys of the seeds in a bucket, sorted.
    fn keys_in(seeds: &[crate::native::Seed], bucket: &str) -> Vec<String> {
        let mut k: Vec<String> = seeds.iter().filter(|s| s.bucket == bucket && !s.oids.is_empty()).map(|s| s.key.clone()).collect();
        k.sort();
        k
    }

    /// Findings as ( check, bucket, key ).
    fn found(r: &BucketReport) -> Vec<(String, String, String)> {
        let mut f: Vec<_> = r.findings.iter().map(|f| (f.check.clone(), f.bucket.clone(), f.key.clone().unwrap_or_default())).collect();
        f.sort();
        f
    }

    /// Bucket m ( IDM, marker MM ): big, an SLO of segments in segs ( IDS,
    /// marker MS, three shards in placement segs-placement ) at paths as a
    /// GET reads them, s1, s2 and dir/s3; s2's head is missing.  Near them in
    /// segs's shards, s, s10 and s1x.  bi_list pages of one entry.
    fn slo_store() -> MockStore {
        let mut store = MockStore::new(1, 0);
        store.bi_max = 1;
        store.shards.insert(".dir.IDM".into(), vec![old_entry("big")]);
        store.put(0, "MM_big", slo_head(&["/segs/s1", "segs/s2", "//segs/dir/s3"]));
        for shard in 0..3 {
            let oid = format!(".dir.IDS.{shard}");
            store.shards.insert(oid.clone(), Vec::new());
            store.placements.insert(oid, "segs-placement".into());
        }
        let mut keys = vec!["s", "s1", "s10", "s1x", "s2", "dir/s3"];
        keys.sort();
        for key in keys {
            store.shards.get_mut(&format!(".dir.IDS.{}", crate::native::shard_of(key, 3))).unwrap().push(old_entry(key));
            if key != "s2" {
                store.put(0, &format!("MS_{key}"), object(&[], &[]));
            }
        }
        store
    }

    fn segs_stats() -> String {
        json!({ "bucket": "segs", "id": "IDS", "marker": "MS", "num_shards": 3, "placement_rule": "segs-placement" }).to_string()
    }

    /// An SLO's segments are looked up in the shards their keys hash to, in
    /// their bucket's placement, a key at a time ( the keys near them are
    /// not theirs ), and a missing head is a gap and a finding of that bucket.
    #[cfg(unix)]
    #[tokio::test]
    async fn slo_segments_are_followed() {
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
        let e = engine(slo_store(), admin, Listing::Native);
        let seeds = listed(&e, m.clone(), None).await;
        assert_eq!(keys_in(&seeds, "segs"), ["dir/s3", "s1", "s2"]);
        assert!(seeds.iter().filter(|s| s.bucket == "segs").all(|s| s.followed.as_deref() == Some("segs-placement")), "{seeds:?}");
        let r = e.scan_bucket("m", Some(m.clone())).await.unwrap();
        // the entry read again in segs's placement, not m's
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.missing, ["s3://segs/s2 MISSING MS_s2"]);
        assert_eq!((r.gaps, r.rados_objects), (1, 4));
        assert_eq!(found(&r), [("listed_without_head".to_string(), "segs".to_string(), "s2".to_string())]);

        // a scan that lists segs too checks them there; so does one of every
        // bucket, but for the keys outside its prefix
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
        let e = engine(slo_store(), admin, Listing::Native);
        e.segments.lists_too(["m".to_string(), "segs".to_string()]);
        assert_eq!(keys_in(&listed(&e, m.clone(), None).await, "segs"), Vec::<String>::new());
        let every = |prefix: Option<&str>| {
            let (admin, dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
            let opts = Options { uploads: false, every_bucket: true, match_prefix: prefix.map(str::to_string), ..Options::default() };
            (changed(engine(slo_store(), admin, Listing::Native), |e| e.opts = opts), dir)
        };
        let (e, _dir) = every(None);
        assert_eq!(keys_in(&listed(&e, m.clone(), None).await, "segs"), Vec::<String>::new());
        let (e, _dir) = every(Some("b"));
        assert_eq!(keys_in(&listed(&e, m, None).await, "segs"), ["dir/s3", "s1", "s2"]);
    }

    /// What a bucket's units rely on other buckets for, as --state records
    /// it: segments followed into a bucket the scan does not list, or left
    /// to one it does, which alone reports their lines.
    #[cfg(unix)]
    #[tokio::test]
    async fn segment_buckets_are_noted() {
        use crate::native::Depends;
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
        let e = engine(slo_store(), admin, Listing::Native);
        e.segments.lists_too(["m".to_string()]);
        assert_eq!(e.scan_bucket("m", Some(m.clone())).await.unwrap().missing, ["s3://segs/s2 MISSING MS_s2"]);
        assert_eq!(e.segments.depends("m"), Depends { left_to: BTreeSet::new(), followed: true });
        assert_eq!(e.segments.depends("segs"), Depends::default());
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
        let e = engine(slo_store(), admin, Listing::Native);
        e.segments.lists_too(["m".to_string(), "segs".to_string()]);
        assert!(e.scan_bucket("m", Some(m)).await.unwrap().missing.is_empty(), "segs's own scan reports s2");
        assert_eq!(e.segments.depends("m"), Depends { left_to: ["segs".to_string()].into(), followed: false });
    }

    /// A DLO's segments are the keys under its prefix in a bucket of its
    /// tenant, listed a range of each shard at a time, a page at a time:
    /// not the keys around them, nor an upload's entries or an escaped key.
    #[cfg(unix)]
    #[tokio::test]
    async fn dlo_prefix_is_followed() {
        let m = stats_of(json!({ "bucket": "m", "tenant": "t", "id": "IDM", "marker": "MM" }));
        let segs = json!({ "bucket": "segs", "tenant": "t", "id": "IDS", "marker": "MS", "num_shards": 2 });
        let mut store = MockStore::new(1, 0);
        store.bi_max = 2;
        store.shards.insert(".dir.IDM".into(), vec![old_entry("d")]);
        store.put(0, "MM_d", object(&[(crate::native::XATTR_USER_MANIFEST, b"segs/p/\0")], &[]));
        for shard in 0..2 {
            store.shards.insert(format!(".dir.IDS.{shard}"), Vec::new());
        }
        let mut names = vec!["_multipart_p/x.U.meta", "__p/esc", "o", "p", "p.", "p/", "p/1", "p/2", "p/2/x", "p/\u{e9}", "p0", "q/1", "\u{e9}"];
        names.sort();
        for name in names {
            store.shards.get_mut(&format!(".dir.IDS.{}", crate::native::shard_of(name, 2))).unwrap().push(old_entry(name));
            if name != "p/2" {
                store.put(0, &format!("MS_{}", crate::decode::Key::from_index(name, "").oid()), object(&[(XATTR_ETAG, b"E")], &[]));
            }
        }
        // p/1's entry lists an older object than its head holds
        store.put(0, "MS_p/1", object(&[(XATTR_ETAG, b"new")], &[]));
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=t/segs", segs.to_string())]);
        let e = changed(engine(store, admin, Listing::Native), |e| e.opts.check_index = true);
        let seeds = listed(&e, m.clone(), None).await;
        assert_eq!(keys_in(&seeds, "t/segs"), ["p/", "p/1", "p/2", "p/2/x", "p/\u{e9}"]);
        let r = e.scan_bucket("t/m", Some(m)).await.unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.missing, ["s3://t/segs/p/2 MISSING MS_p/2"]);
        let segs = |check: &str, key: &str| (check.to_string(), "t/segs".to_string(), key.to_string());
        assert_eq!(found(&r), [segs("listed_without_head", "p/2"), segs("stale_entry", "p/1")]);
    }

    /// A bucket segments are in that does not exist is a tally of each large
    /// object, as radoslist only warns of it; one whose stats cannot be read
    /// is an error, once.
    #[cfg(unix)]
    #[tokio::test]
    async fn segment_buckets_not_there() {
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
        let store = || {
            let mut store = slo_store();
            store.shards.get_mut(".dir.IDM").unwrap().push(old_entry("big2"));
            store.put(0, "MM_big2", slo_head(&["/segs/s3", "/segs/s4"]));
            store
        };
        let (admin, _dir) = fake_admin_exiting(&[] as &[(&str, &str)], libc::ENOENT);
        let r = engine(store(), admin, Listing::Native).scan_bucket("m", Some(m.clone())).await.unwrap();
        assert!(r.missing.is_empty() && r.findings.is_empty() && r.errors.is_empty(), "{r:?}");
        assert_eq!(r.tally.skipped.get(crate::native::SKIP_NO_SEGMENT_BUCKET), Some(&2), "{:?}", r.tally.skipped);
        assert_eq!(r.rados_objects, 2);

        let (admin, _dir) = fake_admin_exiting(&[] as &[(&str, &str)], libc::EIO);
        let r = engine(store(), admin, Listing::Native).scan_bucket("m", Some(m.clone())).await.unwrap();
        assert!(r.missing.is_empty() && r.findings.is_empty() && r.tally.skipped.is_empty(), "{r:?}");
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].contains("bucket stats --bucket=segs") && r.errors[0].ends_with("segments in segs are not checked"), "{:?}", r.errors);

        // an index shard of segs that is not there: an error, once, for the
        // segments in it; those in the others are checked
        let lost = format!(".dir.IDS.{}", crate::native::shard_of("s1", 3));
        assert_ne!(lost, format!(".dir.IDS.{}", crate::native::shard_of("s2", 3)));
        let mut store = store();
        store.shards.remove(&lost);
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
        let r = engine(store, admin, Listing::Native).scan_bucket("m", Some(m)).await.unwrap();
        assert_eq!(r.missing, ["s3://segs/s2 MISSING MS_s2"]);
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].contains(&format!("index shard {lost} does not exist")), "{:?}", r.errors);
    }

    /// Manifests that name each other: the listing ends, and follows each
    /// segment once.
    #[cfg(unix)]
    #[tokio::test]
    async fn large_object_loops_end() {
        // m's big and big2 are SLOs of segs/s1, itself an SLO of s1, m/big
        // and s2; s2 is a DLO of segs's keys under s
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
        let segs = json!({ "bucket": "segs", "id": "IDS", "marker": "MS" });
        let mut store = MockStore::new(1, 0);
        store.shards.insert(".dir.IDM".into(), vec![old_entry("big"), old_entry("big2")]);
        store.shards.insert(".dir.IDS".into(), vec![old_entry("s1"), old_entry("s2")]);
        store.put(0, "MM_big", slo_head(&["/segs/s1"]));
        store.put(0, "MM_big2", slo_head(&["/segs/s1"]));
        store.put(0, "MS_s1", slo_head(&["/segs/s1", "/m/big", "/segs/s2"]));
        store.put(0, "MS_s2", object(&[(crate::native::XATTR_USER_MANIFEST, b"segs/s")], &[]));
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs.to_string())]);
        let store = Arc::new(store);
        let e = changed(engine(MockStore::new(1, 0), admin, Listing::Native), |e| e.store = store.clone());
        let seeds = tokio::time::timeout(std::time::Duration::from_secs(20), listed(&e, m, None)).await.expect("the listing ends");
        assert!(seeds.iter().all(|s| s.error.is_none()), "{seeds:?}");
        let mut all: Vec<String> = seeds.iter().map(|s| format!("{}/{}", s.bucket, s.key)).collect();
        all.sort();
        assert_eq!(all, ["m/big", "m/big2", "segs/s1", "segs/s2"]);
        // m's shard, then s1, s2 and the prefix s once each
        assert_eq!(store.bi_calls.load(Ordering::Relaxed), 4);
    }

    /// Many large objects, a small limiter, and reads that take time, as a
    /// cluster's do: the listing follows their segments a batch at a time,
    /// while it lists, and holds no permit while it waits on the checks.
    #[cfg(unix)]
    #[tokio::test]
    async fn following_many_large_objects_ends() {
        let n = 1200;
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
        let store = |latency: u64| {
            let mut store = MockStore::new(1, 0);
            store.latency = std::time::Duration::from_millis(latency);
            store.shards.insert(".dir.IDM".into(), (0..n).map(|i| old_entry(&format!("big{i:04}"))).collect());
            // over many shards, as the mock rebuilds a shard's omap for each bi_list
            for i in 0..n {
                let key = format!("s{i:04}");
                store.shards.entry(format!(".dir.IDS.{}", crate::native::shard_of(&key, 64))).or_default().push(old_entry(&key));
            }
            for i in 0..n {
                store.put(0, &format!("MM_big{i:04}"), slo_head(&[&format!("/segs/s{i:04}")]));
                if i % 100 != 7 {
                    store.put(0, &format!("MS_s{i:04}"), object(&[], &[]));
                }
            }
            store
        };
        let segs = json!({ "bucket": "segs", "id": "IDS", "marker": "MS", "num_shards": 64 }).to_string();
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs.clone())]);
        let e = changed(engine(store(1), admin, Listing::Native), |e| e.limiter = Limiter::new(4));
        let r = tokio::time::timeout(std::time::Duration::from_secs(60), e.scan_bucket("m", Some(m.clone()))).await.expect("the scan ends").unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.rados_objects, r.gaps), (2 * n as u64, 12));
        assert!(r.missing.iter().all(|l| l.starts_with("s3://segs/s") && l.ends_with("7")), "{:?}", r.missing);

        // some followed before m is all listed: a batch is all it holds
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs)]);
        let seeds = listed(&engine(store(0), admin, Listing::Native), m, None).await;
        assert_eq!(seeds.len(), 2 * n);
        let first_followed = seeds.iter().position(|s| s.bucket == "segs").unwrap();
        let last_listed = seeds.iter().rposition(|s| s.bucket == "m").unwrap();
        assert!(first_followed < last_listed, "{first_followed} {last_listed}");
    }

    /// A segment two shard units follow ( SLOs in each name it ) is reported
    /// once by a scan whose reports go to one place, and by each unit of a
    /// server's, which keeps one gap line and finding of it.
    #[cfg(unix)]
    #[tokio::test]
    async fn followed_segments_are_reported_once() {
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM", "num_shards": 2 }));
        let (a, b) = ("big", (0..).map(|i| format!("big{i}")).find(|k| crate::native::shard_of(k, 2) != crate::native::shard_of("big", 2)).unwrap());
        let store = || {
            let mut store = slo_store();
            store.shards.remove(".dir.IDM");
            for key in [a, b.as_str()] {
                store.shards.entry(format!(".dir.IDM.{}", crate::native::shard_of(key, 2))).or_default().push(old_entry(key));
                store.put(0, &format!("MM_{key}"), slo_head(&["/segs/s1", "/segs/s2"]));
            }
            store.shards.entry(format!(".dir.IDM.{}", 1 - crate::native::shard_of(a, 2))).or_default();
            store
        };
        let units = |once: bool| {
            let (admin, dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
            let e = engine(store(), admin, Listing::Native);
            if once {
                e.segments.report_once();
            }
            let m = m.clone();
            async move {
                let mut reports = Vec::new();
                for shard in 0..2 {
                    reports.push(e.scan_bucket_with("m", Some(m.clone()), Arc::default(), Some(shard)).await.unwrap());
                }
                drop(dir);
                reports
            }
        };
        let reports = units(true).await;
        let missing: Vec<&String> = reports.iter().flat_map(|r| &r.missing).collect();
        assert_eq!(missing, ["s3://segs/s2 MISSING MS_s2"]);
        assert_eq!(reports.iter().map(|r| r.gaps).sum::<u64>(), 1);
        assert_eq!(reports.iter().map(|r| r.findings.len()).sum::<usize>(), 1);
        // a server's client: each unit reports it
        let reports = units(false).await;
        assert!(reports.iter().all(|r| r.missing == ["s3://segs/s2 MISSING MS_s2"] && r.findings.len() == 1), "{reports:?}");
    }

    /// Manifests the listing cannot follow: an SLO's that does not decode is
    /// an error, but for a scan of every bucket and key; a DLO's that names
    /// no container a tally.
    #[cfg(unix)]
    #[tokio::test]
    async fn unreadable_manifests() {
        let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
        let store = || {
            let mut store = slo_store();
            store.shards.insert(".dir.IDM".into(), vec![old_entry("n"), old_entry("u")]);
            store.put(0, "MM_u", object(&[(crate::native::XATTR_SLO_MANIFEST, b"\x01")], &[]));
            store.put(0, "MM_n", object(&[(crate::native::XATTR_USER_MANIFEST, b"nocontainer\0")], &[]));
            store
        };
        let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
        let r = engine(store(), admin, Listing::Native).scan_bucket("m", Some(m.clone())).await.unwrap();
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].starts_with("s3://m/u: its SLO manifest does not decode"), "{:?}", r.errors);
        assert_eq!(r.tally.skipped.get(crate::native::SKIP_NAMELESS_SEGMENT), Some(&1), "{:?}", r.tally.skipped);
        for opts in [Options { orphans: true, ..Options::default() }, Options { every_bucket: true, ..Options::default() }] {
            let (admin, _dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
            let seeds = listed(&changed(engine(store(), admin, Listing::Native), |e| e.opts = opts), m.clone(), None).await;
            assert!(seeds.iter().all(|s| s.error.is_none() && s.bucket == "m"), "{seeds:?}");
        }
    }

    /// A bucket scanned a shard at a time finds what a scan of it whole
    /// does: logs/b was completed through upload 2~U, whose meta object was
    /// left, and copied to a key in the other shard, which names the upload
    /// from there; its part has no index entry.  With logs/b deleted, the
    /// copy's upload is open; with it still there, both are.
    #[tokio::test]
    async fn shard_units_see_other_shards_uploads() {
        use crate::decode::enc::multipart_manifest;
        let stats = stats_of(json!({ "bucket": "b", "id": "B.1", "marker": "M.1", "num_shards": 2 }));
        let (src, meta) = ("logs/b", "_multipart_logs/b.2~U.meta");
        let copy = (0..).map(|i| format!("archive/{i}")).find(|k| crate::native::shard_of(k, 2) != crate::native::shard_of(src, 2)).unwrap();
        let shards = crate::native::shard_objects(&stats, None);
        let run = |source: bool, shard: Option<u32>| {
            let mut store = MockStore::new(1, 1);
            store.put(1, &format!("M.1_{meta}"), object(&[], &["part.1"]));
            store.put(0, "M.1__multipart_logs/b.2~U.1", object(&[], &[]));
            let head = |key: &str| object(&[(crate::native::XATTR_MANIFEST, &multipart_manifest("M.1", key, "logs/b.2~U", 1)), (XATTR_IDTAG, b"t")], &[]);
            let mut keys = vec![copy.as_str()];
            if source {
                keys.push(src);
            }
            for oid in &shards {
                store.shards.insert(oid.clone(), Vec::new());
                store.index.insert((stats.placement(), oid.clone()), Vec::new());
            }
            for key in keys {
                store.shards.get_mut(&shards[crate::native::shard_of(key, 2)]).unwrap().push(old_entry(key));
                store.put(0, &format!("M.1_{key}"), head(key));
            }
            // the meta object's entry, in its key's shard, and no part's
            store.index.get_mut(&(stats.placement(), shards[crate::native::shard_of(src, 2)].clone())).unwrap().push(meta.to_string());
            let e = changed(engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native), |e| e.opts.uploads = true);
            let stats = stats.clone();
            async move {
                let r = e.scan_bucket_with("b", Some(stats), Arc::default(), shard).await.unwrap();
                assert!(r.errors.is_empty(), "{:?}", r.errors);
                found(&r)
            }
        };
        let open = |key: &str| ("completed_upload_open".to_string(), "b".to_string(), key.to_string());
        for (source, want) in [(false, vec![open(&copy)]), (true, vec![open(&copy), open(src)])] {
            assert_eq!(run(source, None).await, want, "whole, source there: {source}");
            let mut units = run(source, Some(0)).await;
            units.extend(run(source, Some(1)).await);
            units.sort();
            assert_eq!(units, want, "a shard at a time, source there: {source}");
        }
    }

    /// Open uploads with unindexed parts, after a listing that did not read
    /// every head: the head that names one may be among those it missed,
    /// so none is reported as an upload no head names.
    #[tokio::test]
    async fn partial_listing_names_no_upload_unnamed() {
        // logs/k was completed through upload U, and its meta object left
        let store = || {
            let mut store = MockStore::new(1, 1);
            store.put(1, &format!("{MARKER}__multipart_logs/k.U.meta"), object(&[], &["part.1"]));
            store.index.insert(("default-placement".into(), ".dir.id1".into()), vec!["_multipart_logs/k.U.meta".into()]);
            for oid in [format!("{MARKER}_a"), format!("{MARKER}_logs/k"), format!("{MARKER}__multipart_logs/k.U.1")] {
                store.put(0, &oid, object(&[(XATTR_IDTAG, b"t")], &[]));
            }
            store
        };
        let (a, k, part) = (format!("{MARKER}_a"), format!("{MARKER}_logs/k"), format!("{MARKER}__multipart_logs/k.U.1"));
        let full = [("a", a.as_str()), ("logs/k", k.as_str()), ("logs/k", part.as_str())];
        let r = scan_exiting("partial-full", store(), Options::default(), &full, json!([]), Arc::default(), 0).await;
        assert_eq!(keys(&r.findings), [("completed_upload_open".to_string(), "logs/k".to_string())]);
        // radoslist fails after its first record
        let r = scan_exiting("partial-cut", store(), Options::default(), &full[..1], json!([]), Arc::default(), 5).await;
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert_eq!(r.tally.skipped.get("an upload with unindexed parts, not every head that may name it read"), Some(&1));

        // a native listing that could not read a head: what it names is not known
        let stats = stats_of(json!({ "bucket": "b", "id": "ID", "marker": "M" }));
        let mut store = MockStore::new(1, 1);
        store.shards.insert(".dir.ID".into(), vec![old_entry("logs/k")]);
        store.index.insert((stats.placement(), ".dir.ID".into()), vec!["_multipart_logs/k.U.meta".into()]);
        store.put(1, "M__multipart_logs/k.U.meta", object(&[], &["part.1"]));
        store.put(0, "M_logs/k", object(&[], &[]));
        store.fail(0, "M_logs/k", -libc::EIO);
        let e = changed(engine(store, Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY), Listing::Native), |e| e.opts.uploads = true);
        let r = e.scan_bucket("b", Some(stats)).await.unwrap();
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert!(r.errors.iter().any(|e| e.contains("stat of the head M_logs/k")), "{:?}", r.errors);
        assert_eq!(r.tally.skipped.get("an upload with unindexed parts, not every head that may name it read"), Some(&1));
    }

    /// radoslist lists a Swift large object's segments under their own
    /// bucket: their causes are ranked by that bucket's lifecycle, not the
    /// scanned one's.
    #[cfg(unix)]
    #[tokio::test]
    async fn radoslist_segment_uses_its_buckets_lifecycle() {
        let radoslist: Vec<u8> = [("S_seg", "segs", "seg"), ("S__multipart_seg.U.1", "segs", "seg")].iter().flat_map(|(oid, b, key)| record(oid, b, key)).collect();
        let rule = json!({ "rule_map": [{ "rule": { "mp_expiration": { "days": 1 } } }] }).to_string();
        // segs has no lifecycle configuration: lc get fails
        let (admin, _dir) = fake_admin(&[("bucket radoslist --rgw-obj-fs=* --bucket=m", radoslist), ("lc get --bucket=m", rule.into())]);
        let mut store = MockStore::new(1, 0);
        store.put(0, "S_seg", object(&[(XATTR_IDTAG, b"t")], &[]));
        let e = engine(store, admin, Listing::Radoslist);
        let r = e.scan_bucket("m", Some(stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" })))).await.unwrap();
        assert_eq!(found(&r), [("missing_data".to_string(), "segs".to_string(), "seg".to_string())]);
        let lc = r.findings[0].causes.iter().find(|c| c.cause == "lc-abort").expect("an lc-abort cause");
        assert_eq!(lc.confidence, Low, "{lc:?}");
    }

    /// A segment followed into its bucket, completed through an upload
    /// whose meta object was left: no scan checks it there, so the scan
    /// that follows it does, as a scan of that bucket would.
    #[cfg(unix)]
    #[tokio::test]
    async fn followed_segment_open_upload() {
        use crate::decode::enc::multipart_manifest;
        let store = || {
            let mut store = slo_store();
            store.extra = 1;
            store.put(0, "MS_s1", object(&[(crate::native::XATTR_MANIFEST, &multipart_manifest("MS", "s1", "s1.2~U", 1)), (XATTR_IDTAG, b"t")], &[]));
            store.put(0, "MS__multipart_s1.2~U.1", object(&[], &[]));
            store.put(1, "MS__multipart_s1.2~U.meta", object(&[], &["part.1"]));
            for shard in 0..3 {
                let oid = format!(".dir.IDS.{shard}");
                let keys = if shard == crate::native::shard_of("s1", 3) { vec!["_multipart_s1.2~U.meta".to_string()] } else { Vec::new() };
                store.index.insert(("segs-placement".into(), oid), keys);
            }
            let m = stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" }));
            store.index.insert((m.placement(), ".dir.IDM".into()), Vec::new());
            store
        };
        let scan = |of: &'static str, opts: Options| {
            let (admin, dir) = fake_admin(&[("bucket stats --bucket=segs", segs_stats())]);
            let e = changed(engine(store(), admin, Listing::Native), |e| e.opts = Options { uploads: true, ..opts });
            async move {
                let stats = if of == "m" { stats_of(json!({ "bucket": "m", "id": "IDM", "marker": "MM" })) } else { stats_of(serde_json::from_str(&segs_stats()).unwrap()) };
                let r = e.scan_bucket(of, Some(stats)).await.unwrap();
                drop(dir);
                assert!(r.errors.is_empty(), "{:?}", r.errors);
                found(&r)
            }
        };
        let f = |check: &str, key: &str| (check.to_string(), "segs".to_string(), key.to_string());
        let want = [f("completed_upload_open", "s1"), f("listed_without_head", "s2")];
        assert_eq!(scan("segs", Options::default()).await, want, "a scan of segs");
        assert_eq!(scan("m", Options::default()).await, want, "a scan of m, which follows s1");
        // a scan of every bucket, whose prefix leaves s1 out of segs's
        let every = Options { every_bucket: true, match_prefix: Some("b".into()), ..Options::default() };
        assert_eq!(scan("m", every).await, want, "a scan of every bucket under b");
    }

    /// A versioned key's OLH object lost, where a null delete marker was
    /// written before the current version: the index lists the marker
    /// still, but GET reads the OLH, and answers 404.  A null delete marker
    /// that is current is no gap.
    #[cfg(unix)]
    #[tokio::test]
    async fn olh_missing_behind_a_null_delete_marker() {
        let run = |current_dm: bool| {
            let mut entries: Vec<serde_json::Value> = serde_json::from_str(&bi(&[("k", "", 8), ("k", "", if current_dm { 7 } else { 5 })])).unwrap();
            if !current_dm {
                entries.extend(serde_json::from_str::<Vec<serde_json::Value>>(&bi(&[("k", "V2", 3)])).unwrap());
            }
            let instance = if current_dm { "" } else { "V2" };
            entries.push(json!({ "type": "olh", "idx": "k", "entry": {
                "key": { "name": "k", "instance": instance }, "delete_marker": current_dm, "epoch": 3, "epoch_timestamp": "0.000003",
                "pending_log": [], "tag": "OT", "exists": true, "pending_removal": false,
            } }));
            let (admin, dir) = fake_admin(&[("bucket radoslist --rgw-obj-fs=* --bucket=b", record("M_k", "b", "k")), (&bi_list("k"), serde_json::to_vec(&entries).unwrap())]);
            let e = engine(MockStore::new(1, 0), admin, Listing::Radoslist);
            async move {
                let r = e.scan_bucket("b", Some(stats_of(json!({ "bucket": "b", "id": "ID", "marker": "M" })))).await.unwrap();
                drop(dir);
                assert!(r.errors.is_empty(), "{:?}", r.errors);
                r
            }
        };
        let r = run(false).await;
        assert_eq!(keys(&r.findings), [("olh_missing".to_string(), "k".to_string())]);
        assert_eq!(r.findings[0].evidence["current_instance"], json!("V2"));
        assert_eq!(r.missing, ["s3://b/k MISSING M_k"]);
        let r = run(true).await;
        assert!(r.findings.is_empty() && r.missing.is_empty(), "{r:?}");
        assert_eq!(r.tally.skipped.get("delete marker"), Some(&1));
    }
}
