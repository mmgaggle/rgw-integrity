//! The checks: the gap check, one S3 object at a time, and the checks for the
//! other artifacts known RGW races leave behind.  A port of rgw-gap-list.py's
//! classification.

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
use crate::oid::{Kind, decode_refcount, index_objects, iso, key_oid, parse_oid, parse_time, split_key, survives_gc, tag_text};
use crate::store::{PoolId, Pools, Stat, Store};

pub const XATTR_IDTAG: &str = "user.rgw.idtag";
pub const XATTR_TAIL_TAG: &str = "user.rgw.tail_tag";
pub const XATTR_ETAG: &str = "user.rgw.etag";
pub const XATTR_MP_COMPLETION_TAG: &str = "user.rgw.mp_completion_tag";
pub const XATTR_REFCOUNT: &str = "refcount";

use Confidence::{High, Low, Medium};

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    /// skip findings younger than this many seconds
    pub grace: i64,
    /// compare each index entry's ETag with its head's
    pub check_index: bool,
    /// read each tail object's refcount
    pub refcount: bool,
    /// read each bucket's open multipart uploads from its index
    pub uploads: bool,
    /// only S3 objects whose key starts with this
    pub match_prefix: Option<String>,
    /// concurrent head reads of the index check
    pub threads: usize,
    /// find orphans: RADOS objects in the data pools that no bucket references
    #[serde(default)]
    pub orphans: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { grace: 3600, check_index: false, refcount: false, uploads: true, match_prefix: None, threads: 32, orphans: false }
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
    /// the `s3://bucket/key MISSING <oid>` lines of rgw-gap-list
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
    missing: Vec<String>,
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
    uploads: HashMap<String, Upload>,
    named: Mutex<HashSet<String>>,
    lc_mp: OnceCell<bool>,
    out: Mutex<Out>,
    rados_objects: Arc<AtomicU64>,
}

impl Bucket {
    fn emit(&self, f: Finding) {
        let mut out = self.out.lock().unwrap();
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
}

struct Group {
    bucket: String,
    key: String,
    oids: Vec<String>,
    uploads: BTreeSet<String>,
    open_uploads: BTreeSet<String>,
    gc: Vec<(String, Vec<(String, Option<i64>)>)>,
    present: Vec<(String, PoolId)>,
    missing: Vec<String>,
}

impl Group {
    fn new(bucket: String, key: String) -> Group {
        Group {
            bucket,
            key,
            oids: Vec::new(),
            uploads: BTreeSet::new(),
            open_uploads: BTreeSet::new(),
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

    async fn head_info(&self, oid: &str) -> Option<HeadInfo> {
        let (pool, _, mtime) = self.store.find(oid, Pools::Data).await?;
        let get = |name| async move { self.store.getxattr(pool, oid, name).await.ok().flatten().map(|v| tag_text(&v)) };
        let (idtag, tail_tag, etag) = tokio::join!(get(XATTR_IDTAG), get(XATTR_TAIL_TAG), get(XATTR_ETAG));
        Some(HeadInfo { mtime, idtag, tail_tag, etag })
    }

    async fn read_meta(&self, marker: &str, key: &str, upload: &str) -> Option<Meta> {
        let oid = format!("{marker}__multipart_{key}.{upload}.meta");
        let (pool, _, mtime) = self.store.find(&oid, Pools::ExtraFirst).await?;
        let keys = self.store.omap_keys(pool, &oid, "part.").await.ok().flatten().unwrap_or_default();
        let parts = keys.iter().filter_map(|k| k.strip_prefix("part.")?.parse().ok()).collect();
        let record = self.store.getxattr(pool, &oid, XATTR_MP_COMPLETION_TAG).await.ok().flatten().map(|v| tag_text(&v));
        Some(Meta { oid, mtime, parts, record })
    }

    /// The bucket's open uploads and their parts' entries, from its index:
    /// only keys in the multipart namespace, filtered by the OSDs.
    async fn list_open_uploads(&self, stats: &BucketStats) -> Result<HashMap<String, Upload>> {
        let mut uploads: HashMap<String, Upload> = HashMap::new();
        if !stats.index_type.is_empty() && stats.index_type != "Normal" {
            return Ok(uploads);
        }
        let placement = stats.placement();
        for oid in index_objects(&stats.id, stats.num_shards, stats.index_generation) {
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

    /// Scan one bucket.  `stats` saves a `bucket stats` call when the caller
    /// has them.
    pub async fn scan_bucket(self: &Arc<Self>, name: &str, stats: Option<BucketStats>) -> Result<BucketReport> {
        self.scan_bucket_with(name, stats, Arc::default()).await
    }

    /// The same, counting the RADOS objects listed in `progress` as it goes.
    pub async fn scan_bucket_with(self: &Arc<Self>, name: &str, stats: Option<BucketStats>, progress: Arc<AtomicU64>) -> Result<BucketReport> {
        let started = Instant::now();
        let mut errors = Vec::new();
        let stats = match stats {
            Some(s) => Some(s),
            None => match self.admin.bucket_stats(name).await {
                Ok(s) => Some(s),
                Err(e) => {
                    errors.push(format!("{e:#}; skipping the upload and index checks"));
                    None
                }
            },
        };
        let mut uploads = HashMap::new();
        if let (true, Some(st)) = (self.opts.uploads, &stats) {
            match self.list_open_uploads(st).await {
                Ok(u) => uploads = u,
                Err(e) => {
                    // resharded since the stats were read?
                    match self.admin.bucket_stats(name).await {
                        Ok(fresh) if fresh.index_generation != st.index_generation || fresh.num_shards != st.num_shards => {
                            uploads = self.list_open_uploads(&fresh).await.unwrap_or_else(|e| {
                                errors.push(format!("{e:#}"));
                                HashMap::new()
                            })
                        }
                        _ => errors.push(format!("{e:#}")),
                    }
                }
            }
        }
        let marker = stats.as_ref().map(|s| s.marker.clone()).unwrap_or_default();
        let bucket = Arc::new(Bucket {
            name: name.to_string(),
            stats,
            marker,
            start: now(),
            uploads,
            named: Mutex::default(),
            lc_mp: OnceCell::new(),
            out: Mutex::new(Out { errors, ..Default::default() }),
            rados_objects: progress,
        });

        let gc = self.gc.read().unwrap().clone();
        let mut rx = self.admin.radoslist(name);
        let mut tasks = JoinSet::new();
        // bound the S3 objects in flight, so a fast listing cannot outrun the stats
        let groups = Arc::new(Semaphore::new(4096));
        let mut cur: Option<Group> = None;
        let mut references = self.partitions.map(crate::detect::Refs::new);
        while let Some(line) = rx.recv().await {
            let (oid, b, key) = match line {
                Ok(l) => l,
                Err(e) => {
                    // a partial listing would make orphans of what it missed
                    if references.is_some() {
                        return Err(e.context(format!("listing {name}")));
                    }
                    bucket.out.lock().unwrap().errors.push(format!("{e:#}"));
                    break;
                }
            };
            if let Some(r) = references.as_mut() {
                r.add(&oid);
            }
            if let Some(p) = &self.opts.match_prefix {
                if !key.starts_with(p.as_str()) {
                    continue;
                }
            }
            bucket.rados_objects.fetch_add(1, Ordering::Relaxed);
            if cur.as_ref().is_none_or(|g| g.bucket != b || g.key != key) {
                if let Some(g) = cur.take() {
                    let permit = groups.clone().acquire_owned().await?;
                    let (engine, bucket) = (self.clone(), bucket.clone());
                    tasks.spawn(async move {
                        engine.process_group(&bucket, g).await;
                        drop(permit);
                    });
                }
                cur = Some(Group::new(b, key));
            }
            let g = cur.as_mut().expect("set above");
            let o = parse_oid(&oid);
            // radoslist lists an open upload's meta object too; only parts name an upload
            if let (Some(upload), true) = (o.upload, o.kind.is_multipart()) {
                g.uploads.insert(upload.to_string());
                if bucket.uploads.get(upload).is_some_and(|u| u.meta) {
                    g.open_uploads.insert(upload.to_string());
                    bucket.named.lock().unwrap().insert(upload.to_string());
                }
            }
            if let Some(entries) = gc.map.get(&oid) {
                g.gc.push((oid.clone(), entries.clone()));
            }
            g.oids.push(oid);
        }
        if let Some(g) = cur.take() {
            let (engine, bucket) = (self.clone(), bucket.clone());
            tasks.spawn(async move { engine.process_group(&bucket, g).await });
        }
        while let Some(r) = tasks.join_next().await {
            r?;
        }

        if bucket.stats.is_some() {
            self.finalize_uploads(&bucket).await;
            if self.opts.check_index {
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
        let stats: Vec<(String, Stat)> = futures::stream::iter(g.oids.clone())
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
                Stat::Missing => {
                    let mut out = bucket.out.lock().unwrap();
                    out.gaps += 1;
                    out.missing.push(format!("s3://{}/{} MISSING {oid}", g.bucket, g.key));
                    drop(out);
                    g.missing.push(oid);
                }
                Stat::Error(r) => {
                    let e = std::io::Error::from_raw_os_error(-r);
                    bucket.out.lock().unwrap().errors.push(format!("stat of {oid}: {e}"));
                }
            }
        }
        let head = g.head().cloned();
        if !g.missing.is_empty() {
            self.classify_missing(bucket, &g, head.as_deref()).await;
        } else if !g.gc.is_empty() {
            self.check_pending_loss(bucket, &g, head.as_deref()).await;
        }
        for upload in &g.open_uploads {
            self.check_open_upload(bucket, &g, head.as_deref(), upload).await;
        }
        if self.opts.refcount {
            self.refcount_group(bucket, &g, head.as_deref()).await;
        }
    }

    async fn lc_mp(&self, bucket: &Bucket) -> bool {
        *bucket.lc_mp.get_or_init(|| self.admin.has_mp_expiration(&bucket.name)).await
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
        let lc = self.lc_mp(bucket).await;
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

    async fn classify_missing(&self, bucket: &Bucket, g: &Group, head: Option<&str>) {
        let (name, instance) = split_key(&g.key);
        if head.is_none_or(|h| g.missing.iter().any(|m| m == h)) {
            let Some(entry) = self.admin.index_entry(&bucket.name, name, instance).await else {
                return bucket.skip("deleted during the scan");
            };
            if entry.is_delete_marker() {
                return bucket.skip("delete marker");
            }
            if entry.pending {
                return bucket.skip("index op in flight");
            }
            let when = entry.mtime();
            if self.young(when) {
                return bucket.skip("younger than the grace period");
            }
            let mut f = Finding::new(Class::Inconsistency, "listed_without_head", &g.bucket)
                .key(&g.key)
                .evidence(json!({ "entry_etag": entry.etag, "entry_mtime": entry.mtime, "entry_tag": entry.tag }))
                .hint("ListObjects lists this key and GET answers 404");
            if let Some(h) = head {
                f = f.oids(&[h.to_string()]);
            }
            let why = "a delete, put, delete sequence whose completions arrived out of order leaves a listed key with no head";
            return bucket.emit(self.ctx.rank(f, vec![cause("stale-entry", Medium, why.to_string())], when));
        }
        let head = head.expect("checked above");
        let Some(info) = self.head_info(head).await else { return bucket.skip("deleted during the scan") };
        if info.mtime >= bucket.start - 1 {
            return bucket.skip("rewritten during the scan");
        }
        if self.young(Some(info.mtime)) {
            return bucket.skip("younger than the grace period");
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
        bucket.emit(self.ctx.rank(f, causes, Some(info.mtime)));
    }

    async fn check_pending_loss(&self, bucket: &Bucket, g: &Group, head: Option<&str>) {
        let mut doomed = Vec::new();
        let mut due = Vec::new();
        for (oid, entries) in &g.gc {
            let pool = g.present.iter().find(|(o, _)| o == oid).map(|(_, p)| *p);
            let refcount = match pool {
                Some(p) => self.store.getxattr(p, oid, XATTR_REFCOUNT).await.ok().flatten().and_then(|b| decode_refcount(&b).ok()),
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
        let Some(info) = (match head {
            Some(h) => self.head_info(h).await,
            None => None,
        }) else {
            return bucket.skip("deleted during the scan");
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
        bucket.emit(self.ctx.rank(f, causes, Some(info.mtime)));
    }

    /// A listed head names the parts of an upload that is still open.
    async fn check_open_upload(&self, bucket: &Bucket, g: &Group, head: Option<&str>, upload: &str) {
        let Some(info) = (match head {
            Some(h) => self.head_info(h).await,
            None => None,
        }) else {
            return;
        };
        if self.young(Some(info.mtime)) {
            return bucket.skip("younger than the grace period");
        }
        let u = &bucket.uploads[upload];
        let Some(meta) = self.read_meta(&bucket.marker, &u.key, upload).await else {
            return bucket.skip("upload closed during the scan");
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
            return bucket.emit(self.ctx.rank(f, vec![c], Some(info.mtime)));
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
        bucket.emit(self.ctx.rank(f, causes, Some(info.mtime)));
    }

    /// Open uploads no listed head names: all their parts should be indexed.
    async fn finalize_uploads(&self, bucket: &Bucket) {
        let named = bucket.named.lock().unwrap().clone();
        let mut uploads: Vec<(&String, &Upload)> = bucket.uploads.iter().filter(|(id, u)| u.meta && !named.contains(*id)).collect();
        uploads.sort_by_key(|(id, _)| *id);
        for (upload, u) in uploads {
            let Some(meta) = self.read_meta(&bucket.marker, &u.key, upload).await else { continue };
            if self.young(Some(meta.mtime)) {
                bucket.skip("younger than the grace period");
                continue;
            }
            let unindexed: Vec<u64> = meta.parts.difference(&u.parts).copied().collect();
            if unindexed.is_empty() {
                continue;
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

    /// Index entries that list an older object than their head holds.
    async fn check_index(&self, bucket: &Bucket) -> Result<()> {
        let mut seen = HashSet::new();
        let mut rx = self.admin.bi_list(&bucket.name);
        let mut entries = Vec::new();
        loop {
            let item = rx.recv().await;
            let done = item.is_none();
            if let Some(item) = item {
                let e = IndexEntry::from_value(&item?);
                if (e.kind == "plain" || e.kind == "instance")
                    && !e.name.starts_with("_multipart_")
                    && e.exists
                    && !e.pending
                    && !e.is_delete_marker()
                    && seen.insert((e.name.clone(), e.instance.clone()))
                {
                    entries.push(e);
                }
            }
            if done || entries.len() >= 4096 {
                let batch = std::mem::take(&mut entries);
                let results: Vec<(IndexEntry, Option<HeadInfo>)> = futures::stream::iter(batch)
                    .map(|e| async move {
                        let _permit = self.limiter.acquire().await;
                        let oid = format!("{}_{}", bucket.marker, key_oid(&e.name, &e.instance));
                        let info = self.head_info(&oid).await;
                        (e, info)
                    })
                    .buffer_unordered(self.opts.threads.max(1))
                    .collect()
                    .await;
                for (e, info) in results {
                    let Some(info) = info else { continue };
                    if info.mtime >= bucket.start - 1 || self.young(Some(info.mtime)) {
                        continue;
                    }
                    if info.etag.is_none() || info.etag.as_deref() == Some(e.etag.as_str()) {
                        continue;
                    }
                    let key = if e.instance.is_empty() { e.name.clone() } else { format!("{}[{}]", e.name, e.instance) };
                    let f = Finding::new(Class::Inconsistency, "stale_entry", &bucket.name)
                        .key(key)
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

    /// References on this object's tail objects, and the tags its head carries.
    async fn refcount_group(&self, bucket: &Bucket, g: &Group, head: Option<&str>) {
        let tails: Vec<(String, PoolId)> = g.present.iter().filter(|(o, _)| parse_oid(o).kind != Kind::Head).cloned().collect();
        if tails.is_empty() {
            return;
        }
        let refs: Vec<(String, BTreeSet<String>)> = futures::stream::iter(tails)
            .map(|(oid, pool)| async move {
                let _permit = self.limiter.acquire().await;
                let rc = self.store.getxattr(pool, &oid, XATTR_REFCOUNT).await.ok().flatten().and_then(|b| decode_refcount(&b).ok());
                let tags: BTreeSet<String> = rc.map(|rc| rc.tags().cloned().collect()).unwrap_or_default();
                (oid, tags)
            })
            .buffer_unordered(64)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter(|(_, tags)| !tags.is_empty())
            .collect();
        if refs.is_empty() {
            return;
        }
        let carried: BTreeSet<String> = match head {
            Some(h) => self.head_info(h).await.map(|i| [i.idtag, i.tail_tag].into_iter().flatten().collect()).unwrap_or_default(),
            None => BTreeSet::new(),
        };
        let mut out = bucket.out.lock().unwrap();
        for (oid, tags) in refs {
            out.refs.needed.entry(oid.clone()).or_insert_with(|| (bucket.name.clone(), BTreeSet::new())).1.extend(tags);
            out.refs.carried.entry(oid).or_default().extend(carried.iter().cloned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
