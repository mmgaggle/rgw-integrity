//! The native listing: a bucket's objects, and every RADOS object each
//! one's manifest names, read from its index shards and head objects, with
//! no radosgw-admin.  One shard at a time, so a bucket's shards can be
//! spread over clients.  As radoslist does, it follows Swift large objects
//! into the buckets their segments are in.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use futures::StreamExt;
use tokio::sync::{OnceCell, mpsc};

use crate::admin::BucketStats;
use crate::decode::{
    DirEntry, FLAG_VER_MARKER, Key, Manifest, RawName, SloInfo, bi_list_named_op, bi_list_op, bi_list_ret, dlo_segments, object_names, slo_segment,
};
use crate::oid::{index_objects, parse_oid};
use crate::scan::Engine;
use crate::store::{PoolId, Pools, Stat, strerror};

pub const XATTR_MANIFEST: &str = "user.rgw.manifest";
/// a Swift DLO's "container/prefix"
pub const XATTR_USER_MANIFEST: &str = "user.rgw.user_manifest";
/// a Swift SLO's RGWSLOInfo
pub const XATTR_SLO_MANIFEST: &str = "user.rgw.slo_manifest";

/// Where a Swift large object's segments are, as its head names them: in a
/// container of the head's tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Segment {
    /// a DLO's: every object whose key starts with the prefix
    Prefix { container: String, prefix: String },
    /// an SLO's: one object
    Key { container: String, key: String },
    /// an SLO manifest this tool cannot decode: its segments are unknown
    Undecodable(String),
    /// a manifest's path that names no object, which a GET cannot read either
    Nameless(String),
}

/// The segments a head's xattrs name, if it is a Swift large object: a DLO's
/// prefix, or an SLO's objects ( a GET reads the DLO's if there are both ).
pub fn segments_of(xattrs: &HashMap<String, Vec<u8>>) -> Vec<Segment> {
    if let Some(dlo) = xattrs.get(XATTR_USER_MANIFEST) {
        return vec![match dlo_segments(dlo) {
            Some((container, prefix)) => Segment::Prefix { container, prefix },
            None => Segment::Nameless(String::from_utf8_lossy(dlo.split(|&c| c == 0).next().unwrap_or_default()).into_owned()),
        }];
    }
    let Some(slo) = xattrs.get(XATTR_SLO_MANIFEST) else { return Vec::new() };
    match SloInfo::decode(slo) {
        Ok(info) => info
            .entries
            .into_iter()
            .map(|e| match slo_segment(&e.path) {
                Some((container, key)) => Segment::Key { container, key },
                None => Segment::Nameless(e.path),
            })
            .collect(),
        Err(e) => vec![Segment::Undecodable(format!("{e:#}"))],
    }
}

/// The tally of a large object whose segments are in a bucket that does not
/// exist ( Swift takes a manifest before its segments ): no error, as
/// radoslist only warns of it.
pub const SKIP_NO_SEGMENT_BUCKET: &str = "a Swift large object's segments in a bucket that does not exist";
/// The tally of a manifest's path that names no object.
pub const SKIP_NAMELESS_SEGMENT: &str = "a Swift large object's segment path that names no object";
/// The tally of a large object among segments nested deeper than FOLLOW_DEPTH.
pub const SKIP_NESTED_SEGMENTS: &str = "a Swift large object's segments nested too deep to follow";

/// Segments a listing takes to follow before it follows them.
const FOLLOW_BATCH: usize = 1024;
/// What a listing remembers it has followed ( Follow::seen ) at most.
const FOLLOW_SEEN: usize = 1 << 16;
/// How deep in large objects a listing follows segments: a bound, so that
/// a manifest loop ends however long it is, though `seen` ends most at once.
const FOLLOW_DEPTH: u32 = 8;

/// What a scan knows of the buckets Swift large objects keep segments in:
/// those it lists itself, the stats and lifecycle of those it follows
/// segments into ( read once a scan ), and what it reported of them.
#[derive(Default)]
pub struct Segments {
    /// the buckets the scan names ( as `bucket list` names them ): it lists
    /// them itself.  Unset, only a unit's own bucket is known listed, or
    /// every one ( Options::every_bucket )
    named: OnceLock<HashSet<String>>,
    /// the findings ( by fingerprint ) and MISSING lines of followed
    /// segments reported so far, when every unit's report goes to one place
    /// ( a standalone scan ): each once, however many units follow it.
    /// Unset on a server's client, which may scan a unit again: the server
    /// keeps one finding per fingerprint, and a gap line once a scan
    reported: OnceLock<Mutex<HashSet<String>>>,
    stats: Mutex<HashMap<String, StatsOnce>>,
    lc_mp: Mutex<HashMap<String, Arc<OnceCell<bool>>>>,
    /// what each bucket's units relied on other buckets for, by its name
    depends: Mutex<HashMap<String, Depends>>,
}

/// What a bucket's units relied on other buckets for, of the Swift segments
/// its large objects name: a --state record of one is reused only by a
/// scan that lists those it left segments to, and only if it followed none
/// ( the lines of followed segments are reported once a scan, by whichever
/// unit follows them first ).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Depends {
    /// the other buckets it left segments to, as the scan lists them
    pub left_to: BTreeSet<String>,
    /// it followed segments into a bucket the scan does not list
    pub followed: bool,
}

impl Segments {
    /// What a bucket's units relied on so far ( see Depends ).
    pub fn depends(&self, bucket: &str) -> Depends {
        self.depends.lock().unwrap().get(bucket).cloned().unwrap_or_default()
    }

    /// Add what a unit of `bucket` relied on ( see Depends ).
    fn relies(&self, bucket: String, on: Depends) {
        if on != Depends::default() {
            let mut depends = self.depends.lock().unwrap();
            let d = depends.entry(bucket).or_default();
            d.left_to.extend(on.left_to);
            d.followed |= on.followed;
        }
    }

    /// The buckets the scan names, which it lists itself.
    pub fn lists_too(&self, buckets: impl IntoIterator<Item = String>) {
        let _ = self.named.set(buckets.into_iter().collect());
    }

    /// Report once a scan what followed segments show ( see `reported` ).
    pub fn report_once(&self) {
        let _ = self.reported.set(Mutex::default());
    }

    /// Whether to report a followed segment's finding ( its fingerprint ) or
    /// MISSING line: not one reported already, when the scan reports once.
    pub fn first(&self, what: &str) -> bool {
        self.reported.get().is_none_or(|r| r.lock().unwrap().insert(what.to_string()))
    }
}

/// A bucket's stats, read once: None if there is no such bucket.  A
/// failure to read them is not kept: the next listing asks again.
type StatsOnce = Arc<OnceCell<Option<Arc<BucketStats>>>>;

/// A segment to follow: the large object that names it ( s3://bucket/key ),
/// and how deep in large objects it is.
struct Pending {
    of: String,
    segment: Segment,
    depth: u32,
}

/// A listing's following of segments.
#[derive(Default)]
struct Follow {
    pending: Vec<Pending>,
    /// what it followed or sent: the segments large objects named, the keys
    /// it sent, the notes it made.  Cleared when full: a repeat after that is
    /// followed again, and reported once all the same ( Segments::first )
    seen: HashSet<String>,
}

impl Follow {
    /// Whether the listing has not followed or sent `what` ( see `seen` ).
    fn first(&mut self, what: String) -> bool {
        if self.seen.len() >= FOLLOW_SEEN {
            self.seen.clear();
        }
        self.seen.insert(what)
    }
}

/// A bucket segments are followed into.
struct SegmentBucket {
    name: String,
    stats: Arc<BucketStats>,
    /// the scan lists it itself, and checks there the keys it covers
    scanned: bool,
}

/// The id of the note that a bucket segments are in cannot be read: a
/// listing sends it once, and asks no more of that bucket.
fn failed_bucket(name: &str) -> String {
    format!("E\0{name}")
}

/// The bucket of a container a large object in `unit` names: one of its
/// tenant, where its owner's GET looks.
fn segment_bucket(unit: &BucketStats, container: &str) -> String {
    if unit.tenant.is_empty() { container.to_string() } else { format!("{}/{container}", unit.tenant) }
}

/// One S3 object, as a listing yields it: its key as radoslist writes it,
/// the RADOS objects it names ( head first ), and its index entry.
#[derive(Debug, Clone)]
pub struct Seed {
    pub bucket: String,
    pub key: String,
    pub oids: Vec<String>,
    pub entry: Option<DirEntry>,
    /// the head could not be statted, or its manifest read or decoded: what
    /// it names is not all known
    pub error: Option<String>,
    /// the objects the listing found, and their pools: not to stat again
    pub found: Vec<(String, PoolId)>,
    /// the stripes of an open upload's parts, which radoslist lists without
    /// a key: references, not an S3 object
    pub parts: bool,
    /// the index shard object the listing read the entry from
    pub shard: Option<String>,
    /// the segments its head names, if it is a Swift large object
    pub segments: Vec<Segment>,
    /// a segment of a large object the listing followed into its bucket,
    /// which the scan may not list: that bucket's index placement
    pub followed: Option<String>,
    /// why what the head names is not all checked, though no error: a tally
    pub skipped: Option<&'static str>,
}

impl Seed {
    fn new(bucket: &str, key: String, entry: Option<DirEntry>) -> Seed {
        Seed {
            bucket: bucket.to_string(),
            key,
            oids: Vec::new(),
            entry,
            error: None,
            found: Vec::new(),
            parts: false,
            shard: None,
            segments: Vec::new(),
            followed: None,
            skipped: None,
        }
    }

    /// What a listing could not follow into a bucket: no object, and an
    /// error or a tally.
    fn note(bucket: &str, error: Option<String>, skipped: Option<&'static str>) -> Seed {
        Seed { error, skipped, ..Seed::new(bucket, String::new(), None) }
    }
}

/// How to scan a bucket: whole, or a unit per index shard when it has more
/// than `above` S3 objects over several shards.  Everything of a key ( its
/// versions, its OLH, its uploads' meta and part entries ) hashes to the
/// shard of its name, so a shard is listed on its own; but a copy shares
/// its source's tail, and names its upload from another shard: a unit looks
/// up such an upload's meta object, and reads the uploads every head names
/// before it reports one no head of its own names ( scan.rs ).
pub fn shard_units(stats: &BucketStats, above: u64) -> Vec<Option<u32>> {
    let shards = stats.num_shards.min(u32::MAX as u64) as u32;
    if shards > 1 && stats.num_objects() > above {
        (0..shards).map(Some).collect()
    } else {
        vec![None]
    }
}

/// The shard objects of a bucket's current index: all, or one.
pub fn shard_objects(stats: &BucketStats, shard: Option<u32>) -> Vec<String> {
    let all = index_objects(&stats.id, stats.num_shards, stats.index_generation);
    match shard {
        Some(s) => all.into_iter().nth(s as usize).into_iter().collect(),
        None => all,
    }
}

/// A range of a shard's index: the entries whose index key starts with
/// `prefix` ( empty: every entry ), listed from just after `start_after`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexRange {
    pub prefix: Vec<u8>,
    pub start_after: Vec<u8>,
}

impl IndexRange {
    fn new(prefix: Vec<u8>) -> IndexRange {
        IndexRange { start_after: start_after(&prefix), prefix }
    }

    /// Whether an index key, and every key after it, is past the range.
    /// The listing starts below the prefix, so any key that does not start
    /// with it but sorts after it ends the range: in the ASCII region, the
    /// first instance or OLH entry ( 0x80 ) too.
    fn past(&self, key: &[u8]) -> bool {
        !self.prefix.is_empty() && !key.starts_with(&self.prefix) && key > self.prefix.as_slice()
    }
}

/// The greatest key below `prefix` that an index can hold, as an exclusive
/// start-after marker: the prefix with its last byte decremented and 0xff
/// appended.  Index keys are UTF-8 names ( RGW rejects others ) with ASCII
/// version suffixes, so none holds 0xff and none sorts between it and the
/// prefix.
fn start_after(prefix: &[u8]) -> Vec<u8> {
    let mut m = prefix.to_vec();
    match m.pop() {
        None | Some(0) => {}
        Some(b) => m.extend([b - 1, 0xff]),
    }
    m
}

/// An S3 name's index name ( rgw_obj_key::get_index_key_name ): a name
/// starting with '_' gets another.
fn index_name(name: &str) -> String {
    if name.starts_with('_') { format!("_{name}") } else { name.to_string() }
}

/// The index ranges that hold the entries of the S3 keys, as the scan names
/// them ( Options::covers: `name`, or `name[instance]` ), starting with
/// `prefix`: the plain entries under the prefix's index name ( a version's
/// entry adds "\0v<ver>\0i<instance>" after its name, cls_rgw's
/// get_list_index_key ); its uploads' meta and part entries, under
/// "_multipart_<key>.<upload>." ( a namespaced name is not escaped ); and,
/// for each '[' the prefix runs into, the versions of the name before it,
/// under "<name>\0v", whose "name[instance]" may start with the prefix.
/// No prefix: the whole index, as one range.
pub fn index_ranges(prefix: &str) -> Vec<IndexRange> {
    if prefix.is_empty() {
        return vec![IndexRange::default()];
    }
    let mut ranges = vec![names_range(prefix), IndexRange::new(uploads_prefix(prefix).into_bytes())];
    for (i, _) in prefix.match_indices('[').filter(|(i, _)| *i > 0) {
        let mut versions = index_name(&prefix[..i]).into_bytes();
        versions.extend(b"\0v");
        ranges.push(IndexRange::new(versions));
    }
    ranges
}

/// The index range of the plain entries of the names that start with
/// `prefix` ( the whole index, with none ): the keys a bucket listing of the
/// prefix reads, and their versions.
fn names_range(prefix: &str) -> IndexRange {
    if prefix.is_empty() { IndexRange::default() } else { IndexRange::new(index_name(prefix).into_bytes()) }
}

/// The index shard of a key: an index into shard_objects(), by rgw's
/// bucket_shard_index() of its name ( ceph_str_hash_linux, its low byte
/// mixed into its high one, mod a prime, mod the shards ).
pub fn shard_of(name: &str, num_shards: u64) -> usize {
    if num_shards == 0 {
        return 0;
    }
    let mut hash: u32 = 0;
    for &c in name.as_bytes() {
        let c = c as u32;
        hash = hash.wrapping_add(c << 4).wrapping_add(c >> 4).wrapping_mul(11);
    }
    let sid = hash ^ ((hash & 0xff) << 24);
    let prime = if num_shards <= 7877 { 7877 } else { 65521 };
    (u64::from(sid % prime) % num_shards) as usize
}

/// The index keys of the open uploads of the keys starting with `prefix`.
fn uploads_prefix(prefix: &str) -> String {
    format!("_multipart_{prefix}")
}

/// The index entries of ranges of one shard, a page at a time, through
/// cls_rgw's bi_list ( as radosgw-admin bi list reads them ): only the
/// listing's entries that `keep` keeps ( a scan's, those its prefix covers ),
/// not the versioned or OLH bookkeeping.  bi_list's name filter limits a
/// listing to one name and its instances ( list_plain_entries_help stops
/// past it ), so a range is its marker and a stop.  A call returns, after
/// its marker: the ASCII plain entries below 0x80, and once they run out
/// every instance entry ( 0x80 "1000_" ), every OLH entry ( 0x80 "1001_" ),
/// then the non-ASCII plain entries from 0x80 "9999_"; a marker in one of
/// those regions skips the regions before it ( rgw_bi_list_op ).
async fn shard_entries(
    engine: &Engine,
    placement: &str,
    oid: &str,
    ranges: &[IndexRange],
    keep: impl Fn(&DirEntry) -> bool,
    tx: &mpsc::Sender<Result<Vec<DirEntry>>>,
) -> Result<()> {
    for range in ranges {
        let mut marker = range.start_after.clone();
        loop {
            let out = engine
                .store
                .index_exec(placement, oid, "rgw", "bi_list", bi_list_op(&marker, 1000))
                .await?
                .with_context(|| format!("index shard {oid} does not exist"))?;
            let (page, truncated) = bi_list_ret(&out).with_context(|| format!("decoding bi_list of {oid}"))?;
            let Some((_, last, _)) = page.last() else { break };
            marker = last.clone();
            let mut done = !truncated;
            let mut entries = Vec::with_capacity(page.len());
            for (kind, idx, data) in page {
                if range.past(&idx) {
                    done = true;
                    break;
                }
                if kind != 1 {
                    continue;
                }
                match DirEntry::decode(&data) {
                    Ok(e) if keep(&e) => entries.push(e),
                    Ok(_) => {}
                    Err(e) => {
                        let key = String::from_utf8_lossy(&idx);
                        return Err(e.context(format!("decoding the index entry {key:?} of {oid}")));
                    }
                }
            }
            if tx.send(Ok(entries)).await.is_err() {
                return Ok(());
            }
            if done {
                break;
            }
        }
    }
    Ok(())
}

/// What to list for one index entry, as radoslist's process_bucket and
/// do_incomplete_multipart would.
enum Item {
    /// an S3 object: its head, and what the head's manifest names.  `live`:
    /// only if the head exists, as for an entry with ops in flight
    /// ( RGWRados::check_disk_state drops it from the listing otherwise )
    Object { key: Key, display: String, entry: Option<DirEntry>, live: bool },
    /// every stripe of the parts of the open upload whose meta object this is
    Parts { meta: String },
}

/// The items of a page of entries.  `olh`: the last key whose versions were
/// seen, whose shared head ( the OLH ) is listed once, as radoslist does.
/// A key has an OLH if it has an instance or a delete marker: a delete
/// marker is always linked through one, and under suspended versioning a
/// null one ( no instance ) leaves the OLH as its key's only object, which
/// radoslist stats as the entry's own key.  A null version's head is the
/// OLH itself, and is listed as its object.
fn items(entries: Vec<DirEntry>, olh: &mut Option<String>) -> Vec<Item> {
    let mut items = Vec::with_capacity(entries.len());
    for e in entries {
        if e.flags & FLAG_VER_MARKER != 0 {
            continue; // not a listing entry ( rgw_bucket_dir_entry::is_valid )
        }
        let key = e.key();
        let versioned = !e.instance.is_empty() || e.is_delete_marker();
        if versioned && olh.as_deref() != Some(key.name.as_str()) {
            *olh = Some(key.name.clone());
            let k = Key { name: key.name.clone(), instance: String::new(), ns: key.ns.clone() };
            items.push(Item::Object { display: k.name.clone(), key: k, entry: None, live: false });
        }
        // a delete marker has no head
        if e.is_delete_marker() {
            continue;
        }
        let meta = key.ns == "multipart" && key.name.ends_with(".meta");
        let live = !e.exists || e.pending > 0;
        items.push(Item::Object { key: key.clone(), display: e.display(), entry: Some(e), live });
        if meta {
            items.push(Item::Parts { meta: key.oid() });
        }
    }
    items
}

impl Engine {
    /// The seed of one S3 object: read its head's manifest, and walk it.
    async fn seed(&self, bucket: &str, marker: &str, key: Key, display: String, entry: Option<DirEntry>, live: bool) -> Option<Seed> {
        let head = RawName { oid: format!("{marker}_{}", key.oid()), loc: None };
        let mut seed = Seed::new(bucket, display, entry);
        seed.oids.push(head.oid.clone());
        let _permit = self.limiter.acquire().await;
        // an upload's meta object and its parts carry no manifest; the meta
        // object lives in the data-extra pool
        if !key.ns.is_empty() {
            if live {
                match self.store.locate(&head.oid, Pools::ExtraFirst).await {
                    Stat::Found { .. } => {}
                    Stat::Missing => return None,
                    Stat::Error(r) => seed.error = Some(format!("stat of {}: {}", head.oid, strerror(r))),
                }
            }
            return Some(seed);
        }
        let pool = match self.store.locate(&head.oid, Pools::Data).await {
            Stat::Found { pool, .. } => pool,
            // no head: the gap check reports it, as radoslist lists it
            Stat::Missing => return (!live).then_some(seed),
            // its manifest is unread, so its tail is unknown: an error, and
            // the gap check stats the head again
            Stat::Error(r) => {
                seed.error = Some(format!("stat of the head {}: {}; its tail is not checked", head.oid, strerror(r)));
                return Some(seed);
            }
        };
        seed.found.push((head.oid.clone(), pool));
        // one read for the manifest, and a Swift large object's segments
        let xattrs = match self.store.getxattrs(pool, &head.oid).await {
            Ok(x) => x.unwrap_or_default(),
            Err(err) => {
                seed.error = Some(format!("reading the manifest of {}: {err:#}", head.oid));
                return Some(seed);
            }
        };
        seed.segments = segments_of(&xattrs);
        let manifest = match xattrs.get(XATTR_MANIFEST).map(|bl| Manifest::decode(bl)) {
            Some(Ok(m)) => Some(m),
            Some(Err(err)) => {
                seed.error = Some(format!("the manifest of {} does not decode: {err:#}", head.oid));
                return Some(seed);
            }
            None => None,
        };
        match object_names(&head, manifest.as_ref()) {
            Ok(names) => {
                // the head first, then its tail, as radoslist names them
                let mut oids: Vec<String> = names.into_iter().map(|n| n.oid).filter(|o| *o != head.oid).collect();
                oids.insert(0, head.oid);
                seed.oids = oids;
            }
            Err(err) => seed.error = Some(format!("walking the manifest of {}: {err:#}", head.oid)),
        }
        Some(seed)
    }

    /// The stripes of an open upload's parts, from the part records in its
    /// meta object's omap.
    pub async fn parts_seed(&self, bucket: &str, marker: &str, meta: &str) -> Option<Seed> {
        let oid = format!("{marker}_{meta}");
        let _permit = self.limiter.acquire().await;
        let mut seed = Seed::new(bucket, String::new(), None);
        seed.parts = true;
        let pool = match self.store.locate(&oid, Pools::ExtraFirst).await {
            Stat::Found { pool, .. } => pool,
            // closed since it was listed
            Stat::Missing => return None,
            Stat::Error(r) => {
                seed.error = Some(format!("stat of {oid}: {}; its parts are not listed", strerror(r)));
                return Some(seed);
            }
        };
        let records = match self.store.omap_vals(pool, &oid, "part.").await {
            Ok(r) => r?,
            Err(err) => {
                seed.error = Some(format!("reading the parts of {oid}: {err:#}"));
                return Some(seed);
            }
        };
        for (name, record) in records {
            match Manifest::decode_part(&record).and_then(|m| m.locations()) {
                Ok(objs) => seed.oids.extend(objs.into_iter().map(|o| o.raw().oid)),
                Err(err) => seed.error = Some(format!("the {name} record of {oid} does not decode: {err:#}")),
            }
        }
        Some(seed)
    }

    /// The prefix the listing is limited to: the scan's, unless it finds
    /// orphans, which needs every reference, or reads refcounts, which needs
    /// every head: a copy outside the prefix carries references on the tail
    /// objects of one inside it ( RGWRados::copy_obj shares them, and
    /// carry_group reads them ).
    pub fn listing_prefix(&self) -> &str {
        match (&self.opts.match_prefix, self.partitions, self.opts.refcount) {
            (Some(p), None, false) => p,
            _ => "",
        }
    }

    /// Say once, as a scan starts, whether its prefix limits the listing.
    pub fn note_listing(&self) {
        let Some(p) = self.opts.match_prefix.as_deref().filter(|p| !p.is_empty()) else { return };
        if self.opts.listing == crate::scan::Listing::Radoslist {
            tracing::warn!("bucket radoslist takes no prefix: it lists whole buckets, and the scan drops the keys not under {p:?}");
        } else if self.listing_prefix().is_empty() {
            let why = if self.opts.refcount { "the refcount check needs" } else { "orphan detection needs" };
            tracing::info!("{why} every head: listing whole buckets, and dropping the keys not under {p:?}");
        } else {
            tracing::info!("listing only the index entries under {p:?}");
        }
    }

    /// The uploads the heads of a bucket's objects name, from a listing of
    /// every shard: for a scan whose listing is limited to a prefix or a
    /// shard, or did not read every head, and read only when an upload it
    /// holds seems named by none ( a copy outside the prefix or the shard
    /// shares the upload's tail, and names it ).  With
    /// them, the errors of the heads whose manifests could not be read: what
    /// those name is not known, so the naming is not complete.
    pub async fn uploads_named(&self, stats: &BucketStats) -> Result<(HashSet<String>, Vec<String>)> {
        let (placement, name, marker) = (stats.placement(), stats.name(), stats.marker.as_str());
        let (mut named, mut errors) = (HashSet::new(), Vec::new());
        for oid in shard_objects(stats, None) {
            let (tx, mut rx) = mpsc::channel(4);
            let (placement, oid) = (&placement, &oid);
            let list = async move {
                let r = shard_entries(self, placement, oid, &index_ranges(""), |_| true, &tx).await;
                drop(tx);
                r
            };
            let read = async {
                let mut olh = None;
                while let Some(page) = rx.recv().await {
                    let heads = items(page?, &mut olh).into_iter().filter_map(|item| match item {
                        Item::Object { key, display, entry, live } if key.ns.is_empty() => Some((key, display, entry, live)),
                        _ => None,
                    });
                    let work = heads.map(|(key, display, entry, live)| self.seed(&name, marker, key, display, entry, live));
                    let mut seeds = futures::stream::iter(work).buffer_unordered(256);
                    while let Some(seed) = seeds.next().await {
                        errors.extend(seed.as_ref().and_then(|s| s.error.clone()));
                        for o in seed.iter().flat_map(|s| &s.oids) {
                            let o = parse_oid(o);
                            if let (Some(upload), true) = (o.upload, o.kind.is_multipart()) {
                                named.insert(upload.to_string());
                            }
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            let (listed, read) = tokio::join!(list, read);
            listed.and(read)?;
        }
        Ok((named, errors))
    }

    /// The seeds of a bucket's objects, from its index: every shard, or one;
    /// with a listing prefix, only the index ranges of the keys under it,
    /// in each shard, since keys hash to shards by their whole name.
    /// Delete markers have no head, and are left out ( their key's OLH is not ).
    /// The segments of the Swift large objects it lists are followed into
    /// their buckets, a batch at a time, but those the scan checks there.
    pub fn native_seeds(self: &Arc<Self>, stats: BucketStats, shard: Option<u32>) -> mpsc::Receiver<Result<Seed>> {
        let (tx, rx) = mpsc::channel(4096);
        let engine = self.clone();
        tokio::spawn(async move {
            let placement = stats.placement();
            let name = stats.name();
            let marker = stats.marker.as_str();
            let prefix = engine.listing_prefix().to_string();
            let mut follow = Follow::default();
            for oid in shard_objects(&stats, shard) {
                let (etx, mut erx) = mpsc::channel(4);
                let lister = {
                    let (engine, placement, oid, prefix) = (engine.clone(), placement.clone(), oid.clone(), prefix.clone());
                    tokio::spawn(async move {
                        // a limited listing is the scan's prefix: keep what it covers
                        let keep = |e: &DirEntry| prefix.is_empty() || e.display().starts_with(&prefix);
                        if let Err(e) = shard_entries(&engine, &placement, &oid, &index_ranges(&prefix), keep, &etx).await {
                            let _ = etx.send(Err(e)).await;
                        }
                    })
                };
                // a key's versions are together in its shard, and in one range
                let mut olh = None;
                while let Some(page) = erx.recv().await {
                    let entries = match page {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    };
                    let work = items(entries, &mut olh).into_iter().map(|item| {
                        let (engine, name) = (&engine, &name);
                        async move {
                            match item {
                                Item::Object { key, display, entry, live } => engine.seed(name, marker, key, display, entry, live).await,
                                Item::Parts { meta } => engine.parts_seed(name, marker, &meta).await,
                            }
                        }
                    });
                    // every seed of the page read before any is sent: a seed
                    // holds a limiter permit while it reads, and one left
                    // unpolled while this waits on the receiver ( whose checks
                    // take permits ) or follows segments would starve them
                    let seeds: Vec<Option<Seed>> = futures::stream::iter(work).buffer_unordered(256).collect().await;
                    for mut seed in seeds.into_iter().flatten() {
                        seed.shard = Some(oid.clone());
                        engine.take_segments(&stats, &mut seed, &mut follow, 0);
                        if tx.send(Ok(seed)).await.is_err() {
                            return;
                        }
                        // a batch at a time, so a bucket of large objects is not held
                        if follow.pending.len() >= FOLLOW_BATCH && !engine.follow(&stats, &mut follow, &tx).await {
                            return;
                        }
                    }
                }
                let _ = lister.await;
            }
            engine.follow(&stats, &mut follow, &tx).await;
        });
        rx
    }

    /// Take the segments a seed's head names to follow, if the scan covers
    /// it ( or it is a segment followed ): those the scan does not check
    /// where they are, and has not taken yet.  `depth`: the seed's, in large
    /// objects followed.  What cannot be followed is its error, or a tally;
    /// what the unit relied on other buckets for, noted ( Segments::depends ).
    fn take_segments(&self, unit: &BucketStats, seed: &mut Seed, follow: &mut Follow, depth: u32) {
        let segments = std::mem::take(&mut seed.segments);
        if segments.is_empty() || (seed.followed.is_none() && !self.opts.covers(&seed.key)) {
            return;
        }
        let of = format!("s3://{}/{}", seed.bucket, seed.key);
        let (own, mut on) = (unit.name(), Depends::default());
        for segment in segments {
            let id = match &segment {
                Segment::Prefix { container, prefix } if !self.checks_there(unit, container, prefix) => format!("P\0{container}\0{prefix}"),
                Segment::Key { container, key } if !self.checks_there(unit, container, key) => format!("S\0{container}\0{key}"),
                Segment::Prefix { container, .. } | Segment::Key { container, .. } => {
                    let there = segment_bucket(unit, container);
                    if there != own {
                        on.left_to.insert(there);
                    }
                    continue;
                }
                Segment::Undecodable(e) => {
                    // whatever they are, a scan of every bucket and key checks them there
                    if !self.scans_everything() {
                        seed.error.get_or_insert_with(|| format!("{of}: its SLO manifest does not decode: {e}; its segments are not checked"));
                    }
                    continue;
                }
                Segment::Nameless(path) => {
                    tracing::warn!("{of}: its manifest's path {path:?} names no object");
                    seed.skipped = Some(SKIP_NAMELESS_SEGMENT);
                    continue;
                }
            };
            on.followed = true;
            if depth >= FOLLOW_DEPTH {
                seed.skipped = Some(SKIP_NESTED_SEGMENTS);
            } else if follow.first(id) {
                follow.pending.push(Pending { of: of.clone(), segment, depth: depth + 1 });
            }
        }
        self.segments.relies(own, on);
    }

    /// Whether the scan lists every bucket and every key: finds orphans, or
    /// lists every bucket with no prefix.
    fn scans_everything(&self) -> bool {
        self.opts.orphans || (self.opts.every_bucket && self.opts.match_prefix.is_none())
    }

    /// Whether the scan lists a bucket itself: the unit's own ( each of its
    /// shards is a unit ), one it names, or any when it lists every one.
    fn lists(&self, unit: &BucketStats, bucket: &str) -> bool {
        self.opts.orphans || self.opts.every_bucket || bucket == unit.name() || self.segments.named.get().is_some_and(|n| n.contains(bucket))
    }

    /// Whether the scan checks where they are all the keys that start with
    /// `under` in a container of the unit's tenant: in a bucket it lists,
    /// under its prefix.
    fn checks_there(&self, unit: &BucketStats, container: &str, under: &str) -> bool {
        self.lists(unit, &segment_bucket(unit, container)) && self.opts.covers(under)
    }

    /// Follow the pending segments into their buckets, send their seeds, and
    /// follow those they name in turn, a batch at a time, until none is
    /// left: `seen` and FOLLOW_DEPTH end a manifest loop.  False if the
    /// receiver went away.  As the listing does, it waits on the receiver
    /// only with every seed it read in hand.
    async fn follow(&self, unit: &BucketStats, follow: &mut Follow, tx: &mpsc::Sender<Result<Seed>>) -> bool {
        while !follow.pending.is_empty() {
            let batch = follow.pending.split_off(follow.pending.len().saturating_sub(FOLLOW_BATCH));
            let mut keys = Vec::new();
            for p in batch {
                let container = match &p.segment {
                    Segment::Prefix { container, .. } | Segment::Key { container, .. } => container,
                    Segment::Undecodable(_) | Segment::Nameless(_) => continue,
                };
                let name = segment_bucket(unit, container);
                // the listing asks once of a bucket whose stats it could not read
                if follow.seen.contains(&failed_bucket(&name)) {
                    continue;
                }
                let bucket = match self.bucket_to_follow(unit, &name, &p.of).await {
                    Ok(b) => Arc::new(b),
                    Err((id, note)) => {
                        if follow.first(id) && tx.send(Ok(note)).await.is_err() {
                            return false;
                        }
                        continue;
                    }
                };
                match &p.segment {
                    Segment::Prefix { .. } => {
                        if !self.follow_prefix(unit, &bucket, &p, follow, tx).await {
                            return false;
                        }
                    }
                    Segment::Key { key, .. } => keys.push((bucket, key.clone(), p.of, p.depth)),
                    Segment::Undecodable(_) | Segment::Nameless(_) => {}
                }
            }
            if !self.follow_keys(unit, keys, follow, tx).await {
                return false;
            }
        }
        true
    }

    /// The bucket a large object ( `of` ) keeps segments in, to follow them
    /// there; or why not, a note to send once a listing ( and its id ): one
    /// that does not exist is a tally for each large object, one that cannot
    /// be read an error.
    async fn bucket_to_follow(&self, unit: &BucketStats, name: &str, of: &str) -> Result<SegmentBucket, (String, Seed)> {
        let error = |why: String| (failed_bucket(name), Seed::note(name, Some(format!("{why}; the Swift large objects' segments in {name} are not checked")), None));
        let stats = match self.segment_stats(name).await {
            Ok(Some(s)) => s,
            Ok(None) => return Err((format!("N\0{name}\0{of}"), Seed::note(name, None, Some(SKIP_NO_SEGMENT_BUCKET)))),
            Err(e) => return Err(error(e)),
        };
        if !stats.index_type.is_empty() && stats.index_type != "Normal" {
            return Err(error(format!("the index of {name} is {}", stats.index_type)));
        }
        Ok(SegmentBucket { name: name.to_string(), stats, scanned: self.lists(unit, name) })
    }

    /// The stats of a bucket segments are followed into, read once a scan;
    /// None if there is no such bucket.  An error is not kept: one failure
    /// ( a timeout, say ) would leave every later unit's segments there
    /// unchecked, for the whole scan.
    async fn segment_stats(&self, bucket: &str) -> Result<Option<Arc<BucketStats>>, String> {
        let cell = self.segments.stats.lock().unwrap().entry(bucket.to_string()).or_default().clone();
        cell.get_or_try_init(|| async {
            let stats = self.admin.find_bucket_stats(bucket).await.map_err(|e| format!("{e:#}"))?;
            if stats.is_none() {
                // as radoslist warns of it
                tracing::warn!("bucket {bucket} does not exist: the segments Swift large objects keep there are not checked");
            }
            Ok(stats.map(Arc::new))
        })
        .await
        .cloned()
    }

    /// Whether a bucket segments are followed into has an
    /// AbortIncompleteMultipartUpload rule; read once a scan.
    pub async fn segment_lc_mp(&self, bucket: &str) -> bool {
        let cell = self.segments.lc_mp.lock().unwrap().entry(bucket.to_string()).or_default().clone();
        *cell.get_or_init(|| self.admin.has_mp_expiration(bucket)).await
    }

    /// Follow a DLO's segments: the keys under its prefix in each shard of
    /// their bucket, in the range a listing of the prefix reads, a page at a
    /// time.  False if the receiver went away.
    async fn follow_prefix(&self, unit: &BucketStats, bucket: &Arc<SegmentBucket>, p: &Pending, follow: &mut Follow, tx: &mpsc::Sender<Result<Seed>>) -> bool {
        let (Segment::Prefix { prefix, .. }, of, depth) = (&p.segment, &p.of, p.depth) else { return true };
        let placement = bucket.stats.placement();
        let ranges = [names_range(prefix)];
        for oid in shard_objects(&bucket.stats, None) {
            let (etx, mut erx) = mpsc::channel(4);
            let (placement, ranges, oid) = (&placement, &ranges, &oid);
            let list = async move {
                // what a GET of the DLO reads: a bucket listing of the prefix
                let keep = |e: &DirEntry| {
                    let k = e.key();
                    k.ns.is_empty() && k.name.starts_with(prefix)
                };
                let r = shard_entries(self, placement, oid, ranges, keep, &etx).await;
                drop(etx);
                r
            };
            let read = {
                let follow = &mut *follow;
                async move {
                    let mut olh = None;
                    while let Some(page) = erx.recv().await {
                        let Ok(entries) = page else { continue };
                        let entries = entries.into_iter().filter(|e| !(bucket.scanned && self.opts.covers(&e.display()))).collect();
                        let items = items(entries, &mut olh).into_iter().map(|i| (bucket.clone(), oid.clone(), i, depth)).collect();
                        for (mut seed, depth) in self.followed_seeds(items, follow).await {
                            self.take_segments(unit, &mut seed, follow, depth);
                            if tx.send(Ok(seed)).await.is_err() {
                                return false;
                            }
                        }
                    }
                    true
                }
            };
            let (listed, sent) = tokio::join!(list, read);
            if !sent {
                return false;
            }
            if let Err(e) = listed {
                let why = format!("listing {} under {prefix:?}, for {of}: {e:#}; the segments it did not list are not checked", bucket.name);
                if follow.first(format!("E\0{why}")) && tx.send(Ok(Seed::note(&bucket.name, Some(why), None))).await.is_err() {
                    return false;
                }
            }
        }
        true
    }

    /// Follow SLOs' segments: each key's entries from the index shard it
    /// hashes to, all read, then their seeds, all read, then sent.  False if
    /// the receiver went away.
    async fn follow_keys(
        &self,
        unit: &BucketStats,
        keys: Vec<(Arc<SegmentBucket>, String, String, u32)>,
        follow: &mut Follow,
        tx: &mpsc::Sender<Result<Seed>>,
    ) -> bool {
        let found: Vec<_> = futures::stream::iter(keys)
            .map(|(bucket, key, of, depth)| async move {
                let r = self.key_entries(&bucket.stats, &key).await;
                (bucket, key, of, depth, r)
            })
            .buffer_unordered(64)
            .collect()
            .await;
        let mut listed = Vec::new();
        for (bucket, key, of, depth, r) in found {
            match r {
                Ok((oid, entries)) => {
                    let entries = entries.into_iter().filter(|e| !(bucket.scanned && self.opts.covers(&e.display()))).collect();
                    listed.extend(items(entries, &mut None).into_iter().map(|i| (bucket.clone(), oid.clone(), i, depth)));
                }
                Err(e) => {
                    // once a listing for each failure: a shard that cannot be read fails each key in it
                    let why = format!("{e:#}");
                    let note = format!("reading the index of {} for the segment {key:?} of {of}, and of any other segments it fails for: {why}; they are not checked", bucket.name);
                    if follow.first(format!("E\0{}\0{why}", bucket.name)) && tx.send(Ok(Seed::note(&bucket.name, Some(note), None))).await.is_err() {
                        return false;
                    }
                }
            }
        }
        for (mut seed, depth) in self.followed_seeds(listed, follow).await {
            self.take_segments(unit, &mut seed, follow, depth);
            if tx.send(Ok(seed)).await.is_err() {
                return false;
            }
        }
        true
    }

    /// The seeds of the items of segments followed into their buckets ( each
    /// with its bucket, shard and depth ), but those the listing has sent:
    /// all read, so the caller can send them holding no limiter permit.
    async fn followed_seeds(&self, items: Vec<(Arc<SegmentBucket>, String, Item, u32)>, follow: &mut Follow) -> Vec<(Seed, u32)> {
        let work: Vec<_> = items
            .into_iter()
            .filter_map(|(bucket, oid, item, depth)| match item {
                Item::Object { key, display, entry, live } if follow.first(format!("K\0{}\0{display}", bucket.name)) => {
                    Some((bucket, oid, key, display, entry, live, depth))
                }
                // an upload's, which no segment is
                _ => None,
            })
            .collect();
        futures::stream::iter(work)
            .map(|(bucket, oid, key, display, entry, live, depth)| async move {
                let mut seed = self.seed(&bucket.name, &bucket.stats.marker, key, display, entry, live).await?;
                seed.shard = Some(oid);
                seed.followed = Some(bucket.stats.placement());
                Some((seed, depth))
            })
            .buffer_unordered(256)
            .filter_map(futures::future::ready)
            .collect()
            .await
    }

    /// The listing entries of one key ( its versions too ), from the index
    /// shard it hashes to, and that shard.
    async fn key_entries(&self, stats: &BucketStats, key: &str) -> Result<(String, Vec<DirEntry>)> {
        let placement = stats.placement();
        let shards = shard_objects(stats, None);
        let oid = shards.get(shard_of(key, stats.num_shards)).with_context(|| format!("no index shard of {key:?} among {}", shards.len()))?.clone();
        let name = index_name(key);
        let (mut marker, mut entries) = (Vec::new(), Vec::new());
        loop {
            let out = {
                let _permit = self.limiter.acquire().await;
                self.store.index_exec(&placement, &oid, "rgw", "bi_list", bi_list_named_op(&name, &marker, 1000)).await?
            };
            let out = out.with_context(|| format!("index shard {oid} does not exist"))?;
            let (page, truncated) = bi_list_ret(&out).with_context(|| format!("decoding bi_list of {oid}"))?;
            for (kind, _, data) in &page {
                if *kind != 1 {
                    continue;
                }
                let e = DirEntry::decode(data).with_context(|| format!("decoding an index entry of {name:?} in {oid}"))?;
                if e.name == name {
                    entries.push(e);
                }
            }
            match page.last() {
                Some((_, last, _)) if truncated => marker = last.clone(),
                _ => return Ok((oid, entries)),
            }
        }
    }
}

/// Group radoslist's lines into seeds: it names one object's RADOS objects together.
pub fn radoslist_seeds(mut lines: mpsc::Receiver<Result<(String, String, String)>>) -> mpsc::Receiver<Result<Seed>> {
    let (tx, rx) = mpsc::channel(4096);
    tokio::spawn(async move {
        let mut cur: Option<Seed> = None;
        while let Some(line) = lines.recv().await {
            let (oid, bucket, key) = match line {
                Ok(l) => l,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };
            if cur.as_ref().is_none_or(|s| s.bucket != bucket || s.key != key) {
                if let Some(s) = cur.take() {
                    if tx.send(Ok(s)).await.is_err() {
                        return;
                    }
                }
                // do_incomplete_multipart's lines name no key
                let mut seed = Seed::new(&bucket, key, None);
                seed.parts = seed.key.is_empty();
                cur = Some(seed);
            }
            cur.as_mut().expect("set above").oids.push(oid);
        }
        if let Some(s) = cur {
            let _ = tx.send(Ok(s)).await;
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::admin::Admin;
    use crate::decode::FLAG_DELETE_MARKER;
    use crate::decode::enc::{dir_entry_of, multipart_manifest};
    use crate::finding::{Catalog, Context};
    use crate::scan::Options;
    use crate::store::{MockObject, MockStore, bi_list};

    // rgw_bucket_dir_entry's flags: FLAG_VER, FLAG_CURRENT
    const VER: u16 = 0x1;
    const CUR: u16 = 0x2;

    fn e(name: &str, instance: &str, flags: u16) -> DirEntry {
        DirEntry::decode(&dir_entry_of(name, instance, flags)).unwrap()
    }

    /// each item as `obj <oid>` ( `+` when it has its entry ) or `parts <meta>`
    fn listed(entries: Vec<DirEntry>) -> Vec<String> {
        let mut olh = None;
        items(entries, &mut olh)
            .into_iter()
            .map(|i| match i {
                Item::Object { key, entry, .. } => format!("obj {}{}", key.oid(), if entry.is_some() { "+" } else { "" }),
                Item::Parts { meta } => format!("parts {meta}"),
            })
            .collect()
    }

    #[test]
    fn null_delete_marker_olh() {
        // suspended versioning, PUT k then DELETE k: the placeholder and a
        // null delete marker, and the OLH <marker>_k left behind
        let dm = VER | CUR | FLAG_DELETE_MARKER;
        assert_eq!(listed(vec![e("k", "", FLAG_VER_MARKER), e("k", "", dm)]), ["obj k"]);
        // with older versions too: the OLH once
        assert_eq!(listed(vec![e("k", "", FLAG_VER_MARKER), e("k", "", dm), e("k", "v1", VER)]), ["obj k", "obj _:v1_k+"]);
        assert_eq!(listed(vec![e("k", "v1", VER | CUR), e("k", "", VER | FLAG_DELETE_MARKER)]), ["obj k", "obj _:v1_k+"]);
        // an instanced delete marker: its OLH, and no head
        assert_eq!(listed(vec![e("k", "v2", dm)]), ["obj k"]);
    }

    #[test]
    fn shards_of_keys() {
        // as Ceph's bucket_shard_index() puts them, for 11, 3, 7877 and 7878 shards
        for (key, want) in [
            ("s1", [5, 1, 3976, 781]),
            ("s2", [3, 0, 4656, 3109]),
            ("segs/p/1", [8, 0, 1152, 2944]),
            ("_under", [2, 0, 7614, 6408]),
            ("\u{e9}t\u{e9}", [9, 2, 6290, 2288]),
        ] {
            let got = [11, 3, 7877, 7878].map(|n| shard_of(key, n));
            assert_eq!(got, want, "{key}");
        }
        // an unsharded index, and one of one shard
        assert_eq!((shard_of("s1", 0), shard_of("s1", 1)), (0, 0));
    }

    #[test]
    fn large_object_segments() {
        let xattrs = |pairs: &[(&str, &[u8])]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect::<HashMap<_, _>>();
        let slo = crate::decode::enc::slo_info(&["/segs/s1", "bad", "segs/s%202"]);
        let key = |k: &str| Segment::Key { container: "segs".into(), key: k.into() };
        let segments = segments_of(&xattrs(&[(XATTR_SLO_MANIFEST, &slo)]));
        assert_eq!(segments, [key("s1"), Segment::Nameless("bad".into()), key("s%202")]);
        // a GET reads the DLO's segments first
        let segments = segments_of(&xattrs(&[(XATTR_SLO_MANIFEST, &slo), (XATTR_USER_MANIFEST, b"c/p\0")]));
        assert_eq!(segments, [Segment::Prefix { container: "c".into(), prefix: "p".into() }]);
        assert_eq!(segments_of(&xattrs(&[(XATTR_USER_MANIFEST, b"nocontainer\0")])), [Segment::Nameless("nocontainer".into())]);
        assert!(matches!(segments_of(&xattrs(&[(XATTR_SLO_MANIFEST, b"\x01")]))[..], [Segment::Undecodable(_)]));
        assert_eq!(segments_of(&xattrs(&[(XATTR_MANIFEST, b"")])), []);
    }

    /// Bucket m ( IDM, marker MM ): an SLO, big, of two segments in segs
    /// ( IDS, marker MS, unsharded ), s1 and s2; s2's head is missing.
    fn slo_store() -> MockStore {
        let entry = |name: &str| DirEntry { name: name.into(), exists: true, mtime: 1577836800, etag: "E".into(), ..Default::default() };
        let mut store = MockStore::new(1, 0);
        store.shards.insert(".dir.IDM".into(), vec![entry("big")]);
        let slo = crate::decode::enc::slo_info(&["/segs/s1", "/segs/s2"]);
        store.put(0, "MM_big", MockObject { mtime: 1000, xattrs: [(XATTR_SLO_MANIFEST.to_string(), slo)].into(), ..Default::default() });
        store.shards.insert(".dir.IDS".into(), vec![entry("s1"), entry("s2")]);
        store.put(0, "MS_s1", MockObject::default());
        store
    }

    /// A failure to read the stats of a bucket segments are in is that
    /// listing's error, asked once however many segments are there; it is
    /// not kept, so the next unit asks again, and checks them.
    #[cfg(unix)]
    #[tokio::test]
    async fn segment_stats_failures_are_not_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-segstats-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("segs"), r#"{"bucket": "segs", "id": "IDS", "marker": "MS"}"#).unwrap();
        // each bucket stats of segs counted; the first times out
        let script = r#"#!/bin/sh
d=$(dirname "$0")
case "$*" in
'bucket stats --bucket=segs') echo >> "$d/calls"; if [ "$(wc -l < "$d/calls")" -eq 1 ]; then echo 'ERROR: timed out' >&2; exit 110; fi; cat "$d/segs" ;;
*) exit 1 ;;
esac
"#;
        let program = dir.join("radosgw-admin");
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (e, _) = engine_of(slo_store(), Options { uploads: false, ..Default::default() });
        let mut e = Arc::into_inner(e).expect("unshared");
        e.admin = Arc::new(Admin::new(program.display().to_string(), None, None, crate::admin::DEFAULT_CONCURRENCY));
        let e = Arc::new(e);
        let m: BucketStats = serde_json::from_value(serde_json::json!({ "bucket": "m", "id": "IDM", "marker": "MM" })).unwrap();
        let calls = || std::fs::read_to_string(dir.join("calls")).unwrap().lines().count();
        let r = e.scan_bucket("m", Some(m.clone())).await.unwrap();
        assert_eq!(r.errors.len(), 1, "{:?}", r.errors);
        assert!(r.errors[0].contains("timed out") && r.errors[0].ends_with("segments in segs are not checked"), "{:?}", r.errors);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(calls(), 1, "asked once for both segments");
        let r = e.scan_bucket("m", Some(m.clone())).await.unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.missing, ["s3://segs/s2 MISSING MS_s2"]);
        // the stats read, kept
        let _ = e.scan_bucket("m", Some(m)).await.unwrap();
        assert_eq!(calls(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A key written before versioning, with a version since: the null
    /// version's head is the OLH, which radoslist lists twice ( as the OLH,
    /// and as the null version ), so its objects count twice, as there; but
    /// its lost tail is one gap and MISSING line each ( rgw-gap-list writes
    /// two, a server's gap list keeps one ), and one finding.
    #[tokio::test]
    async fn null_version_found_once() {
        let st: BucketStats = serde_json::from_value(serde_json::json!({ "bucket": "b", "id": "B.1", "marker": "M.1" })).unwrap();
        let entry = |instance: &str, flags: u16| DirEntry { name: "k".into(), instance: instance.into(), exists: true, flags, mtime: 1000, ..Default::default() };
        let mut store = MockStore::new(1, 0);
        store.shards.insert(".dir.B.1".into(), vec![entry("", FLAG_VER_MARKER), entry("v2", VER | CUR), entry("", VER)]);
        let manifest = multipart_manifest("M.1", "k", "k.2~u", 2);
        store.put(0, "M.1_k", MockObject { mtime: 1000, xattrs: [(XATTR_MANIFEST.to_string(), manifest)].into(), ..Default::default() });
        store.put(0, "M.1__:v2_k", MockObject { mtime: 1000, ..Default::default() });
        let (e, _) = engine_of(store, Options { uploads: false, ..Default::default() });
        let r = e.scan_bucket("b", Some(st)).await.unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let mut missing = r.missing.clone();
        missing.sort();
        let line = |part: u32| format!("s3://b/k MISSING M.1__multipart_k.2~u.{part}");
        assert_eq!(missing, [line(1), line(2)]);
        assert_eq!(r.gaps, 2);
        let found: Vec<(&str, &str)> = r.findings.iter().map(|f| (f.check.as_str(), f.key.as_deref().unwrap_or(""))).collect();
        assert_eq!(found, [("missing_data", "k")]);
        assert_eq!(r.tally.classes.values().sum::<u64>(), 1, "{:?}", r.tally.classes);
    }

    #[test]
    fn no_olh_invented() {
        // an unversioned object, and a null version whose head is its OLH
        assert_eq!(listed(vec![e("k", "", 0)]), ["obj k+"]);
        assert_eq!(listed(vec![e("k", "", FLAG_VER_MARKER), e("k", "", VER | CUR)]), ["obj k+"]);
        // the next key's delete marker lists its own OLH
        assert_eq!(listed(vec![e("a", "", 0), e("b", "", VER | CUR | FLAG_DELETE_MARKER)]), ["obj a+", "obj b"]);
    }

    /// S3 keys, and the instances ( and flags ) of the versioned ones
    const KEYS: &[(&str, &[(&str, u16)])] = &[
        ("a", &[]),
        ("l", &[]),
        ("log", &[]),
        ("logs", &[("n1", VER | CUR)]),
        ("logs.", &[]),
        ("logs.1", &[]),
        ("logs.v", &[("i1", VER | CUR), ("i2", VER)]),
        ("logs/", &[]),
        ("logs/a", &[]),
        ("logs/a/b", &[]),
        ("logs/ab", &[]),
        ("logs/b", &[]),
        ("logs/n", &[("", VER | CUR | FLAG_DELETE_MARKER)]),
        ("logs/v", &[("i1", VER | CUR), ("i2", VER), ("i3", VER | FLAG_DELETE_MARKER)]),
        ("logs/v/w", &[("j1", VER | CUR)]),
        ("logs0", &[]),
        ("logs[", &[]),
        ("_", &[]),
        ("_hidden", &[]),
        ("_hidden/x", &[("k1", VER | CUR)]),
        ("__x", &[]),
        ("_multipart_fake.2~u.meta", &[]),
        ("zz", &[]),
        ("~", &[]),
        ("\u{7f}", &[]),
        ("è", &[]),
        ("é", &[]),
        ("é/1", &[]),
        ("é/v", &[("m1", VER | CUR), ("m2", VER)]),
        ("ê", &[]),
        ("日", &[]),
        ("日本", &[]),
        ("日本/x", &[]),
        ("日本語", &[]),
        ("\u{10ffff}", &[]),
    ];
    /// the keys of open uploads
    const UPLOADS: &[&str] = &["logs/a", "logs/big", "logs.big", "_hidden/mp", "é/mp", "日本/mp", "l"];

    const PREFIXES: &[&str] = &[
        "", "l", "lo", "log", "logs", "logs.", "logs/", "logs/a", "logs/a/", "logs/a.", "logs/a.2~up0", "logs/v", "logs/v/", "logs/big", "logs/n",
        "logs[", "logs[n", "logs/v[", "logs/v[i", "logs/v[i3", "logs/v/w[", "logs.v[i2", "logs/n[", "_", "__", "_h", "_hidden", "_hidden/x",
        "_hidden/x[k", "_multipart_", "_multipart_fake", "a", "l.2~up6.m", "zz", "zzz", "~", "\u{7f}", "è", "é", "é/", "é/v", "é/v[m", "ê", "日",
        "日本", "日本/", "日本語", "\u{10ffff}", "\u{10fffe}", "e\u{301}", "nomatch",
    ];

    fn special(region: &str, rest: &[&[u8]]) -> Vec<u8> {
        [&[0x80u8][..], region.as_bytes()].into_iter().chain(rest.iter().copied()).collect::<Vec<&[u8]>>().concat()
    }

    /// Two index shards' omaps as cls_rgw keeps them: plain entries ( a
    /// versioned key's placeholder under its name, and its versions' under
    /// "\0v<ver>\0i<instance>" after it ), the instance and OLH entries of
    /// versions, the uploads' entries, and some of the bucket and reshard logs.
    fn shards() -> [BTreeMap<Vec<u8>, Vec<u8>>; 2] {
        let mut shards = [BTreeMap::new(), BTreeMap::new()];
        for (i, (key, versions)) in KEYS.iter().enumerate() {
            let (name, omap) = (index_name(key), &mut shards[i % 2]);
            if versions.is_empty() {
                omap.insert(name.clone().into_bytes(), dir_entry_of(&name, "", 0));
            } else {
                omap.insert(name.clone().into_bytes(), dir_entry_of(&name, "", FLAG_VER_MARKER));
                omap.insert(special("1001_", &[name.as_bytes()]), b"olh".to_vec());
            }
            for (j, (instance, flags)) in versions.iter().enumerate() {
                let listed = format!("{name}\0v{:03}\0i{instance}", 999 - j);
                omap.insert(listed.into_bytes(), dir_entry_of(&name, instance, *flags));
                omap.insert(special("1000_", &[name.as_bytes(), b"\0i", instance.as_bytes()]), b"instance".to_vec());
            }
        }
        for (i, key) in UPLOADS.iter().enumerate() {
            let base = format!("_multipart_{key}.2~up{i}");
            for suffix in ["meta", "1", "2"] {
                let name = format!("{base}.{suffix}");
                shards[i % 2].insert(name.clone().into_bytes(), dir_entry_of(&name, "", 0));
            }
        }
        for omap in &mut shards {
            omap.insert(special("0_", &[b"00000000001.1.2"]), b"log".to_vec());
            omap.insert(special("2001_", &[b"resharding"]), b"reshard".to_vec());
        }
        shards
    }

    fn stats() -> BucketStats {
        serde_json::from_value(serde_json::json!({ "bucket": "b", "id": "B.1", "marker": "M.1", "num_shards": 2 })).expect("stats")
    }

    /// the head of "zz", a copy of the object completed from upload 1
    /// ( "logs/big" ): it names that upload's tail
    const COPY: (&str, &str) = ("M.1_zz", "logs/big.2~up1");

    /// A store of the shards, whose bi_list pages hold at most `max`, with
    /// the uploads' meta objects ( whose part records do not decode, and
    /// that list a part more than their index entries ), and the head of
    /// the copy.
    fn store(max: u32) -> MockStore {
        let mut store = MockStore::new(1, 1);
        store.bi = shard_objects(&stats(), None).into_iter().zip(shards()).collect();
        store.bi_max = max;
        for (i, key) in UPLOADS.iter().enumerate() {
            let meta = MockObject { omap: vec!["part.1".into(), "part.2".into(), "part.3".into()], ..Default::default() };
            store.put(1, &format!("M.1__multipart_{key}.2~up{i}.meta"), meta);
        }
        let manifest = multipart_manifest("M.1", "zz", COPY.1, 2);
        store.put(0, COPY.0, MockObject { mtime: 1000, xattrs: [(XATTR_MANIFEST.to_string(), manifest)].into(), ..Default::default() });
        store
    }

    fn engine_of(store: MockStore, opts: Options) -> (Arc<Engine>, Arc<MockStore>) {
        let store = Arc::new(store);
        let engine = Engine {
            store: store.clone(),
            admin: Arc::new(Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY)),
            ctx: Arc::new(Context { catalog: Catalog::builtin(), ..Default::default() }),
            gc: RwLock::default(),
            gc_min_wait: 0,
            limiter: crate::limiter::Limiter::new(8),
            opts,
            partitions: None,
            segments: Default::default(),
        };
        (Arc::new(engine), store)
    }

    /// An engine over the store of the shards, listing under `prefix`.
    fn engine(prefix: Option<&str>, max: u32) -> (Arc<Engine>, Arc<MockStore>) {
        engine_of(store(max), Options { match_prefix: prefix.map(str::to_string), ..Default::default() })
    }

    type Row = (String, Vec<String>, Option<(String, String)>);

    /// The seeds of a native listing, in order.
    async fn seeds(engine: &Arc<Engine>) -> Vec<(Row, Seed)> {
        let mut rx = engine.native_seeds(stats(), None);
        let mut out = Vec::new();
        while let Some(s) = rx.recv().await {
            let s = s.expect("listing");
            let entry = s.entry.as_ref().map(|e| (e.name.clone(), e.instance.clone()));
            out.push(((s.key.clone(), s.oids.clone(), entry), s));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    #[test]
    fn ranges() {
        assert_eq!(index_ranges(""), vec![IndexRange::default()]);
        let r = |p: &[u8], m: &[u8]| IndexRange { prefix: p.to_vec(), start_after: m.to_vec() };
        assert_eq!(index_ranges("logs/"), vec![r(b"logs/", b"logs.\xff"), r(b"_multipart_logs/", b"_multipart_logs.\xff")]);
        // a name starting with '_' is escaped; an upload's is not
        assert_eq!(index_ranges("_tmp"), vec![r(b"__tmp", b"__tmo\xff"), r(b"_multipart__tmp", b"_multipart__tmo\xff")]);
        assert_eq!(index_ranges("_"), vec![r(b"__", b"_^\xff"), r(b"_multipart__", b"_multipart_^\xff")]);
        // non-ASCII, in the high region: the last byte of a multi-byte
        // character decremented
        assert_eq!(index_ranges("é")[0], r("é".as_bytes(), b"\xc3\xa8\xff"));
        assert_eq!(index_ranges("日")[0], r("日".as_bytes(), b"\xe6\x97\xa4\xff"));
        assert_eq!(index_ranges("a")[0], r(b"a", b"`\xff"));
        assert_eq!(start_after(b"a\0"), b"a");
        assert_eq!(start_after(b"\0"), b"");
        // a prefix that runs into "[": the versions of the name before it too
        assert_eq!(index_ranges("logs/v[i")[2..], [r(b"logs/v\0v", b"logs/v\0u\xff")]);
        assert_eq!(index_ranges("_a[b[c")[2..], [r(b"__a\0v", b"__a\0u\xff"), r(b"__a[b\0v", b"__a[b\0u\xff")]);
        assert_eq!(index_ranges("[x").len(), 2, "no name is empty");
        // a DLO's keys: the first range alone
        assert_eq!(names_range("_tmp"), index_ranges("_tmp")[0]);
        assert_eq!(names_range(""), IndexRange::default());
        // the end of a range: a key past the prefix, not one below it
        let logs = &index_ranges("logs/")[0];
        assert!(!logs.past(b"logs/"));
        assert!(!logs.past(b"logs/a\0v999\0ii1"));
        assert!(!logs.past(b"logs."));
        assert!(logs.past(b"logs0"));
        assert!(logs.past(&special("1000_", &[b"logs/v\0ii1"])));
        assert!(logs.past("é".as_bytes()));
        assert!(!IndexRange::default().past(b"\x80"));
    }

    #[test]
    fn orphans_list_everything() {
        let (e, _) = engine(Some("logs/"), 0);
        assert_eq!(e.listing_prefix(), "logs/");
        let mut e = Arc::try_unwrap(e).ok().expect("unshared");
        e.opts.refcount = true;
        assert_eq!(e.listing_prefix(), "");
        e.opts.refcount = false;
        e.partitions = Some(4);
        assert_eq!(e.listing_prefix(), "");
    }

    /// The uploads a bucket's heads name, from a full listing though the
    /// scan's is limited: the copy outside the prefix names upload 1.
    #[tokio::test]
    async fn uploads_named() {
        let (e, store) = engine(Some("logs/"), 3);
        let (named, errors) = e.uploads_named(&stats()).await.expect("listing");
        assert_eq!(named, ["2~up1".to_string()].into());
        assert!(errors.is_empty(), "{errors:?}");
        // every shard, from the start
        let (full, all) = engine(None, 3);
        let _ = seeds(&full).await;
        assert_eq!(store.bi_calls.load(Ordering::Relaxed), all.bi_calls.load(Ordering::Relaxed));
        // the limited listing leaves the copy out
        assert!(seeds(&e).await.iter().all(|(r, _)| r.0 != "zz"));
    }

    /// Between an index range's marker and its prefix lies no key an index
    /// holds, and its keys are together: listed from the marker until one
    /// is past it, they are the keys that start with the prefix.
    #[test]
    fn range_bounds() {
        let all: BTreeMap<Vec<u8>, Vec<u8>> = shards().into_iter().flatten().collect();
        let keys: Vec<&Vec<u8>> = all.keys().collect();
        for p in PREFIXES.iter().filter(|p| !p.is_empty()) {
            for r in index_ranges(p) {
                for k in &keys {
                    assert_eq!(k.as_slice() > r.start_after.as_slice(), k.as_slice() >= r.prefix.as_slice(), "{p:?}: {k:?}");
                }
                let listed: Vec<&Vec<u8>> = keys.iter().copied().filter(|k| k.as_slice() > r.start_after.as_slice()).take_while(|k| !r.past(k)).collect();
                let want: Vec<&Vec<u8>> = keys.iter().copied().filter(|k| k.starts_with(&r.prefix)).collect();
                assert_eq!(listed, want, "{p:?}");
            }
        }
    }

    /// The emulated bi_list, paged from the start, returns every entry but
    /// the logs once: the ASCII plain ones, the instance and OLH ones, then
    /// the non-ASCII plain ones.  Of one name, only its entries.
    #[test]
    fn bi_list_regions() {
        for omap in &shards() {
            for max in [1, 2, 3, 7, 1000] {
                let (mut marker, mut listed) = (Vec::new(), Vec::new());
                loop {
                    let (page, truncated) = bi_list(omap, "", &marker, max).expect("listing");
                    assert!(page.len() <= max as usize);
                    let Some((_, last, _)) = page.last() else { break };
                    marker = last.clone();
                    listed.extend(page.into_iter().map(|(t, k, _)| (t, k)));
                    if !truncated {
                        break;
                    }
                }
                let of = |t: u8, f: fn(&[u8]) -> bool| omap.keys().filter(move |k| f(k)).map(move |k| (t, k.clone()));
                let want: Vec<(u8, Vec<u8>)> = of(1, |k| k[0] < 0x80)
                    .chain(of(2, |k| k.starts_with(b"\x801000_")))
                    .chain(of(3, |k| k.starts_with(b"\x801001_")))
                    .chain(of(1, |k| k[0] > 0x80))
                    .collect();
                assert_eq!(listed, want, "pages of {max}");
            }
        }
        let shards = shards();
        for (i, (key, versions)) in KEYS.iter().enumerate() {
            let name = index_name(key);
            let (page, truncated) = bi_list(&shards[i % 2], &name, b"", 1000).expect("listing");
            assert!(!truncated);
            let kinds: Vec<u8> = page.iter().map(|(t, _, _)| *t).collect();
            let plain = page.iter().filter(|(t, _, _)| *t == 1).map(|(_, _, d)| DirEntry::decode(d).expect("entry").name).collect::<Vec<_>>();
            assert_eq!(plain, vec![name.clone(); versions.len() + 1], "{key:?}");
            let bookkeeping = if versions.is_empty() { 0 } else { versions.len() + 1 };
            assert_eq!(kinds.len(), plain.len() + bookkeeping, "{key:?}");
        }
    }

    /// A listing under a prefix yields the seeds of a full listing that the
    /// scan covers, whatever the page size, in fewer pages.
    #[tokio::test]
    async fn pushed_down() {
        for max in [1, 2, 3, 5, 1000] {
            let (e, store) = engine(None, max);
            let full = seeds(&e).await;
            let full_calls = store.bi_calls.load(Ordering::Relaxed);
            for p in PREFIXES {
                let (e, store) = engine(Some(p), max);
                let covers = |k: &str| e.opts.covers(k);
                let got = seeds(&e).await;
                // the parts of the open uploads under the prefix, read for their
                // errors, and dropped by the post-filter
                let parts = got.iter().filter(|(_, s)| s.parts).count();
                let under = UPLOADS.iter().enumerate().filter(|(i, k)| covers(&format!("{k}.2~up{i}.meta"))).count();
                assert_eq!(parts, under, "prefix {p:?}, pages of {max}");
                // nothing else the post-filter drops, but the OLH of a name the
                // prefix runs into "[" after
                let dropped = got.iter().filter(|(_, s)| !s.parts && !covers(&s.key));
                assert!(dropped.clone().all(|(_, s)| s.entry.is_none() && p.starts_with(&format!("{}[", s.key))), "{p:?}");
                let want: Vec<&Row> = full.iter().filter(|(_, s)| !s.parts && covers(&s.key)).map(|(r, _)| r).collect();
                let got: Vec<&Row> = got.iter().filter(|(_, s)| !s.parts && covers(&s.key)).map(|(r, _)| r).collect();
                assert_eq!(got, want, "prefix {p:?}, pages of {max}");
                // a page per `max` entries of each range in each shard, and
                // one that ends the range
                let pages: u64 = shards()
                    .iter()
                    .flat_map(|omap| index_ranges(p).into_iter().map(move |r| omap.keys().filter(|k| k.starts_with(&r.prefix)).count() as u64))
                    .map(|n| n / u64::from(max) + 1)
                    .sum();
                let calls = store.bi_calls.load(Ordering::Relaxed);
                assert!(calls <= pages, "prefix {p:?}, pages of {max}: {calls} calls");
                if p.starts_with("logs/") && max <= 2 {
                    assert!(calls * 2 < full_calls, "prefix {p:?}, pages of {max}: {calls} calls of {full_calls}");
                }
            }
        }
    }

    /// The findings, MISSING lines, gaps and RADOS objects a scan under a
    /// prefix reports, with its listing pushed down, are those of a scan of
    /// every key filtered by the prefix: heads missing ( the entry read
    /// again, or the OLH looked up ), tails missing, stale entries, open
    /// uploads a head names, and unnamed ones with parts unindexed, one
    /// named only by a copy outside the prefix.
    #[tokio::test]
    async fn scan_as_filtered() {
        let (lister, _) = engine(None, 1000);
        let listed = seeds(&lister).await;
        let mut store = store(3);
        // the heads, but every fourth; every fourth an ETag its entry lacks
        let heads = listed.iter().map(|(_, s)| s).filter(|s| !s.parts && !s.oids[0].starts_with("M.1__multipart_") && s.oids[0] != COPY.0);
        for (i, s) in heads.enumerate() {
            let etag = [(crate::scan::XATTR_ETAG.to_string(), b"new".to_vec())].into();
            let head = MockObject { mtime: 1000, xattrs: if i % 4 == 2 { etag } else { Default::default() }, ..Default::default() };
            if i % 4 != 1 {
                store.put(0, &s.oids[0], head);
            }
        }
        // the OLH a null delete marker leaves, missing: looked up, and still a gap
        store.objects.remove(&(0, "M.1_logs/n".to_string()));
        // a completed upload's object, and its tail
        let manifest = multipart_manifest("M.1", "logs/ab", "logs/ab.2~done", 2);
        store.put(0, "M.1_logs/ab", MockObject { mtime: 1000, xattrs: [(XATTR_MANIFEST.to_string(), manifest)].into(), ..Default::default() });
        for part in 1..=2 {
            store.put(0, &format!("M.1__multipart_logs/ab.2~done.{part}"), MockObject::default());
        }
        // what list_open_uploads reads of the shards
        for (oid, omap) in &store.bi {
            let keys = omap.keys().filter_map(|k| String::from_utf8(k.clone()).ok()).collect();
            store.index.insert((stats().placement(), oid.clone()), keys);
        }
        let copy = |s: &MockStore| MockStore { objects: s.objects.clone(), index: s.index.clone(), bi: s.bi.clone(), bi_max: s.bi_max, ..MockStore::new(1, 1) };
        let scan = |prefix: Option<&str>| {
            let opts = Options { match_prefix: prefix.map(str::to_string), check_index: true, ..Default::default() };
            let (e, _) = engine_of(copy(&store), opts);
            async move {
                let gaps = Arc::new(AtomicU64::new(0));
                let r = e.scan_bucket_counting("b", Some(stats()), Arc::default(), gaps.clone(), None).await.expect("scan");
                assert_eq!(gaps.load(Ordering::Relaxed), r.gaps, "the gaps counted as they are found");
                r
            }
        };
        let findings = |r: &crate::scan::BucketReport, covers: &dyn Fn(&str) -> bool| {
            let mut f: Vec<String> = r.findings.iter().filter(|f| covers(f.key.as_deref().unwrap_or(""))).map(|f| serde_json::to_string(f).unwrap()).collect();
            f.sort();
            f
        };
        let missing = |r: &crate::scan::BucketReport, covers: &dyn Fn(&str) -> bool| {
            let key = |l: &String| l.strip_prefix("s3://b/").and_then(|l| l.split_once(" MISSING ")).map(|(k, _)| k.to_string()).unwrap_or_default();
            let mut m: Vec<String> = r.missing.iter().filter(|l| covers(&key(l))).cloned().collect();
            m.sort();
            m
        };
        // the seeds a full listing of the bucket yields, whose RADOS objects count
        let (all, _) = engine_of(copy(&store), Options::default());
        let all = seeds(&all).await;
        let full = scan(None).await;
        let checks: BTreeSet<&str> = full.findings.iter().map(|f| f.check.as_str()).collect();
        let want = ["completed_upload_open", "listed_without_head", "missing_data", "part_entries_missing", "stale_entry"];
        assert_eq!(checks, want.into(), "the full scan finds each");
        assert!(full.missing.contains(&"s3://b/logs/n MISSING M.1_logs/n".to_string()), "{:?}", full.missing);
        for p in ["logs/", "logs", "logs/a", "logs/a.", "logs[", "logs/v[i", "logs/n", "l", "_", "_hidden", "é", "日本", "zz", "nomatch"] {
            let opts = Options { match_prefix: Some(p.into()), ..Default::default() };
            let covers = |k: &str| opts.covers(k);
            let got = scan(Some(p)).await;
            assert_eq!(findings(&got, &|_| true), findings(&full, &covers), "{p:?}");
            let lines = missing(&full, &covers);
            assert_eq!(missing(&got, &|_| true), lines, "{p:?}");
            assert_eq!(got.gaps, lines.len() as u64, "{p:?}");
            let objects: usize = all.iter().filter(|(_, s)| covers(&s.key)).map(|(_, s)| s.oids.len()).sum();
            assert_eq!(got.rados_objects, objects as u64, "{p:?}");
            assert!(got.errors.iter().all(|e| full.errors.contains(e)), "{p:?}: {:?}", got.errors);
        }
    }
}
