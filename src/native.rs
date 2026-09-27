//! The native listing: a bucket's objects, and every RADOS object each
//! one's manifest names, read from its index shards and head objects, with
//! no radosgw-admin.  One shard at a time, so a bucket's shards can be
//! spread over clients.

use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::admin::BucketStats;
use crate::decode::{DirEntry, FLAG_VER_MARKER, Key, Manifest, RawName, bi_list_op, bi_list_ret, object_names};
use crate::oid::index_objects;
use crate::scan::Engine;
use crate::store::{PoolId, Pools};

pub const XATTR_MANIFEST: &str = "user.rgw.manifest";

/// One S3 object, as a listing yields it: its key as radoslist writes it,
/// the RADOS objects it names ( head first ), and its index entry.
#[derive(Debug, Clone)]
pub struct Seed {
    pub bucket: String,
    pub key: String,
    pub oids: Vec<String>,
    pub entry: Option<DirEntry>,
    /// the manifest could not be read or decoded
    pub error: Option<String>,
    /// the objects the listing found, and their pools: not to stat again
    pub found: Vec<(String, PoolId)>,
    /// the stripes of an open upload's parts, which radoslist lists without
    /// a key: references, not an S3 object
    pub parts: bool,
}

impl Seed {
    fn new(bucket: &str, key: String, entry: Option<DirEntry>) -> Seed {
        Seed { bucket: bucket.to_string(), key, oids: Vec::new(), entry, error: None, found: Vec::new(), parts: false }
    }
}

/// How to scan a bucket: whole, or a unit per index shard when it has more
/// than `above` S3 objects over several shards.  Everything of a key ( its
/// versions, its OLH, its uploads' meta and part entries ) hashes to the
/// shard of its name, so a shard can be checked on its own.
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

/// The index entries of one shard, a page at a time, through cls_rgw's
/// bi_list ( as radosgw-admin bi list reads them ): only the listing's
/// entries, not the versioned or OLH bookkeeping.
async fn shard_entries(engine: &Engine, placement: &str, oid: &str, tx: &mpsc::Sender<Result<Vec<DirEntry>>>) -> Result<()> {
    let mut marker: Vec<u8> = Vec::new();
    loop {
        let out = engine
            .store
            .index_exec(placement, oid, "rgw", "bi_list", bi_list_op(&marker, 1000))
            .await?
            .with_context(|| format!("index shard {oid} does not exist"))?;
        let (page, truncated) = bi_list_ret(&out).with_context(|| format!("decoding bi_list of {oid}"))?;
        let Some((_, last, _)) = page.last() else { return Ok(()) };
        marker = last.clone();
        let mut entries = Vec::with_capacity(page.len());
        for (kind, idx, data) in page {
            if kind != 1 {
                continue;
            }
            match DirEntry::decode(&data) {
                Ok(e) => entries.push(e),
                Err(e) => {
                    let key = String::from_utf8_lossy(&idx);
                    return Err(e.context(format!("decoding the index entry {key:?} of {oid}")));
                }
            }
        }
        if tx.send(Ok(entries)).await.is_err() || !truncated {
            return Ok(());
        }
    }
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
fn items(entries: Vec<DirEntry>, olh: &mut Option<String>) -> Vec<Item> {
    let mut items = Vec::with_capacity(entries.len());
    for e in entries {
        if e.flags & FLAG_VER_MARKER != 0 {
            continue; // not a listing entry ( rgw_bucket_dir_entry::is_valid )
        }
        let key = e.key();
        if !e.instance.is_empty() && olh.as_deref() != Some(key.name.as_str()) {
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
            if live && self.store.find(&head.oid, Pools::ExtraFirst).await.is_none() {
                return None;
            }
            return Some(seed);
        }
        let Some((pool, _, _)) = self.store.find(&head.oid, Pools::Data).await else {
            // no head: the gap check reports it, as radoslist lists it
            return (!live).then_some(seed);
        };
        seed.found.push((head.oid.clone(), pool));
        let manifest = match self.store.getxattr(pool, &head.oid, XATTR_MANIFEST).await {
            Ok(Some(bl)) => match Manifest::decode(&bl) {
                Ok(m) => Some(m),
                Err(err) => {
                    seed.error = Some(format!("the manifest of {} does not decode: {err:#}", head.oid));
                    return Some(seed);
                }
            },
            Ok(None) => None,
            Err(err) => {
                seed.error = Some(format!("reading the manifest of {}: {err:#}", head.oid));
                return Some(seed);
            }
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
        // closed since it was listed
        let (pool, _, _) = self.store.find(&oid, Pools::ExtraFirst).await?;
        let mut seed = Seed::new(bucket, String::new(), None);
        seed.parts = true;
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

    /// The seeds of a bucket's objects, from its index: every shard, or one.
    /// Delete markers have no head, and are left out.
    pub fn native_seeds(self: &Arc<Self>, stats: BucketStats, shard: Option<u32>) -> mpsc::Receiver<Result<Seed>> {
        let (tx, rx) = mpsc::channel(4096);
        let engine = self.clone();
        tokio::spawn(async move {
            let placement = stats.placement();
            let name = stats.name();
            let marker = stats.marker.as_str();
            for oid in shard_objects(&stats, shard) {
                let (etx, mut erx) = mpsc::channel(4);
                let lister = {
                    let (engine, placement, oid) = (engine.clone(), placement.clone(), oid.clone());
                    tokio::spawn(async move {
                        if let Err(e) = shard_entries(&engine, &placement, &oid, &etx).await {
                            let _ = etx.send(Err(e)).await;
                        }
                    })
                };
                // a key's versions are together in its shard
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
                    let mut seeds = futures::stream::iter(work).buffer_unordered(256);
                    while let Some(seed) = seeds.next().await {
                        let Some(seed) = seed else { continue };
                        if tx.send(Ok(seed)).await.is_err() {
                            return;
                        }
                    }
                }
                let _ = lister.await;
            }
        });
        rx
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
