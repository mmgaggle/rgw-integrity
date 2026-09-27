//! What the checks read from RADOS, behind a trait so they can be tested
//! without a cluster.

use std::collections::{BTreeSet, HashMap};

use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolId(pub usize);

/// Which pools to look in, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pools {
    /// the data pools
    Data,
    /// the extra pools ( multipart meta objects ), then the data pools
    ExtraFirst,
    /// the data pools, then the extra pools
    DataFirst,
}

/// What a stat of an object found: the object, ENOENT in every pool looked
/// in, or another error ( a negative errno ), which says nothing either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stat {
    Found { pool: PoolId, size: u64, mtime: i64 },
    Missing,
    Error(i32),
}

/// An errno's text, as strerror() gives it.
pub fn strerror(r: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(-r)
}

/// A pool spec as Ceph's rgw_pool::from_str() reads it, into the pool's name
/// and namespace: they are split at the first `:` not escaped by a `\`, and
/// a `\` makes the character after it literal.  The namespace ends at
/// another unescaped `:`, and a trailing `\` is dropped.
pub fn parse_pool(spec: &str) -> (String, String) {
    // rgw_unescape_str(): the unescaped text up to an unescaped ':', and what follows it
    fn unescape(s: &str) -> (String, Option<&str>) {
        let (mut out, mut esc) = (String::new(), false);
        for (i, c) in s.char_indices() {
            if !esc && c == '\\' {
                esc = true;
                continue;
            }
            if !esc && c == ':' {
                return (out, Some(&s[i + 1..]));
            }
            out.push(c);
            esc = false;
        }
        (out, None)
    }
    let (name, rest) = unescape(spec);
    (name, rest.map(|r| unescape(r).0).unwrap_or_default())
}

/// A pool and namespace as rgw_pool::to_str() writes them, the inverse of
/// parse_pool(): `\` and `:` escaped in each, joined by a `:` if there is a
/// namespace.
pub fn pool_spec(name: &str, ns: &str) -> String {
    let escape = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if c == '\\' || c == ':' {
                out.push('\\');
            }
            out.push(c);
        }
        out
    };
    if ns.is_empty() { escape(name) } else { format!("{}:{}", escape(name), escape(ns)) }
}

/// The pools to look in, in order, from pool ids that may name a pool twice
/// ( a data pool the zone lists as an extra pool too, or a --pool given
/// twice ): each pool, as `key` names it, at its first place only, so none
/// is statted twice.  The order is kept, and a pool left out is one looked
/// in already: ENOENT in every pool kept is ENOENT in every pool.
#[cfg_attr(not(feature = "ceph"), allow(dead_code))]
pub fn distinct_pools<K: PartialEq>(ids: &[usize], key: impl Fn(usize) -> K) -> Vec<usize> {
    let mut kept: Vec<(usize, K)> = Vec::with_capacity(ids.len());
    for &id in ids {
        let k = key(id);
        if !kept.iter().any(|(_, seen)| *seen == k) {
            kept.push((id, k));
        }
    }
    kept.into_iter().map(|(id, _)| id).collect()
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Stat an object in the data pools: the first one, then the others.
    async fn stat(&self, oid: &str) -> Stat;

    /// Look for an object in the pools, in order: Found in the first that
    /// holds it, Missing if every one answers ENOENT, and otherwise the
    /// error, since the object may be in a pool that could not be read.
    async fn locate(&self, oid: &str, pools: Pools) -> Stat;

    /// An xattr's value, or None if the object or the xattr is missing.
    async fn getxattr(&self, pool: PoolId, oid: &str, name: &str) -> Result<Option<Vec<u8>>>;

    /// Every xattr of an object, in one read; None if it is missing.
    async fn getxattrs(&self, pool: PoolId, oid: &str) -> Result<Option<HashMap<String, Vec<u8>>>>;

    /// The omap keys of an object in a pool that start with a prefix.
    async fn omap_keys(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<String>>>;

    /// The same, with their values.
    async fn omap_vals(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<(String, Vec<u8>)>>>;

    /// The same, for an object in a placement target's index pool.
    async fn index_keys(&self, placement: &str, oid: &str, prefix: &str) -> Result<Option<Vec<String>>>;

    /// Call an object class method on an index shard; None if it does not exist.
    async fn index_exec(&self, placement: &str, oid: &str, cls: &str, method: &str, input: Vec<u8>) -> Result<Option<Vec<u8>>>;

    /// The major versions the cluster's RGWs and OSDs run.
    async fn majors(&self) -> Result<BTreeSet<u32>>;

    /// A config option, as this client sees it.
    fn conf_get(&self, name: &str) -> Option<String>;

    /// List slice `slice` of `slices` of a pool ( a spec parse_pool() reads ),
    /// sending the names in batches; returns how many.
    async fn list_slice(&self, pool: &str, slice: usize, slices: usize, tx: tokio::sync::mpsc::Sender<Vec<String>>) -> Result<u64>;

    /// The number of objects in each pool.
    async fn pool_objects(&self) -> Result<HashMap<String, u64>>;

    /// The pools stat() looks in, as specs ( see parse_pool() ), each once:
    /// those orphan detection lists, so what it takes for an orphan is what
    /// the scan would have found.
    fn data_pools(&self) -> Vec<String>;

    /// Where orphan detection exchanges its partitions, in a pool.
    fn shuffle(&self, pool: &str) -> Result<std::sync::Arc<dyn crate::shuffle::Shuffle>>;
}

/// An in-memory Store, for tests.
#[cfg(test)]
#[derive(Default)]
pub struct MockStore {
    /// pool 0.. are the data pools, then the extra pools; "index" objects are
    /// looked up by placement
    pub pools: usize,
    pub extra: usize,
    pub objects: HashMap<(usize, String), MockObject>,
    pub index: HashMap<(String, String), Vec<String>>,
    /// the listing entries of index shards, by name: bi_list reads them as
    /// the plain entries of an omap ( see `omap_of` ), when `bi` has none
    pub shards: HashMap<String, Vec<crate::decode::DirEntry>>,
    pub majors: BTreeSet<u32>,
    /// what a pool listing returns, by pool name
    pub listing: HashMap<String, Vec<String>>,
    /// the omap of each index shard, by name, which bi_list reads
    pub bi: HashMap<String, std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
    /// bi_list's largest page ( 0: MAX_BI_LIST_ENTRIES, 1000 )
    pub bi_max: u32,
    /// the bi_list calls
    pub bi_calls: std::sync::atomic::AtomicU64,
    /// the errno a stat of an object fails with in a pool ( see fail() )
    pub errors: HashMap<(usize, String), i32>,
    /// the errno reads of an object's xattrs and omap fail with in a pool
    pub read_errors: HashMap<(usize, String), i32>,
    /// the placement of an index shard, by name: bi_list in another finds
    /// no such shard ( none: any placement )
    pub placements: HashMap<String, String>,
    /// how long each stat and xattr read takes, as a cluster's do: a read
    /// in flight holds its limiter permit
    pub latency: std::time::Duration,
    /// the data pools' specs, as data_pools() gives them
    pub specs: Vec<String>,
}

#[cfg(test)]
#[derive(Default, Clone)]
pub struct MockObject {
    pub size: u64,
    pub mtime: i64,
    pub xattrs: HashMap<String, Vec<u8>>,
    pub omap: Vec<String>,
}

#[cfg(test)]
impl MockStore {
    pub fn new(pools: usize, extra: usize) -> MockStore {
        MockStore { pools, extra, ..Default::default() }
    }

    pub fn put(&mut self, pool: usize, oid: &str, obj: MockObject) {
        self.objects.insert((pool, oid.to_string()), obj);
    }

    /// The omap of an index shard: its `bi` one, or one of the plain entries
    /// `shards` gives it, keyed as cls_rgw keys them ( a version's by its
    /// name and "\0v<ver>\0i<instance>", in their order ).
    fn omap_of(&self, oid: &str) -> Option<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
        if let Some(omap) = self.bi.get(oid) {
            return Some(omap.clone());
        }
        let mut omap = std::collections::BTreeMap::new();
        for (i, d) in self.shards.get(oid)?.iter().enumerate() {
            let mut key = d.name.clone().into_bytes();
            if !d.instance.is_empty() || omap.contains_key(&key) {
                key.extend(format!("\0v{:05}\0i{}", 99_999 - i, d.instance).into_bytes());
            }
            omap.insert(key, crate::decode::enc::dir_entry(d));
        }
        Some(omap)
    }

    /// Make a stat of `oid` in `pool` fail with `errno` ( e.g. -EIO; -ENOENT
    /// hides an object that is there ).
    pub fn fail(&mut self, pool: usize, oid: &str, errno: i32) {
        self.errors.insert((pool, oid.to_string()), errno);
    }

    /// A stat of `oid` in one pool: its size and mtime, or the errno.
    fn stat_in(&self, pool: usize, oid: &str) -> std::result::Result<(u64, i64), i32> {
        let k = (pool, oid.to_string());
        if let Some(&r) = self.errors.get(&k) {
            return Err(r);
        }
        self.objects.get(&k).map(|o| (o.size, o.mtime)).ok_or(-libc::ENOENT)
    }

    /// Wait as a read of the cluster would.
    async fn wait(&self) {
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
    }

    /// An object in a pool, to read its xattrs or omap: None if it is not there.
    fn read(&self, pool: PoolId, oid: &str) -> Result<Option<&MockObject>> {
        let k = (pool.0, oid.to_string());
        if let Some(&r) = self.read_errors.get(&k) {
            anyhow::bail!("reading {oid}: {}", strerror(r));
        }
        Ok(self.objects.get(&k))
    }

    fn order(&self, pools: Pools) -> Vec<usize> {
        let data = 0..self.pools;
        let extra = self.pools..self.pools + self.extra;
        match pools {
            Pools::Data => data.collect(),
            Pools::ExtraFirst => extra.chain(data).collect(),
            Pools::DataFirst => data.chain(extra).collect(),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl Store for MockStore {
    /// As RadosStore's: the first data pool, and the others only if it
    /// answers ENOENT
    async fn stat(&self, oid: &str) -> Stat {
        self.wait().await;
        let (first, rest) = (0, 1..self.pools);
        match self.stat_in(first, oid) {
            Ok((size, mtime)) => return Stat::Found { pool: PoolId(first), size, mtime },
            Err(r) if r != -libc::ENOENT => return Stat::Error(r),
            Err(_) => {}
        }
        let mut error = None;
        for p in rest {
            match self.stat_in(p, oid) {
                Ok((size, mtime)) => return Stat::Found { pool: PoolId(p), size, mtime },
                Err(r) if r != -libc::ENOENT => error = Some(r),
                Err(_) => {}
            }
        }
        error.map_or(Stat::Missing, Stat::Error)
    }

    async fn locate(&self, oid: &str, pools: Pools) -> Stat {
        self.wait().await;
        let mut error = None;
        for p in self.order(pools) {
            match self.stat_in(p, oid) {
                Ok((size, mtime)) => return Stat::Found { pool: PoolId(p), size, mtime },
                Err(r) if r != -libc::ENOENT => error = Some(r),
                Err(_) => {}
            }
        }
        error.map_or(Stat::Missing, Stat::Error)
    }

    async fn getxattr(&self, pool: PoolId, oid: &str, name: &str) -> Result<Option<Vec<u8>>> {
        self.wait().await;
        Ok(self.read(pool, oid)?.and_then(|o| o.xattrs.get(name).cloned()))
    }

    async fn getxattrs(&self, pool: PoolId, oid: &str) -> Result<Option<HashMap<String, Vec<u8>>>> {
        self.wait().await;
        Ok(self.read(pool, oid)?.map(|o| o.xattrs.clone()))
    }

    async fn omap_keys(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<String>>> {
        Ok(self.read(pool, oid)?.map(|o| o.omap.iter().filter(|k| k.starts_with(prefix)).cloned().collect()))
    }

    async fn omap_vals(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<(String, Vec<u8>)>>> {
        Ok(self.omap_keys(pool, oid, prefix).await?.map(|keys| keys.into_iter().map(|k| (k, Vec::new())).collect()))
    }

    async fn index_keys(&self, placement: &str, oid: &str, prefix: &str) -> Result<Option<Vec<String>>> {
        Ok(self
            .index
            .get(&(placement.to_string(), oid.to_string()))
            .map(|keys| keys.iter().filter(|k| k.starts_with(prefix)).cloned().collect()))
    }

    async fn majors(&self) -> Result<BTreeSet<u32>> {
        Ok(self.majors.clone())
    }

    async fn index_exec(&self, placement: &str, oid: &str, cls: &str, method: &str, input: Vec<u8>) -> Result<Option<Vec<u8>>> {
        use std::sync::atomic::Ordering;
        if (cls, method) != ("rgw", "bi_list") {
            anyhow::bail!("the mock store has no {cls}.{method}");
        }
        if self.placements.get(oid).is_some_and(|p| p != placement) {
            return Ok(None);
        }
        let Some(omap) = self.omap_of(oid) else { return Ok(None) };
        // rgw_cls_bi_list_op, version 1
        let c = &mut crate::decode::Cursor::new(&input);
        let h = c.start()?;
        let max = c.u32()?;
        let name = String::from_utf8(c.bytes()?)?;
        let marker = c.bytes()?;
        c.finish(h)?;
        let cap = if self.bi_max == 0 { 1000 } else { self.bi_max };
        let (entries, truncated) = bi_list(&omap, &name, &marker, max.min(cap))?;
        self.bi_calls.fetch_add(1, Ordering::Relaxed);
        // rgw_cls_bi_list_ret
        let mut e = crate::decode::enc::Enc::new();
        e.st(1, 1, |e| {
            e.u32(entries.len() as u32);
            for (t, idx, data) in &entries {
                e.st(1, 1, |e| {
                    e.u8(*t).u32(idx.len() as u32).raw(idx).u32(data.len() as u32).raw(data);
                });
            }
            e.u8(truncated as u8);
        });
        Ok(Some(e.0))
    }

    fn conf_get(&self, _name: &str) -> Option<String> {
        None
    }

    async fn list_slice(&self, pool: &str, slice: usize, slices: usize, tx: tokio::sync::mpsc::Sender<Vec<String>>) -> Result<u64> {
        let names: Vec<String> = self
            .listing
            .get(pool)
            .map(|all| all.iter().enumerate().filter(|(i, _)| i % slices.max(1) == slice).map(|(_, n)| n.clone()).collect())
            .unwrap_or_default();
        let n = names.len() as u64;
        tx.send(names).await?;
        Ok(n)
    }

    async fn pool_objects(&self) -> Result<HashMap<String, u64>> {
        Ok(self.listing.iter().map(|(p, n)| (p.clone(), n.len() as u64)).collect())
    }

    fn data_pools(&self) -> Vec<String> {
        self.specs.clone()
    }

    fn shuffle(&self, pool: &str) -> Result<std::sync::Arc<dyn crate::shuffle::Shuffle>> {
        let dir = std::env::temp_dir().join(format!("rgwi-mock-{}-{pool}", std::process::id()));
        Ok(std::sync::Arc::new(crate::shuffle::LocalShuffle::new(dir)?))
    }
}

/// cls_rgw's rgw_bi_list_op over an index shard's omap, as the OSD runs it:
/// list_plain_entries in the ASCII region after the marker; then, while no
/// step says more follow, list_instance_entries and list_olh_entries from
/// the later of their start and the marker, and list_plain_entries in the
/// non-ASCII region from the later of the marker and BI_PREFIX_END.  `more`
/// is cls_cxx_map_get_vals': keys beyond those asked for.  A name filter
/// limits the plain entries to the keys starting with it, up to the first
/// whose entry is of a later name, and the instance and OLH entries to the
/// name's ( by their keys: the mock's omaps need not hold them decodable ).
/// The counts are uint32_t's, as the OSD's: an exact first instance or OLH
/// entry when none is left to ask for wraps them, and lists the rest.
#[cfg(test)]
pub fn bi_list(omap: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>, name: &str, marker: &[u8], max: u32) -> Result<crate::decode::BiPage> {
    use std::ops::Bound::{Excluded, Included, Unbounded};
    const BEGIN: &[u8] = b"\x80";
    const END: &[u8] = b"\x809999_";
    // cls_cxx_map_get_vals: up to `n` keys after `start` that start with
    // `filter`, and whether more follow
    let get_vals = |start: &[u8], filter: &[u8], n: usize| {
        let from = if filter > start { Included(filter) } else { Excluded(start) };
        let mut it = omap.range::<[u8], _>((from, Unbounded)).take_while(|(k, _)| k.starts_with(filter));
        let vals: Vec<(Vec<u8>, Vec<u8>)> = it.by_ref().take(n).map(|(k, v)| (k.clone(), v.clone())).collect();
        (vals, it.next().is_some())
    };
    // list_plain_entries_help: whether an entry is of a name past the filter
    let past_name = |v: &[u8]| -> Result<bool> { Ok(!name.is_empty() && crate::decode::DirEntry::decode(v)?.name.as_str() > name) };
    let mut out: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();
    let left = |out: &Vec<(u8, Vec<u8>, Vec<u8>)>| max.wrapping_sub(out.len() as u32);
    let mut more = false;
    // the ASCII plain entries, below BI_PREFIX_BEGIN
    if marker < BEGIN {
        let (vals, m) = get_vals(marker, name.as_bytes(), max as usize);
        more = m;
        for (k, v) in vals {
            if k.as_slice() >= BEGIN || past_name(&v)? {
                more = false;
                break;
            }
            out.push((1, k, v));
            if out.len() >= max as usize {
                break;
            }
        }
    }
    // the instance ( 2 ) and OLH ( 3 ) entries
    let instances = if name.is_empty() { b"\x801000_".to_vec() } else { [&b"\x801000_"[..], name.as_bytes(), b"\0i"].concat() };
    let olhs = [&b"\x801001_"[..], name.as_bytes()].concat();
    for (t, filter) in [(2u8, instances.as_slice()), (3, olhs.as_slice())] {
        if more {
            break;
        }
        let start = filter.max(marker);
        let mut n = left(&out);
        let first = omap.get(start).filter(|_| start != marker).cloned();
        if first.is_some() {
            n = n.wrapping_sub(1);
        }
        let mut vals = Vec::new();
        if n > 0 {
            let (v, m) = get_vals(start, b"", n as usize);
            (vals, more) = (v, m);
        }
        if let Some(v) = first {
            vals.insert(0, (start.to_vec(), v));
        }
        for (k, v) in vals {
            // a named OLH entry's key is the name's alone
            if !k.starts_with(filter) || (t == 3 && !name.is_empty() && k != filter) {
                more = false;
                break;
            }
            out.push((t, k, v));
        }
    }
    // the non-ASCII plain entries, after BI_PREFIX_END
    if !more {
        let (vals, m) = get_vals(END.max(marker), name.as_bytes(), left(&out) as usize);
        more = m;
        for (k, v) in vals {
            if past_name(&v)? {
                more = false;
                break;
            }
            out.push((1, k, v));
        }
    }
    let truncated = out.len() > max as usize || more;
    out.truncate(max as usize);
    Ok((out, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_specs_follow_rgw_pool() {
        let own = |n: &str, ns: &str| (n.to_string(), ns.to_string());
        assert_eq!(parse_pool("default.rgw.buckets.data"), own("default.rgw.buckets.data", ""));
        assert_eq!(parse_pool("p:ns"), own("p", "ns"));
        // how the zone dumps a pool named rgw:data, and one named a\b
        assert_eq!(parse_pool(r"rgw\:data"), own("rgw:data", ""));
        assert_eq!(parse_pool(r"a\\b"), own(r"a\b", ""));
        assert_eq!(parse_pool(r"a\\:ns"), own(r"a\", "ns"));
        assert_eq!(parse_pool(r"p:n\:s"), own("p", "n:s"));
        // from_str() stops the namespace at an unescaped ':', and drops a trailing '\'
        assert_eq!(parse_pool("a:b:c"), own("a", "b"));
        assert_eq!(parse_pool(r"a\"), own("a", ""));
        assert_eq!(parse_pool("a:"), own("a", ""));
        assert_eq!(parse_pool(r"\x"), own("x", ""));
        assert_eq!(parse_pool(""), own("", ""));

        assert_eq!(pool_spec("rgw:data", ""), r"rgw\:data");
        assert_eq!(pool_spec(r"a\b", ""), r"a\\b");
        assert_eq!(pool_spec("p", "ns"), "p:ns");
        assert_eq!(pool_spec("a:b", r"c:d\"), r"a\:b:c\:d\\");
        for (n, ns) in [("rgw:data", ""), (r"a\b", "x:y"), ("p", "ns"), (r":\:", r"\")] {
            assert_eq!(parse_pool(&pool_spec(n, ns)), own(n, ns));
        }
    }

    #[tokio::test]
    async fn mock_stats_follow_rados_store() {
        // two data pools and an extra pool
        let mut store = MockStore::new(2, 1);
        let at = |p| Stat::Found { pool: PoolId(p), size: 0, mtime: 0 };
        // ENOENT everywhere
        assert_eq!(store.stat("gone").await, Stat::Missing);
        assert_eq!(store.locate("gone", Pools::DataFirst).await, Stat::Missing);
        // ENOENT in the first pool, EIO in the second: it may be there
        store.fail(1, "split", -libc::EIO);
        assert_eq!(store.stat("split").await, Stat::Error(-libc::EIO));
        assert_eq!(store.locate("split", Pools::Data).await, Stat::Error(-libc::EIO));
        // an error in the first pool: stat looks no further, locate does
        store.put(1, "second", MockObject::default());
        store.fail(0, "second", -libc::ETIMEDOUT);
        assert_eq!(store.stat("second").await, Stat::Error(-libc::ETIMEDOUT));
        assert_eq!(store.locate("second", Pools::Data).await, at(1));
        // stat looks in the data pools only; an unreadable extra pool is an error
        store.put(2, "meta", MockObject::default());
        assert_eq!(store.stat("meta").await, Stat::Missing);
        assert_eq!(store.locate("meta", Pools::ExtraFirst).await, at(2));
        store.fail(2, "meta2", -libc::EPERM);
        assert_eq!(store.locate("meta2", Pools::ExtraFirst).await, Stat::Error(-libc::EPERM));
    }

    #[test]
    fn a_pool_is_looked_in_once() {
        // ids 0.. are the data pools d, c and d:ns, then the extra pools x and c ( the zone's data_extra_pool and a
        // data pool ), and d again
        let specs = ["d", "c", "d:ns", "x", "c", "d"];
        let key = |p: usize| parse_pool(specs[p]);
        let (data, extra) = ([0, 1, 2], [3, 4, 5]);
        assert_eq!(distinct_pools(&data, key), [0, 1, 2], "a namespace is a pool of its own");
        // the first pool, then the rest: each at its first place
        assert_eq!(distinct_pools(&[data, extra].concat(), key), [0, 1, 2, 3]);
        assert_eq!(distinct_pools(&[extra, data].concat(), key), [3, 4, 5, 2]);
        // as the zone escapes them: one pool, however it is written
        let specs = [r"\a", "a", r"a\:b"];
        assert_eq!(distinct_pools(&[0, 1, 2], |p| parse_pool(specs[p])), [0, 2]);
        assert!(distinct_pools(&[], key).is_empty());
    }
}
