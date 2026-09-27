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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stat {
    Found { pool: PoolId, size: u64, mtime: i64 },
    Missing,
    Error(i32),
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Stat an object in the data pools: the first one, then the others.
    async fn stat(&self, oid: &str) -> Stat;

    /// The pool an object is in, its size and its mtime.
    async fn find(&self, oid: &str, pools: Pools) -> Option<(PoolId, u64, i64)>;

    /// An xattr's value, or None if the object or the xattr is missing.
    async fn getxattr(&self, pool: PoolId, oid: &str, name: &str) -> Result<Option<Vec<u8>>>;

    /// The omap keys of an object in a pool that start with a prefix.
    async fn omap_keys(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<String>>>;

    /// The same, for an object in a placement target's index pool.
    async fn index_keys(&self, placement: &str, oid: &str, prefix: &str) -> Result<Option<Vec<String>>>;

    /// The major versions the cluster's RGWs and OSDs run.
    async fn majors(&self) -> Result<BTreeSet<u32>>;

    /// A config option, as this client sees it.
    fn conf_get(&self, name: &str) -> Option<String>;
}

/// An in-memory Store, for tests.
#[derive(Default)]
pub struct MockStore {
    /// pool 0.. are the data pools, then the extra pools; "index" objects are
    /// looked up by placement
    pub pools: usize,
    pub extra: usize,
    pub objects: HashMap<(usize, String), MockObject>,
    pub index: HashMap<(String, String), Vec<String>>,
    pub majors: BTreeSet<u32>,
}

#[derive(Default, Clone)]
pub struct MockObject {
    pub size: u64,
    pub mtime: i64,
    pub xattrs: HashMap<String, Vec<u8>>,
    pub omap: Vec<String>,
}

impl MockStore {
    pub fn new(pools: usize, extra: usize) -> MockStore {
        MockStore { pools, extra, ..Default::default() }
    }

    pub fn put(&mut self, pool: usize, oid: &str, obj: MockObject) {
        self.objects.insert((pool, oid.to_string()), obj);
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

#[async_trait]
impl Store for MockStore {
    async fn stat(&self, oid: &str) -> Stat {
        match self.find(oid, Pools::Data).await {
            Some((pool, size, mtime)) => Stat::Found { pool, size, mtime },
            None => Stat::Missing,
        }
    }

    async fn find(&self, oid: &str, pools: Pools) -> Option<(PoolId, u64, i64)> {
        self.order(pools)
            .into_iter()
            .find_map(|p| self.objects.get(&(p, oid.to_string())).map(|o| (PoolId(p), o.size, o.mtime)))
    }

    async fn getxattr(&self, pool: PoolId, oid: &str, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.get(&(pool.0, oid.to_string())).and_then(|o| o.xattrs.get(name).cloned()))
    }

    async fn omap_keys(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<String>>> {
        Ok(self
            .objects
            .get(&(pool.0, oid.to_string()))
            .map(|o| o.omap.iter().filter(|k| k.starts_with(prefix)).cloned().collect()))
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

    fn conf_get(&self, _name: &str) -> Option<String> {
        None
    }
}
