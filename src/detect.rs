//! Orphan detection: the RADOS objects in the data pools that no bucket's
//! listing references.  Both sides are split into partitions by a hash of
//! the object's name and exchanged through a Shuffle, so no process holds
//! more than a partition: bucket scans file a 16-byte hash of each name
//! they list, pool listings file the names themselves, and a join per
//! partition keeps the names with no reference.

use std::collections::HashSet;
use std::io::{BufRead, Write};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::{xxh3_64, xxh3_128};

use crate::shuffle::Shuffle;

/// How much of a partition's listing to buffer before appending it.
const LIST_FLUSH: usize = 4 << 20;

/// A scan's orphan detection: how many partitions, where they are exchanged,
/// and when the scan began ( objects newer than that are not judged ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub partitions: u32,
    /// the pool ( and namespace ) clients exchange partitions in
    pub work: Option<String>,
    pub created: i64,
}

/// One index shard of a bucket, to scan as a unit of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardUnit {
    pub bucket: String,
    pub shard: u32,
    pub shards: u32,
}

/// A slice of a data pool to list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slice {
    pub pool: String,
    pub slice: usize,
    pub slices: usize,
}

/// A partition to join, and every client that may have written to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Join {
    pub partition: u32,
    pub writers: Vec<String>,
}

/// Classification of the unreferenced objects of some buckets ( by marker ):
/// an unlisted head and its tail, or an upload's parts, share a marker, so
/// they are classified together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classify {
    pub oids: Vec<String>,
}

/// Group candidates into classification units of about `size`, never
/// splitting a marker.
pub fn classification_units(mut candidates: Vec<String>, size: usize) -> Vec<Vec<String>> {
    candidates.sort();
    let mut units: Vec<Vec<String>> = Vec::new();
    let mut last_marker = String::new();
    for oid in candidates {
        let marker = oid.split('_').next().unwrap_or("").to_string();
        let new_marker = marker != last_marker;
        match units.last_mut() {
            Some(u) if !(new_marker && u.len() >= size) => u.push(oid),
            _ => units.push(vec![oid]),
        }
        last_marker = marker;
    }
    units
}

pub fn partition_of(oid: &str, partitions: u32) -> u32 {
    (xxh3_64(oid.as_bytes()) % partitions.max(1) as u64) as u32
}

pub fn ref_hash(oid: &str) -> u128 {
    xxh3_128(oid.as_bytes())
}

/// Partitions for a pool of `objects`: about a million names each.
pub fn partitions_for(objects: u64) -> u32 {
    (objects / 1_000_000 + 1).clamp(1, 4096) as u32
}

/// Slices of a pool of `objects` to list: about half a million objects each.
pub fn slices_for(objects: u64) -> usize {
    (objects / 500_000 + 1).clamp(1, 4096) as usize
}

fn writer_name(w: &str) -> String {
    w.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect()
}

pub fn ref_name(scan: i64, p: u32, writer: &str) -> String {
    format!("s{scan}.p{p}.ref.{}", writer_name(writer))
}

pub fn list_name(scan: i64, p: u32, writer: &str) -> String {
    format!("s{scan}.p{p}.list.{}", writer_name(writer))
}

/// The references one bucket scan files: a hash per name, by partition.
#[derive(Default)]
pub struct Refs {
    parts: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Refs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Refs({} partitions, {} references)", self.parts.len(), self.parts.iter().map(|p| p.len() / 16).sum::<usize>())
    }
}

impl Refs {
    pub fn new(partitions: u32) -> Refs {
        Refs { parts: vec![Vec::new(); partitions.max(1) as usize] }
    }

    pub fn add(&mut self, oid: &str) {
        let n = self.parts.len() as u32;
        self.parts[partition_of(oid, n) as usize].extend_from_slice(&ref_hash(oid).to_le_bytes());
    }

    /// Append each partition's hashes; the scan's report may only follow.
    pub async fn flush(self, shuffle: &dyn Shuffle, scan: i64, writer: &str) -> Result<()> {
        for (p, data) in self.parts.into_iter().enumerate() {
            if !data.is_empty() {
                shuffle.append(&ref_name(scan, p as u32, writer), data).await?;
            }
        }
        Ok(())
    }
}

/// The names one pool listing files, by partition, as gzip members.
pub struct Listing {
    parts: Vec<Vec<u8>>,
    pub listed: u64,
}

fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data)?;
    Ok(e.finish()?)
}

impl Listing {
    pub fn new(partitions: u32) -> Listing {
        Listing { parts: vec![Vec::new(); partitions.max(1) as usize], listed: 0 }
    }

    pub async fn add(&mut self, names: Vec<String>, shuffle: &dyn Shuffle, scan: i64, writer: &str) -> Result<()> {
        let n = self.parts.len() as u32;
        for name in names {
            if name.contains('\n') {
                continue;
            }
            let p = partition_of(&name, n) as usize;
            self.parts[p].extend_from_slice(name.as_bytes());
            self.parts[p].push(b'\n');
            self.listed += 1;
            if self.parts[p].len() >= LIST_FLUSH {
                let data = gzip(&std::mem::take(&mut self.parts[p]))?;
                shuffle.append(&list_name(scan, p as u32, writer), data).await?;
            }
        }
        Ok(())
    }

    pub async fn finish(self, shuffle: &dyn Shuffle, scan: i64, writer: &str) -> Result<u64> {
        for (p, data) in self.parts.into_iter().enumerate() {
            if !data.is_empty() {
                shuffle.append(&list_name(scan, p as u32, writer), gzip(&data)?).await?;
            }
        }
        Ok(self.listed)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct JoinStats {
    pub references: u64,
    pub listed: u64,
    pub unreferenced: u64,
}

/// The names in a partition's listings that nothing references.
pub async fn join(shuffle: &dyn Shuffle, scan: i64, p: u32, writers: &[String]) -> Result<(Vec<String>, JoinStats)> {
    let mut refs: HashSet<u128> = HashSet::new();
    for w in writers {
        if let Some(data) = shuffle.read(&ref_name(scan, p, w)).await? {
            for h in data.chunks_exact(16) {
                refs.insert(u128::from_le_bytes(h.try_into().expect("16 bytes")));
            }
        }
    }
    let mut stats = JoinStats { references: refs.len() as u64, ..Default::default() };
    let mut seen: HashSet<u128> = HashSet::new();
    let mut out = Vec::new();
    for w in writers {
        let Some(data) = shuffle.read(&list_name(scan, p, w)).await? else { continue };
        let reader = std::io::BufReader::new(flate2::read::MultiGzDecoder::new(&data[..]));
        for line in reader.lines() {
            let name = line?;
            let h = ref_hash(&name);
            // a slice listed twice, by a client that died and the one after it
            if !seen.insert(h) {
                continue;
            }
            stats.listed += 1;
            if !refs.contains(&h) {
                out.push(name);
            }
        }
    }
    stats.unreferenced = out.len() as u64;
    out.sort();
    Ok((out, stats))
}

pub async fn cleanup(shuffle: &dyn Shuffle, scan: i64, p: u32, writers: &[String]) -> Result<()> {
    for w in writers {
        shuffle.remove(&ref_name(scan, p, w)).await?;
        shuffle.remove(&list_name(scan, p, w)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffle::LocalShuffle;

    #[tokio::test]
    async fn partitions_join() {
        let dir = std::env::temp_dir().join(format!("rgwi-shuffle-{}-{}", std::process::id(), rand::random::<u32>()));
        let shuffle = LocalShuffle::new(dir.clone()).unwrap();
        let n = 7;
        let pool: Vec<String> = (0..5000).map(|i| format!("m_obj{i}")).collect();
        // two writers reference the even objects between them
        let mut a = Refs::new(n);
        let mut b = Refs::new(n);
        for (i, o) in pool.iter().enumerate().filter(|(i, _)| i % 2 == 0) {
            if i % 4 == 0 { a.add(o) } else { b.add(o) }
        }
        a.flush(&shuffle, 1, "a:1").await.unwrap();
        b.flush(&shuffle, 1, "b:2").await.unwrap();
        // one writer lists everything, another lists a slice again
        let mut l = Listing::new(n);
        l.add(pool.clone(), &shuffle, 1, "a:1").await.unwrap();
        assert_eq!(l.finish(&shuffle, 1, "a:1").await.unwrap(), 5000);
        let mut again = Listing::new(n);
        again.add(pool[..100].to_vec(), &shuffle, 1, "b:2").await.unwrap();
        again.finish(&shuffle, 1, "b:2").await.unwrap();

        let writers = vec!["a:1".to_string(), "b:2".to_string(), "gone:3".to_string()];
        let mut orphans = Vec::new();
        let mut listed = 0;
        for p in 0..n {
            let (o, s) = join(&shuffle, 1, p, &writers).await.unwrap();
            listed += s.listed;
            orphans.extend(o);
            cleanup(&shuffle, 1, p, &writers).await.unwrap();
        }
        orphans.sort();
        let mut want: Vec<String> = pool.iter().enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, o)| o.clone()).collect();
        want.sort();
        assert_eq!(listed, 5000, "a slice listed twice counts once");
        assert_eq!(orphans, want);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "cleaned up");
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn classification_keeps_markers_whole() {
        let c: Vec<String> = ["b_2", "a_1", "a__shadow_.x_1", "c_1", "b__shadow_.y_1", "b__shadow_.y_2"].iter().map(|s| s.to_string()).collect();
        let units = classification_units(c, 2);
        assert_eq!(units, vec![vec!["a_1", "a__shadow_.x_1"], vec!["b_2", "b__shadow_.y_1", "b__shadow_.y_2"], vec!["c_1"]]);
    }

    #[test]
    fn sizing() {
        assert_eq!(partitions_for(0), 1);
        assert_eq!(partitions_for(3_500_000), 4);
        assert_eq!(slices_for(10), 1);
        assert_eq!(slices_for(u64::MAX), 4096);
        assert!(ref_name(3, 4, "host:12/x").ends_with("host_12_x"));
    }
}
