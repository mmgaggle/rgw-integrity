//! Gap lists, verified again: rgw-gap-list.py -x, and what
//! rgw-gap-verify-versioned.sh meant to do.
//!
//! Each line's RADOS object is statted once more in the pools a scan stats
//! in; the lines of what is missing from all of them are kept, as
//! `... STILL MISSING <oid>`.  A stat that fails otherwise than with ENOENT
//! is an error, never a find: its line is kept as it was, unconfirmed.
//!
//! A delete marker has no RADOS object, yet radoslist lists its head, so a
//! gap list of a versioned bucket names every delete marker as missing.
//! rgw-gap-verify-versioned.sh was to drop those lines, but never matches
//! an index entry ( it looks for the key in literal braces, `{key}`, and cuts
//! the instance off only if it is alphanumeric, where RGW's hold '-' and
//! '.' too ), so it drops none.  Here each still missing head's index entry
//! is looked up as the index holds it ( a key starting with '_' escaped, a
//! null version with no instance, in a tenant's bucket by `tenant/bucket` ),
//! and a delete marker's line is dropped.  A head the index holds no entry
//! for is kept, and counted: a lookup that misses must not hide a gap.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use futures::StreamExt;
use serde_json::Value;

use crate::admin::{Admin, FLAG_DELETE_MARKER, IndexEntry};
use crate::gaplist::GapLine;
use crate::oid::{Kind, parse_oid};
use crate::store::Stat;

/// A versioned key's placeholder entry, which lists nothing.
const FLAG_VER_MARKER: u64 = 0x8;

/// Index lookups at once: each is a radosgw-admin process reading every
/// shard of the bucket's index.
const LOOKUPS: usize = 16;

/// The line of an object still missing.  Only the separator becomes
/// ' STILL MISSING ': a ' MISSING ' in the key or the oid is left as it is,
/// and a line verified before is not made ' STILL STILL MISSING '.
pub fn still_line(g: &GapLine) -> String {
    render(g, "STILL MISSING")
}

/// The line of an object whose stat failed: as a gap list writes it, to
/// verify again.
pub fn unconfirmed_line(g: &GapLine) -> String {
    render(g, "MISSING")
}

fn render(g: &GapLine, sep: &str) -> String {
    format!("{}{}/{} {sep} {}", if g.s3 { "s3://" } else { "" }, g.bucket, g.display_key(), g.oid)
}

/// The key's name as the index holds it.
fn index_name(key: &str) -> String {
    if key.starts_with('_') { format!("_{key}") } else { key.to_string() }
}

/// The instance a version's listing entry holds: none for the null version.
fn index_instance(g: &GapLine) -> &str {
    match g.instance.as_deref() {
        None | Some("null") => "",
        Some(i) => i,
    }
}

/// What the index holds of a head that is still missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indexed {
    /// a listing entry: the key is listed, and its head is gone
    Listed,
    /// a delete marker, which has no head: no gap
    DeleteMarker,
    /// no listing entry: the key was deleted since, or is held in a form
    /// not looked for
    Unlisted,
}

/// Judge a still missing head by the entries the index holds of its name.
/// A null delete marker a later version replaced is listed still, but the
/// head is then the OLH, which GET without versionId reads: listed.
pub fn indexed(g: &GapLine, entries: &[IndexEntry]) -> Indexed {
    let (name, instance) = (index_name(&g.key), index_instance(g));
    let entry = entries
        .iter()
        // a versioned key's placeholder ( flag VER_MARKER ) is not a listing entry
        .find(|e| (e.kind == "plain" || e.kind == "instance") && e.name == name && e.instance == instance && e.flags & FLAG_VER_MARKER == 0);
    let replaced = || instance.is_empty() && entries.iter().any(|o| o.kind == "olh" && o.exists && o.flags & FLAG_DELETE_MARKER == 0);
    match entry {
        Some(e) if e.flags & FLAG_DELETE_MARKER != 0 && !replaced() => Indexed::DeleteMarker,
        Some(_) => Indexed::Listed,
        None => Indexed::Unlisted,
    }
}

/// The index entries of a name, as `bi list --object` prints them.
pub async fn index_entries(admin: &Admin, bucket: &str, name: &str) -> Result<Vec<IndexEntry>> {
    let entries: Vec<Value> = admin.json(&["bi", "list", &format!("--bucket={bucket}"), &format!("--object={name}")]).await?;
    Ok(entries.iter().map(IndexEntry::from_value).collect())
}

/// How many lines came to what.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub still: u64,
    pub found: u64,
    /// stats that failed otherwise than with ENOENT
    pub errors: u64,
    /// whether the heads' index entries were looked up
    pub looked_up: bool,
    pub delete_markers: u64,
    pub unlisted: u64,
    /// heads still missing whose index entry could not be read
    pub lookup_errors: u64,
    /// lines read more than once
    pub duplicates: u64,
}

impl Summary {
    /// Whether anything is still missing, or could not be verified.
    pub fn failed(&self) -> bool {
        self.still > 0 || self.errors > 0 || self.lookup_errors > 0
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} still missing, {} found, {} errors", self.still, self.found, self.errors)?;
        if self.looked_up {
            write!(f, "; {} delete markers dropped", self.delete_markers)?;
            if self.unlisted > 0 {
                write!(f, ", {} still missing heads not in the index", self.unlisted)?;
            }
            if self.lookup_errors > 0 {
                write!(f, ", {} index lookups failed", self.lookup_errors)?;
            }
        }
        if self.duplicates > 0 {
            write!(f, " ( {} duplicate lines read once )", self.duplicates)?;
        }
        Ok(())
    }
}

/// The lines to write, in the order read, and the summary.
#[derive(Debug, Default)]
pub struct Verified {
    pub lines: Vec<String>,
    pub summary: Summary,
}

/// Stat each line's object with `stat`; with `lookup` ( the index entries
/// of a bucket's index name ), drop the delete markers' heads.
pub async fn verify<S, SF, L, LF>(gaps: Vec<GapLine>, stat: S, lookup: Option<L>, inflight: usize) -> Verified
where
    S: Fn(String) -> SF,
    SF: Future<Output = Stat>,
    L: Fn(String, String) -> LF,
    LF: Future<Output = Result<Vec<IndexEntry>>>,
{
    let mut summary = Summary { looked_up: lookup.is_some(), ..Default::default() };
    // several runs' lists, catted together, name the same objects
    let read = gaps.len();
    let mut seen = HashSet::new();
    let gaps: Vec<GapLine> = gaps.into_iter().filter(|g| seen.insert(still_line(g))).collect();
    summary.duplicates = (read - gaps.len()) as u64;
    let stats: Vec<(GapLine, Stat)> = futures::stream::iter(gaps)
        .map(|g| {
            let s = stat(g.oid.clone());
            async move { (g, s.await) }
        })
        .buffered(inflight.max(1))
        .collect()
        .await;
    // the index entries of the still missing heads' names, once per name
    let mut entries: HashMap<(String, String), Result<Vec<IndexEntry>, String>> = HashMap::new();
    if let Some(lookup) = &lookup {
        let names: HashSet<(String, String)> = stats
            .iter()
            .filter(|(g, s)| *s == Stat::Missing && parse_oid(&g.oid).kind == Kind::Head)
            .map(|(g, _)| (g.bucket.clone(), index_name(&g.key)))
            .collect();
        entries = futures::stream::iter(names)
            .map(|(bucket, name)| {
                let l = lookup(bucket.clone(), name.clone());
                async move { ((bucket, name), l.await.map_err(|e| format!("{e:#}"))) }
            })
            .buffer_unordered(LOOKUPS)
            .collect()
            .await;
    }
    let mut lines = Vec::new();
    for (g, s) in stats {
        match s {
            Stat::Found { .. } => summary.found += 1,
            Stat::Error(r) => {
                tracing::error!("stat of {}: {}", g.oid, std::io::Error::from_raw_os_error(-r));
                summary.errors += 1;
                lines.push(unconfirmed_line(&g));
            }
            Stat::Missing => {
                // a delete marker has no tail: only a head's line can be one
                let head = parse_oid(&g.oid).kind == Kind::Head;
                let judged = match entries.get(&(g.bucket.clone(), index_name(&g.key))).filter(|_| head) {
                    Some(Ok(e)) => Some(indexed(&g, e)),
                    Some(Err(e)) => {
                        tracing::error!("the index entry of {}/{}: {e}", g.bucket, g.display_key());
                        summary.lookup_errors += 1;
                        None
                    }
                    None => None,
                };
                match judged {
                    Some(Indexed::DeleteMarker) => {
                        tracing::info!("a delete marker, dropped: {}", g.raw);
                        summary.delete_markers += 1;
                        continue;
                    }
                    Some(Indexed::Unlisted) => {
                        tracing::warn!("{}/{}: not in the index ( deleted since the list was written? ); kept", g.bucket, g.display_key());
                        summary.unlisted += 1;
                    }
                    Some(Indexed::Listed) | None => {}
                }
                summary.still += 1;
                lines.push(still_line(&g));
            }
        }
    }
    Verified { lines, summary }
}

/// Write the lines to `path` whole, through a temporary file, so an input
/// it replaces is read in full first.  With no lines nothing is written,
/// and an earlier output is removed, unless it is one of the `inputs`.
pub fn write_lines(path: &Path, lines: &[String], inputs: &[PathBuf]) -> Result<bool> {
    if lines.is_empty() {
        let is_input = std::fs::canonicalize(path).is_ok_and(|p| inputs.iter().any(|i| std::fs::canonicalize(i).is_ok_and(|i| i == p)));
        if !is_input {
            std::fs::remove_file(path).ok();
        }
        return Ok(false);
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaplist::{parse_line, read};
    use crate::store::PoolId;

    const M: &str = "1b14fa0e-7ecf-44dd-8b56-ba8e1473a227.4200.8";
    // RGW's version ids hold '-' and '.' too
    const V: &str = "Dm-3.kQx9ZyXwVuTsRqPoNmLkJiHgFeD";

    fn line(l: &str) -> GapLine {
        parse_line(l).unwrap_or_else(|| panic!("{l}"))
    }

    fn entry(kind: &str, name: &str, instance: &str, flags: u64) -> IndexEntry {
        IndexEntry { kind: kind.into(), name: name.into(), instance: instance.into(), flags, ..Default::default() }
    }

    #[test]
    fn still_lines() {
        for (input, want) in [
            (format!("s3://b/k MISSING {M}_k"), format!("s3://b/k STILL MISSING {M}_k")),
            // verified before: not STILL STILL
            (format!("s3://b/k STILL MISSING {M}_k"), format!("s3://b/k STILL MISSING {M}_k")),
            // only the separator, not the key's or the oid's ' MISSING '
            (format!("s3://b/a MISSING b MISSING {M}_a MISSING b"), format!("s3://b/a MISSING b STILL MISSING {M}_a MISSING b")),
            // upstream -x's, whose re.sub made every one ' STILL MISSING '
            (format!("s3://b/a STILL MISSING b STILL MISSING {M}_a STILL MISSING b"), format!("s3://b/a MISSING b STILL MISSING {M}_a MISSING b")),
            (format!("Not Versioned Instance: b/k[{V}] MISSING {M}__:{V}_k"), format!("b/k[{V}] STILL MISSING {M}__:{V}_k")),
            (format!("s3://t/b/d/k MISSING {M}_d/k"), format!("s3://t/b/d/k STILL MISSING {M}_d/k")),
        ] {
            let out = still_line(&line(&input));
            assert_eq!(out, want, "{input}");
            // it reads back as the same object, still missing
            let back = line(&out);
            assert!(back.still && back.exact, "{out}");
            let g = line(&input);
            assert_eq!((back.display_key(), back.bucket, back.oid), (g.display_key(), g.bucket, g.oid));
        }
        assert_eq!(unconfirmed_line(&line(&format!("s3://b/k STILL MISSING {M}_k"))), format!("s3://b/k MISSING {M}_k"));
    }

    #[test]
    fn delete_markers() {
        let head = line(&format!("s3://b/photo.jpg[{V}] MISSING {M}__:{V}_photo.jpg"));
        // a versioned key: its placeholder, its version's listing entry and instance entry, its OLH
        let dm = [
            entry("plain", "photo.jpg", "", 0x8),
            entry("plain", "photo.jpg", V, 0x7),
            entry("instance", "photo.jpg", V, 0x7),
            entry("olh", "photo.jpg", "", 0),
        ];
        assert_eq!(indexed(&head, &dm), Indexed::DeleteMarker);
        let live = [entry("plain", "photo.jpg", "", 0x8), entry("plain", "photo.jpg", V, 0x3), entry("instance", "photo.jpg", V, 0x3)];
        assert_eq!(indexed(&head, &live), Indexed::Listed);
        // another version's entries, and the placeholder alone, list nothing of this one
        assert_eq!(indexed(&head, &[entry("plain", "photo.jpg", "other", 0x7), entry("plain", "photo.jpg", "", 0xc)]), Indexed::Unlisted);
        // the index holds a key starting with '_' escaped
        let under = line(&format!("s3://b/_u[{V}] MISSING {M}__:{V}__u"));
        assert_eq!(indexed(&under, &[entry("plain", "_u", V, 0x7)]), Indexed::Unlisted);
        assert_eq!(indexed(&under, &[entry("plain", "__u", V, 0x7)]), Indexed::DeleteMarker);
        // a null version is held with no instance
        let null = line(&format!("s3://b/k[null] MISSING {M}_k"));
        assert_eq!(indexed(&null, &[entry("plain", "k", "", 0x8), entry("instance", "k", "", 0x7)]), Indexed::DeleteMarker);
        // a null delete marker a later version replaced: its head is the OLH, which names that version
        let olh = |instance: &str, flags| IndexEntry { exists: true, ..entry("olh", "k", instance, flags) };
        let replaced = [entry("plain", "k", "", 0x8), entry("instance", "k", "", 0x5), entry("instance", "k", V, 0x3), olh(V, 0)];
        assert_eq!(indexed(&null, &replaced), Indexed::Listed);
        assert_eq!(indexed(&line(&format!("s3://b/k MISSING {M}_k")), &replaced), Indexed::Listed);
        // one still current: the OLH names a delete marker
        assert_eq!(indexed(&null, &[entry("plain", "k", "", 0x8), entry("instance", "k", "", 0x7), olh("", 0x4)]), Indexed::DeleteMarker);
        // an unversioned key
        let plain = line(&format!("s3://b/k MISSING {M}_k"));
        assert_eq!(indexed(&plain, &[entry("plain", "k", "", 0)]), Indexed::Listed);
        assert_eq!(indexed(&plain, &[]), Indexed::Unlisted);
    }

    type Lookup = fn(String, String) -> std::future::Ready<Result<Vec<IndexEntry>>>;

    fn found() -> Stat {
        Stat::Found { pool: PoolId(0), size: 1, mtime: 0 }
    }

    #[tokio::test]
    async fn verifies() {
        let text = format!(
            "s3://b/gone MISSING {M}__shadow_.x_1\n\
             s3://b/gone MISSING {M}__shadow_.x_1\n\
             s3://b/back MISSING {M}__shadow_.y_1\n\
             s3://b/eio MISSING {M}__shadow_.z_1\n\
             s3://b/dm[{V}] MISSING {M}__:{V}_dm\n\
             s3://t/b/_v[{V}] MISSING {M}__:{V}__v\n\
             s3://b/del MISSING {M}_del\n\
             s3://b/bad[{V}] MISSING {M}__:{V}_bad\n\
             s3://b/dm[{V}] MISSING {M}__multipart:{V}_dm.2~up.1\n"
        );
        let gaps = read(&text).unwrap().gaps;
        let stat = |oid: String| async move {
            if oid.ends_with(".y_1") {
                found()
            } else if oid.ends_with(".z_1") {
                Stat::Error(-libc::EIO)
            } else {
                Stat::Missing
            }
        };
        let v = verify(gaps.clone(), stat, None::<Lookup>, 2).await;
        assert_eq!(v.summary, Summary { still: 6, found: 1, errors: 1, duplicates: 1, ..Default::default() });
        assert!(v.summary.failed());
        assert_eq!(v.summary.to_string(), "6 still missing, 1 found, 1 errors ( 1 duplicate lines read once )");
        assert_eq!(v.lines[0], format!("s3://b/gone STILL MISSING {M}__shadow_.x_1"));
        assert_eq!(v.lines[1], format!("s3://b/eio MISSING {M}__shadow_.z_1"), "an error is no find, and is kept unconfirmed");

        let asked = std::sync::Mutex::new(Vec::new());
        let lookup = |bucket: String, name: String| {
            asked.lock().unwrap().push(format!("{bucket} {name}"));
            let entries = match (bucket.as_str(), name.as_str()) {
                ("b", "dm") => Ok(vec![entry("plain", "dm", "", 0x8), entry("plain", "dm", V, 0x7)]),
                ("t/b", "__v") => Ok(vec![entry("instance", "__v", V, 0x7)]),
                ("b", "del") => Ok(Vec::new()),
                _ => Err(anyhow::anyhow!("radosgw-admin failed")),
            };
            async move { entries }
        };
        let v = verify(gaps, stat, Some(lookup), 2).await;
        let s = &v.summary;
        assert_eq!((s.still, s.found, s.errors, s.delete_markers, s.unlisted, s.lookup_errors), (4, 1, 1, 2, 1, 1));
        assert_eq!(s.to_string(), "4 still missing, 1 found, 1 errors; 2 delete markers dropped, 1 still missing heads not in the index, 1 index lookups failed ( 1 duplicate lines read once )");
        assert!(!v.lines.iter().any(|l| l.contains(&format!("__:{V}_dm")) || l.contains("_v[")), "{:?}", v.lines);
        // a delete marker has no tail: a tail's line is no delete marker's
        assert!(v.lines.contains(&format!("s3://b/dm[{V}] STILL MISSING {M}__multipart:{V}_dm.2~up.1")));
        assert!(v.lines.contains(&format!("s3://b/del STILL MISSING {M}_del")));
        assert!(v.lines.contains(&format!("s3://b/bad[{V}] STILL MISSING {M}__:{V}_bad")), "a failed lookup hides no gap");
        // only the still missing heads are looked up, a tenant's bucket as tenant/bucket
        let mut asked = asked.into_inner().unwrap();
        asked.sort();
        assert_eq!(asked, ["b bad", "b del", "b dm", "t/b __v"]);

        let v = verify(read(&format!("s3://b/k MISSING {M}_k\n")).unwrap().gaps, |_| async { found() }, None::<Lookup>, 1).await;
        assert!(v.lines.is_empty() && !v.summary.failed());
    }

    /// Upstream's line of a missing head of the key 'k ', next to a key 'k'
    /// that is there: the head statted is the one with the blank.
    #[tokio::test]
    async fn heads_of_keys_ending_in_blanks() {
        let gaps = read(&format!("s3://b/k MISSING {M}_k \n")).unwrap().gaps;
        let stat = |oid: String| async move { if oid.ends_with(' ') { Stat::Missing } else { found() } };
        let v = verify(gaps, stat, None::<Lookup>, 1).await;
        assert_eq!((v.summary.still, v.summary.found), (1, 0));
        assert_eq!(v.lines, [format!("s3://b/k  STILL MISSING {M}_k ")]);
    }

    #[test]
    fn output_files() {
        let dir = std::env::temp_dir().join(format!("rgwi-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (input, out) = (dir.join("in.txt"), dir.join("out.txt"));
        std::fs::write(&input, "old\n").unwrap();
        // in place: the input is replaced, whole
        assert!(write_lines(&input, &["new".into()], std::slice::from_ref(&input)).unwrap());
        assert_eq!(std::fs::read_to_string(&input).unwrap(), "new\n");
        // nothing still missing: no empty file, an earlier output removed, an input kept
        std::fs::write(&out, "stale\n").unwrap();
        assert!(!write_lines(&out, &[], std::slice::from_ref(&input)).unwrap());
        assert!(!out.exists());
        assert!(!write_lines(&input, &[], std::slice::from_ref(&input)).unwrap());
        assert!(input.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
