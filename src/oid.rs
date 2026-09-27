//! RGW's RADOS object names, and the Ceph encodings the checks read.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

/// What an RGW data object is, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// an S3 object's head
    Head,
    /// a multipart part's first stripe
    Part,
    /// a multipart part's further stripes
    MpShadow,
    /// an atomic object's tail
    Shadow,
    /// a multipart upload's meta object
    Meta,
    Other,
}

impl Kind {
    pub fn is_multipart(self) -> bool {
        matches!(self, Kind::Part | Kind::MpShadow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid<'a> {
    pub marker: &'a str,
    pub kind: Kind,
    /// for parts and meta objects: the S3 key and the upload id
    pub key: Option<&'a str>,
    pub upload: Option<&'a str>,
}

/// `<key>.<upload>.meta`
fn split_meta(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_suffix(".meta")?;
    let (key, upload) = rest.rsplit_once('.')?;
    (!upload.is_empty()).then_some((key, upload))
}

/// `<key>.<upload>.<part>[_<stripe>]`; upload ids hold no dots
fn split_part(name: &str) -> Option<(&str, &str)> {
    let (rest, last) = name.rsplit_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let ok = match last.split_once('_') {
        Some((part, stripe)) => digits(part) && digits(stripe),
        None => digits(last),
    };
    if !ok {
        return None;
    }
    let (key, upload) = rest.rsplit_once('.')?;
    (!upload.is_empty()).then_some((key, upload))
}

/// Split an RGW data object's name.  Bucket markers hold no underscore.
pub fn parse_oid(oid: &str) -> Oid<'_> {
    let Some((marker, rest)) = oid.split_once('_') else {
        return Oid { marker: oid, kind: Kind::Other, key: None, upload: None };
    };
    let plain = |kind| Oid { marker, kind, key: None, upload: None };
    if let Some(name) = rest.strip_prefix("_multipart_") {
        if let Some((key, upload)) = split_meta(name) {
            return Oid { marker, kind: Kind::Meta, key: Some(key), upload: Some(upload) };
        }
        return match split_part(name) {
            Some((key, upload)) => Oid { marker, kind: Kind::Part, key: Some(key), upload: Some(upload) },
            None => plain(Kind::Part),
        };
    }
    if let Some(name) = rest.strip_prefix("_shadow_") {
        return match split_part(name) {
            Some((key, upload)) => Oid { marker, kind: Kind::MpShadow, key: Some(key), upload: Some(upload) },
            None => plain(Kind::Shadow),
        };
    }
    plain(Kind::Head)
}

/// radoslist names a version as `name[instance]`
pub fn split_key(keystr: &str) -> (&str, &str) {
    if let Some(rest) = keystr.strip_suffix(']') {
        if let Some((name, instance)) = rest.rsplit_once('[') {
            if !instance.contains(']') {
                return (name, instance);
            }
        }
    }
    (keystr, "")
}

/// A head's name after its bucket marker and '_'.
pub fn key_oid(name: &str, instance: &str) -> String {
    if !instance.is_empty() && instance != "null" {
        format!("_:{instance}_{name}")
    } else if name.starts_with('_') {
        format!("_{name}")
    } else {
        name.to_string()
    }
}

/// A head's (name, instance), from its name after the bucket marker and '_'.
/// Instance ids hold no underscore.
pub fn head_key(rest: &str) -> (&str, &str) {
    if let Some(r) = rest.strip_prefix("_:") {
        if let Some((instance, name)) = r.split_once('_') {
            return (name, instance);
        }
    }
    if rest.starts_with("__") {
        return (&rest[1..], "");
    }
    (rest, "")
}

/// The names of a bucket's current index shard objects.
pub fn index_objects(bucket_id: &str, num_shards: u64, generation: u64) -> Vec<String> {
    let base = format!(".dir.{bucket_id}");
    match (num_shards, generation) {
        (0, _) => vec![base],
        (n, 0) => (0..n).map(|i| format!("{base}.{i}")).collect(),
        (n, g) => (0..n).map(|i| format!("{base}.{g}.{i}")).collect(),
    }
}

/// A tag or xattr value as text, without its trailing NULs.
pub fn tag_text(b: &[u8]) -> String {
    let end = b.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// cls_refcount's obj_refcount: its references, and the tags it retired.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refcount {
    pub refs: BTreeMap<String, bool>,
    pub retired: BTreeSet<String>,
}

impl Refcount {
    /// the references a copy or dedup took, not the first writer's implicit one
    pub fn tags(&self) -> impl Iterator<Item = &String> {
        self.refs.keys().filter(|t| !t.is_empty())
    }
}

pub fn decode_refcount(bl: &[u8]) -> Result<Refcount> {
    struct Cur<'a>(&'a [u8], usize);
    impl Cur<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8]> {
            let end = self.1.checked_add(n).filter(|&e| e <= self.0.len()).context("truncated refcount")?;
            let s = &self.0[self.1..end];
            self.1 = end;
            Ok(s)
        }
        fn u32(&mut self) -> Result<u32> {
            Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
        }
        fn string(&mut self) -> Result<String> {
            let n = self.u32()? as usize;
            Ok(tag_text(self.take(n)?))
        }
    }
    let mut c = Cur(bl, 0);
    let version = c.take(1)?[0];
    c.take(1)?; // compat
    let len = c.u32()? as usize;
    let end = 6 + len;
    if end > bl.len() {
        bail!("refcount length {len} past its {} bytes", bl.len());
    }
    let mut rc = Refcount::default();
    for _ in 0..c.u32()? {
        let t = c.string()?;
        let v = c.take(1)?[0] != 0;
        rc.refs.insert(t, v);
    }
    if version >= 2 && c.1 < end {
        for _ in 0..c.u32()? {
            rc.retired.insert(c.string()?);
        }
    }
    Ok(rc)
}

/// Whether an object survives GC putting each tag, as cls_refcount does: a
/// tag drops its own reference, or else the first writer's implicit one.
/// No refcount attribute means that implicit reference alone.
pub fn survives_gc<'a>(tags: impl IntoIterator<Item = &'a str>, refcount: Option<&Refcount>) -> bool {
    let mut rc = refcount.cloned().unwrap_or_else(|| Refcount {
        refs: BTreeMap::from([(String::new(), true)]),
        retired: BTreeSet::new(),
    });
    for t in tags {
        if rc.retired.contains(t) {
            continue;
        }
        if rc.refs.remove(t).is_none() && rc.refs.remove("").is_none() {
            continue;
        }
        rc.retired.insert(t.to_string());
        if rc.refs.is_empty() {
            return false;
        }
    }
    true
}

/// The epoch of a `2026-09-26T10:00:00...` or `2026-09-26 10:00:00...` UTC time.
pub fn parse_time(text: &str) -> Option<i64> {
    let t = text.get(..19)?.replace('T', " ");
    chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%d %H:%M:%S").ok().map(|d| d.and_utc().timestamp())
}

pub fn iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "1b14fa0e-7ecf-44dd-8b56-ba8e1473a227.4200.8";
    const UP: &str = "2~9wJL7tK7u4D4KqIaxd8eXjZUQdK38RW";

    #[test]
    fn kinds() {
        let cases = [
            (format!("{M}_obj"), Kind::Head, None, None),
            (format!("{M}___shadow_x"), Kind::Head, None, None),
            (format!("{M}__:Y8tL7MyndszuwTxg4Itgx6eICC1bm9p_gone"), Kind::Head, None, None),
            (format!("{M}__shadow_.QmeTJR66RPFocC7r5-Uu_Tn4Kpp4X_1"), Kind::Shadow, None, None),
            (format!("{M}__multipart_a.b.{UP}.2"), Kind::Part, Some("a.b"), Some(UP)),
            (format!("{M}__shadow_a.b.{UP}.2_1"), Kind::MpShadow, Some("a.b"), Some(UP)),
            (format!("{M}__multipart_a.b.{UP}.meta"), Kind::Meta, Some("a.b"), Some(UP)),
        ];
        for (oid, kind, key, upload) in cases {
            let o = parse_oid(&oid);
            assert_eq!((o.marker, o.kind, o.key, o.upload), (M, kind, key, upload), "{oid}");
        }
        assert_eq!(parse_oid("nounderscore").kind, Kind::Other);
    }

    #[test]
    fn keys() {
        assert_eq!(split_key("obj[abc]"), ("obj", "abc"));
        assert_eq!(split_key("obj"), ("obj", ""));
        assert_eq!(key_oid("obj", ""), "obj");
        assert_eq!(key_oid("_obj", ""), "__obj");
        assert_eq!(key_oid("obj", "null"), "obj");
        assert_eq!(key_oid("obj", "abc"), "_:abc_obj");
        for rest in ["obj", "__obj", "_:abc_obj"] {
            let (name, inst) = head_key(rest);
            assert_eq!(key_oid(name, inst), rest);
        }
        assert_eq!(index_objects("x", 0, 0), vec![".dir.x"]);
        assert_eq!(index_objects("x", 2, 0), vec![".dir.x.0", ".dir.x.1"]);
        assert_eq!(index_objects("x", 2, 3), vec![".dir.x.3.0", ".dir.x.3.1"]);
    }

    fn encode(refs: &[&str], retired: &[&str], version: u8) -> Vec<u8> {
        let s = |t: &str| {
            let mut v = (t.len() as u32).to_le_bytes().to_vec();
            v.extend_from_slice(t.as_bytes());
            v
        };
        let mut body = (refs.len() as u32).to_le_bytes().to_vec();
        for r in refs {
            body.extend(s(r));
            body.push(1);
        }
        if version >= 2 {
            body.extend((retired.len() as u32).to_le_bytes());
            for r in retired {
                body.extend(s(r));
            }
        }
        let mut out = vec![version, 1];
        out.extend((body.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn refcount() {
        let rc = decode_refcount(&encode(&["", "copy\0"], &["old\0"], 2)).unwrap();
        assert_eq!(rc.refs.keys().collect::<Vec<_>>(), ["", "copy"]);
        assert!(rc.retired.contains("old"));
        let rc = decode_refcount(&encode(&["a"], &[], 1)).unwrap();
        assert!(rc.retired.is_empty());
        assert!(decode_refcount(&[2, 1, 99, 0, 0, 0]).is_err());

        assert!(!survives_gc(["t"], None));
        let copy = decode_refcount(&encode(&["", "copy"], &[], 2)).unwrap();
        assert!(survives_gc(["src"], Some(&copy)));
        assert!(!survives_gc(["src", "copy"], Some(&copy)));
        let retired = Refcount { refs: BTreeMap::from([(String::new(), true)]), retired: BTreeSet::from(["copy".into()]) };
        assert!(survives_gc(["copy"], Some(&retired)));
    }

    #[test]
    fn times() {
        let t = parse_time("2026-09-26T23:12:18.123456Z").unwrap();
        assert_eq!(iso(t), "2026-09-26T23:12:18Z");
        assert_eq!(parse_time("2026-09-26 23:12:18.1"), Some(t));
        assert_eq!(parse_time("garbage"), None);
    }
}
