//! Upstream's gap lists, read back: the results of rgw-gap-list.py and of the
//! tools around it, as lines to verify again or as findings to import.
//!
//! The forms read, one per line:
//!
//! - rgw-gap-list.py ( v2.2, and v3.0's text file ): `s3://<bucket>/<key> MISSING <oid>`
//! - its `-x` verify: `s3://<bucket>/<key> STILL MISSING <oid>`, with every
//!   ' MISSING ' made ' STILL MISSING ', the key's and the oid's too
//! - rgw-gap-verify-versioned.sh: either, after `Not Versioned Instance: `
//! - rgw-gap-list-by-bucket: `<bucket>/<key> MISSING <oid>`, with no scheme
//! - v3.0's results objects: JSON records `{epoch, bucket, user_object, rados_object}`,
//!   one per line or as arrays
//!
//! The key is radoslist's: a version is `name[instance]` ( rgw_obj_key's
//! operator<< ), and the bucket can be `tenant/bucket`.  Keys hold anything,
//! ' MISSING ' and '/' too, so a line is not split on the first or last of
//! either: the oid names the key ( `<marker>_<key>`, a part's
//! `<marker>__multipart_<key>.<upload>.<n>` ), and the split whose key the
//! oid names is the one taken.  An oid that names no key ( an atomic tail's
//! `<marker>__shadow_.<random>_<n>` ) is split as upstream splits it, unless
//! a line of the same object that does name it settles the split ( resolve;
//! the same object's, as its oid carries the same bucket marker ).
//! Only a head's oid is the key's own: a copy shares its source's parts and
//! tails, named by the source's key, so only a head splits off a tenant.
//!
//! So a tenant's `s3://t/b/<key>` lines ( rgw-integrity's, v3.0's ) read as
//! bucket `t/b` for a head's line, and for the lines an exact one settles;
//! a part's or a tail's line with no such line beside it reads as bucket
//! `t`, key `b/<key>`, until the cluster's bucket names settle it (
//! settle_tenants: `t/b` if there is such a bucket, else `t` ).  v3.0's
//! records name the bucket apart.  v2.2 writes radoslist's bucket column,
//! which names no tenant, so its lines of `t/b`
//! read as bucket `b`: their findings are neither cleared by a scan of
//! `t/b` nor kept from a scan of a global bucket `b` clearing them.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use anyhow::{Context as _, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::admin::Admin;
use crate::finding::{Class, Finding};
use crate::oid::{Kind, head_key, parse_oid, split_key};

/// What rgw-gap-verify-versioned.sh puts before the lines of objects the
/// index holds no versioned entry for.
pub const NOT_VERSIONED: &str = "Not Versioned Instance: ";

/// One missing RADOS object, as an upstream gap list names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapLine {
    /// as radoslist names it: `bucket`, or `tenant/bucket`
    pub bucket: String,
    /// the S3 object's name, without its version
    pub key: String,
    /// the version, for a key written `name[instance]`
    pub instance: Option<String>,
    pub oid: String,
    /// verified missing again by rgw-gap-list.py -x: ` STILL MISSING `
    pub still: bool,
    /// prefixed with NOT_VERSIONED by rgw-gap-verify-versioned.sh
    pub unversioned: bool,
    /// written `s3://<bucket>/<key>`; rgw-gap-list-by-bucket leaves out the scheme
    pub s3: bool,
    /// the oid names the key, so the split is certain; otherwise it is the
    /// split upstream makes
    pub exact: bool,
    /// the line, or the JSON record, as read
    pub raw: String,
}

impl GapLine {
    /// The key as radoslist and rgw-integrity's findings name it: `name[instance]` for a version.
    pub fn display_key(&self) -> String {
        match &self.instance {
            Some(i) => format!("{}[{i}]", self.key),
            None => self.key.clone(),
        }
    }

    fn is_head(&self) -> bool {
        parse_oid(&self.oid).kind == Kind::Head
    }
}

/// The line, as the tool that wrote it writes it; with `still` set, as
/// rgw-gap-list.py -x writes what it found missing again ( every ' MISSING '
/// made ' STILL MISSING ' ).
impl fmt::Display for GapLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prefix = if self.unversioned { NOT_VERSIONED } else { "" };
        let scheme = if self.s3 { "s3://" } else { "" };
        let line = format!("{scheme}{}/{} MISSING {}", self.bucket, self.display_key(), self.oid);
        match self.still {
            true => write!(f, "{prefix}{}", line.replace(" MISSING ", " STILL MISSING ")),
            false => write!(f, "{prefix}{line}"),
        }
    }
}

/// The oid's instance, when a tail's namespace carries it: `_<ns>:<instance>_<name>`.
fn tail_instance(rest: &str) -> Option<&str> {
    let r = rest.strip_prefix('_')?;
    let (_, after) = r.split_at(r.find(['_', ':'])?);
    after.strip_prefix(':')?.split_once('_').map(|(i, _)| i)
}

/// The key's (name, instance), if the oid names the key.  None: it names
/// another, or none ( an atomic tail, an oid that is no RGW data object's ).
fn names<'a>(key: &'a str, oid: &str) -> Option<(&'a str, Option<&'a str>)> {
    let o = parse_oid(oid);
    let rest = oid.get(o.marker.len() + 1..)?;
    let (name, instance) = split_key(key);
    let version = (!instance.is_empty()).then_some(instance);
    // a name the oid carries: the whole key, or a version's name
    let named = |n: &str, oi: Option<&str>| match oi {
        Some(i) => (version == Some(i) && n == name).then_some((name, version)),
        None if n == key => Some((key, None)),
        None => (version.is_some() && n == name).then_some((name, version)),
    };
    match o.kind {
        Kind::Head => {
            // a null version's head carries no instance
            let (n, i) = head_key(rest);
            named(n, (!i.is_empty()).then_some(i)).or_else(|| (n == key).then_some((key, None)))
        }
        Kind::Part | Kind::MpShadow | Kind::Meta => named(o.key?, tail_instance(rest)),
        // an appendable object's tails: `<key>.<random>_<n>`
        Kind::Shadow => {
            let r = rest.strip_prefix("_shadow")?;
            let tail = r.strip_prefix('_').or_else(|| r.strip_prefix(':')?.split_once('_').map(|(_, t)| t))?;
            let (n, _) = tail.rsplit_once('.')?;
            named(n, tail_instance(rest))
        }
        Kind::Other => None,
    }
}

/// The readings of a line after its prefix and scheme: (bucket/key, still,
/// oid) at each ' MISSING ', the last first, as upstream's `^.* MISSING `.
/// `undone`: the text is a -x line with its ' STILL's taken out, so still.
fn readings(text: &str, undone: bool) -> Vec<(&str, bool, &str)> {
    let sep = " MISSING ";
    let mut out = Vec::new();
    for (p, _) in text.rmatch_indices(sep) {
        let (left, oid) = (&text[..p], &text[p + sep.len()..]);
        if !undone && let Some(l) = left.strip_suffix(" STILL") {
            out.push((l, true, oid));
        }
        out.push((left, undone, oid));
    }
    out
}

/// Whether rgw-gap-list.py -x can have written the text: it writes a line
/// again with re.sub(' MISSING ', ' STILL MISSING '), so every ' MISSING '
/// in it, the key's and the oid's too, follows a ' STILL'.
fn rewritten(text: &str) -> bool {
    text.contains(" MISSING ") && text.match_indices(" MISSING ").all(|(p, _)| text[..p].ends_with(" STILL"))
}

/// The (bucket, key) splits of `bucket/key`: at the first '/', then, for a
/// head's oid, at the second, for `tenant/bucket`.  Bucket and tenant names
/// hold no '/'; a part's or a tail's oid can name another key than the one
/// it is listed under ( a copy's source ), so it splits no tenant off.
fn splits(left: &str, head: bool) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut slashes = left.match_indices('/').map(|(p, _)| p);
    if let Some(p) = slashes.next() {
        if p > 0 && p + 1 < left.len() {
            out.push((&left[..p], &left[p + 1..]));
        }
        if let Some(q) = slashes.next()
            && head
            && q > p + 1
            && q + 1 < left.len()
        {
            out.push((&left[..q], &left[q + 1..]));
        }
    }
    out
}

/// Parse one line of an upstream gap list: None if it is not one.  The
/// split is `exact` when the oid names the key; else it is upstream's ( the
/// last ' MISSING ', the first '/' ), and `resolve` can settle it.
pub fn parse_line(line: &str) -> Option<GapLine> {
    parse_with(line, &Known::new())
}

/// A head's key that is `key` with the trailing blanks its oid keeps:
/// rgw-gap-list.py ( v2.2, v3.0's text ) strips the radoslist line it builds
/// each line from, which loses the key's trailing blanks but not the
/// oid's, `s3://b/k MISSING <marker>_k ` for the key 'k '.
fn blank_ended<'a>(key: &str, oid: &'a str) -> Option<&'a str> {
    let rest = oid.get(parse_oid(oid).marker.len() + 1..)?;
    let (name, instance) = head_key(rest);
    (instance.is_empty() && name != key && name.trim_end() == key).then_some(name)
}

/// The split a list's exact lines settle: `bucket/key` as written, and the
/// marker of their oids, to (bucket, key, instance).
type Known = HashMap<(String, String), (String, String, Option<String>)>;

/// `known`: what the exact lines of a list settle ( see Known ).
fn parse_with(line: &str, known: &Known) -> Option<GapLine> {
    let raw = line.trim_start();
    let (unversioned, rest) = match raw.strip_prefix(NOT_VERSIONED) {
        Some(r) => (true, r),
        None => (false, raw),
    };
    let (s3, rest) = match rest.strip_prefix("s3://") {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let gap = |bucket: &str, key: &str, instance: Option<&str>, oid: &str, still, exact| GapLine {
        bucket: bucket.to_string(),
        key: key.to_string(),
        instance: instance.map(str::to_string),
        oid: oid.to_string(),
        still,
        unversioned,
        s3,
        exact,
        raw: line.to_string(),
    };
    // upstream's -x writes its lines stripped: a key's trailing blanks are lost
    let trimmed = rest.trim_end();
    let mut bases = vec![rest];
    if trimmed != rest {
        bases.push(trimmed);
    }
    // the texts to read, and whether each is a -x line undone: those first
    let mut texts: Vec<(String, bool)> = Vec::new();
    if rewritten(rest) {
        texts.extend(bases.iter().map(|t| (t.replace(" STILL MISSING ", " MISSING "), true)));
    }
    texts.extend(bases.iter().map(|t| (t.to_string(), false)));
    for (text, undone) in &texts {
        for (left, still, oid) in readings(text, *undone) {
            let head = parse_oid(oid).kind == Kind::Head;
            for (bucket, key) in splits(left, head) {
                if let Some((name, instance)) = names(key, oid) {
                    return Some(gap(bucket, name, instance, oid, still, true));
                }
                // the untrimmed text is read first: its oid keeps the blanks ( -x's is stripped again, so lost them )
                if head
                    && !*undone
                    && !rewritten(rest)
                    && let Some(name) = blank_ended(key, oid)
                {
                    return Some(gap(bucket, name, None, oid, still, true));
                }
            }
        }
    }
    for (text, undone) in &texts {
        for (left, still, oid) in readings(text, *undone) {
            // a line of another bucket's object can read the same: a global bucket t's key b/k, a tenant's t/b's k
            if let Some((bucket, key, instance)) = known.get(&(left.to_string(), parse_oid(oid).marker.to_string())) {
                return Some(gap(bucket, key, instance.as_deref(), oid, still, true));
            }
        }
    }
    // upstream's split, of the stripped text read first
    let (text, undone) = &texts[bases.len() - 1];
    let &(left, still, oid) = readings(text, *undone).first()?;
    let (bucket, key) = *splits(left, false).first()?;
    let (name, instance) = split_key(key);
    Some(gap(bucket, name, (!instance.is_empty()).then_some(instance), oid, still, false))
}

/// Settle the split of the lines the oid did not: the same object's `bucket/key`
/// is written the same on every line, so a line whose oid names the key
/// splits the others of its bucket, those whose oids carry the same marker
/// ( a tail copied from another bucket carries its source's, and keeps
/// upstream's split ).
pub fn resolve(gaps: &mut [GapLine]) {
    let known: Known = gaps
        .iter()
        .filter(|g| g.exact)
        .map(|g| {
            let text = format!("{}/{}", g.bucket, g.display_key());
            ((text, parse_oid(&g.oid).marker.to_string()), (g.bucket.clone(), g.key.clone(), g.instance.clone()))
        })
        .collect();
    if known.is_empty() {
        return;
    }
    for g in gaps.iter_mut().filter(|g| !g.exact) {
        if let Some(better) = parse_with(&g.raw, &known) {
            *g = better;
        }
    }
}

/// A line still split as upstream splits it, whose key holds a '/': of the
/// global bucket `x`, key `y/<key>`, or of the tenant's bucket `x/y`, key
/// `<key>`.  That tenant's bucket, and that key.
fn tenant_split(g: &GapLine) -> Option<(String, String)> {
    if g.exact || g.bucket.contains('/') {
        return None;
    }
    let (b, rest) = g.key.split_once('/')?;
    (!b.is_empty() && !rest.is_empty()).then(|| (format!("{}/{b}", g.bucket), rest.to_string()))
}

/// Settle what neither the oids nor resolve() did by the cluster's buckets:
/// a line `x/y/<key>` is of the tenant's bucket `x/y` if there is one, else
/// of the global bucket `x`, as upstream splits it.  How many moved.
pub fn settle_buckets(gaps: &mut [GapLine], buckets: &HashSet<String>) -> usize {
    let mut moved = 0;
    for g in gaps.iter_mut() {
        let Some((bucket, key)) = tenant_split(g) else { continue };
        if buckets.contains(&bucket) {
            (g.bucket, g.key) = (bucket, key);
            moved += 1;
        }
    }
    moved
}

/// settle_buckets with the names of the cluster's buckets, read once ( and
/// only if a line needs them ).  When they cannot be read the lines keep
/// upstream's split: the warning that says so.
pub async fn settle_tenants(admin: &Admin, gaps: &mut [GapLine]) -> Option<String> {
    let n = gaps.iter().filter(|g| tenant_split(g).is_some()).count();
    if n == 0 {
        return None;
    }
    match admin.bucket_list().await {
        Ok(names) => {
            settle_buckets(gaps, &names.into_iter().collect());
            None
        }
        Err(e) => {
            let w = format!(
                "the bucket names cannot be read ( {e:#} ): {n} `x/y/<key>` line(s) whose oids name no key are taken for the global bucket x's y/<key>, not a tenant's bucket x/y"
            );
            tracing::warn!("{w}");
            Some(w)
        }
    }
}

/// A v3.0 results record: `{"epoch", "bucket", "user_object", "rados_object"}`.
pub fn from_record(v: &Value) -> Option<GapLine> {
    let field = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let (bucket, object, oid) = (field("bucket")?, field("user_object")?, field("rados_object")?);
    let (key, instance) = names(object, oid).unwrap_or_else(|| {
        let (n, i) = split_key(object);
        (n, (!i.is_empty()).then_some(i))
    });
    Some(GapLine {
        bucket: bucket.to_string(),
        key: key.to_string(),
        instance: instance.map(str::to_string),
        oid: oid.to_string(),
        still: false,
        unversioned: false,
        s3: true,
        exact: true,
        raw: v.to_string(),
    })
}

/// What a file to import holds: rgw-integrity's findings, and upstream's gaps.
#[derive(Debug, Default)]
pub struct Import {
    pub findings: Vec<Finding>,
    pub gaps: Vec<GapLine>,
}

impl Import {
    /// A JSON value: a finding, a v3.0 record, or an array of them.
    fn take(&mut self, v: Value) -> Result<()> {
        match v {
            Value::Array(items) => items.into_iter().try_for_each(|i| self.take(i)),
            Value::Object(ref o) if o.contains_key("rados_object") => {
                self.gaps.push(from_record(&v).context("a results record without its bucket, user_object or rados_object")?);
                Ok(())
            }
            Value::Object(_) => {
                self.findings.push(serde_json::from_value(v)?);
                Ok(())
            }
            _ => bail!("neither a finding nor a results record"),
        }
    }
}

/// Read a file to import, line by line in any mix of: rgw-integrity's JSON
/// findings, upstream's MISSING lines, and v3.0's results records.  A file
/// that is one JSON document, as a results object read with `rados get` or
/// pretty-printed, is read whole.
pub fn read(body: &str) -> Result<Import> {
    let mut import = Import::default();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        import.take(v)?;
        return Ok(import);
    }
    for (i, line) in body.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with(['{', '[']) {
            let v = serde_json::from_str(t).map_err(anyhow::Error::from).and_then(|v| import.take(v));
            v.with_context(|| format!("line {}", i + 1))?;
        } else {
            let g = parse_line(line).ok_or_else(|| anyhow!("line {}: neither a JSON finding nor a `<bucket>/<key> MISSING <oid>` line", i + 1))?;
            import.gaps.push(g);
        }
    }
    resolve(&mut import.gaps);
    Ok(import)
}

/// The findings a scan would make of these gaps, so that its own replace
/// them: per bucket and key, the head's `listed_without_head`, or the
/// missing objects' `missing_data`, with no cause, as neither is verified
/// or classified here.
pub fn findings(gaps: &[GapLine]) -> Vec<Finding> {
    let mut objects: BTreeMap<(&str, String), Vec<&GapLine>> = BTreeMap::new();
    for g in gaps {
        objects.entry((g.bucket.as_str(), g.display_key())).or_default().push(g);
    }
    let mut out = Vec::with_capacity(objects.len());
    for ((bucket, key), lines) in objects {
        let oids: BTreeSet<&str> = lines.iter().map(|g| g.oid.as_str()).collect();
        let oids: Vec<String> = oids.into_iter().map(str::to_string).collect();
        // as classify_missing: a missing head is a listed key without one
        let f = match lines.iter().find(|g| g.is_head()) {
            Some(h) => Finding::new(Class::Inconsistency, "listed_without_head", bucket).oids(std::slice::from_ref(&h.oid)),
            None => Finding::new(Class::DataLoss, "missing_data", bucket).oids(&oids),
        };
        let mut evidence = json!({
            "source": "rgw-gap-list",
            "verified": false,
            "classified": false,
            "missing": oids.len(),
            "still_missing": lines.iter().all(|g| g.still),
            "lines": lines.iter().take(100).map(|g| g.raw.as_str()).collect::<Vec<_>>(),
        });
        if lines.len() > 100 {
            evidence["line_count"] = json!(lines.len());
        }
        if lines.iter().any(|g| g.unversioned) {
            evidence["not_versioned"] = json!(true);
        }
        out.push(
            f.key(key)
                .evidence(evidence)
                .hint("imported from rgw-gap-list's results, not verified or classified: a scan of the bucket checks it and ranks its causes"),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "1b14fa0e-7ecf-44dd-8b56-ba8e1473a227.4200.8";
    const UP: &str = "2~9wJL7tK7u4D4KqIaxd8eXjZUQdK38RW";
    const V: &str = "Y8tL7MyndszuwTxg4Itgx6eICC1bm9p";

    fn parsed(line: &str) -> (String, String, Option<String>, String, bool, bool) {
        let g = parse_line(line).unwrap_or_else(|| panic!("{line}"));
        assert_eq!(g.raw, line);
        (g.bucket, g.key, g.instance, g.oid, g.still, g.exact)
    }

    fn gap(bucket: &str, key: &str, instance: Option<&str>, oid: &str, still: bool, exact: bool) -> (String, String, Option<String>, String, bool, bool) {
        (bucket.into(), key.into(), instance.map(Into::into), oid.into(), still, exact)
    }

    #[test]
    fn upstream_forms() {
        let head = format!("{M}_photo.jpg");
        for (line, still) in [
            (format!("s3://b/photo.jpg MISSING {head}"), false),
            (format!("s3://b/photo.jpg STILL MISSING {head}"), true),
            (format!("Not Versioned Instance: s3://b/photo.jpg MISSING {head}"), false),
            (format!("b/photo.jpg MISSING {head}"), false),
        ] {
            assert_eq!(parsed(&line), gap("b", "photo.jpg", None, &head, still, true), "{line}");
        }
        let g = parse_line(&format!("Not Versioned Instance: b/photo.jpg STILL MISSING {head}")).unwrap();
        assert!(g.unversioned && g.still && !g.s3);
        assert_eq!(g.to_string(), g.raw);
        assert!(parse_line("s3://b/k FOUND x").is_none());
        assert!(parse_line("nothing").is_none());
        assert!(parse_line(&format!("s3://b MISSING {head}")).is_none(), "no key");
    }

    #[test]
    fn keys_the_oid_names() {
        let cases = [
            // a key holding ' MISSING ', ' STILL' and '/'
            (format!("s3://b/a MISSING b MISSING {M}_a MISSING b"), gap("b", "a MISSING b", None, &format!("{M}_a MISSING b"), false, true)),
            (format!("s3://b/x STILL MISSING {M}_x STILL"), gap("b", "x STILL", None, &format!("{M}_x STILL"), false, true)),
            (format!("s3://b/x STILL STILL MISSING {M}_x STILL"), gap("b", "x STILL", None, &format!("{M}_x STILL"), true, true)),
            // -x's re.sub, undone: every ' MISSING ' became ' STILL MISSING '
            (
                format!("s3://b/a STILL MISSING b STILL MISSING {M}_a STILL MISSING b"),
                gap("b", "a MISSING b", None, &format!("{M}_a MISSING b"), true, true),
            ),
            (
                format!("s3://b/a STILL STILL MISSING b STILL MISSING {M}_a STILL STILL MISSING b"),
                gap("b", "a STILL MISSING b", None, &format!("{M}_a STILL MISSING b"), true, true),
            ),
            (
                format!("s3://b/a STILL MISSING b MISSING {M}_a STILL MISSING b"),
                gap("b", "a STILL MISSING b", None, &format!("{M}_a STILL MISSING b"), false, true),
            ),
            (format!("s3://b/d/e/f MISSING {M}_d/e/f"), gap("b", "d/e/f", None, &format!("{M}_d/e/f"), false, true)),
            // a tenant's bucket
            (format!("s3://t/b/d/f MISSING {M}_d/f"), gap("t/b", "d/f", None, &format!("{M}_d/f"), false, true)),
            // a version, and a key with brackets that is none
            (format!("s3://b/k[{V}] MISSING {M}__:{V}_k"), gap("b", "k", Some(V), &format!("{M}__:{V}_k"), false, true)),
            (format!("s3://b/k[x] y[z] MISSING {M}_k[x] y[z]"), gap("b", "k[x] y[z]", None, &format!("{M}_k[x] y[z]"), false, true)),
            (format!("s3://b/k[{V}] MISSING {M}_k[{V}]"), gap("b", &format!("k[{V}]"), None, &format!("{M}_k[{V}]"), false, true)),
            (format!("s3://b/k[null] MISSING {M}_k"), gap("b", "k", Some("null"), &format!("{M}_k"), false, true)),
            // a version's parts and tails, with and without its instance
            (format!("s3://b/k[{V}] MISSING {M}__multipart_k.{UP}.2"), gap("b", "k", Some(V), &format!("{M}__multipart_k.{UP}.2"), false, true)),
            (format!("s3://b/k[{V}] MISSING {M}__shadow:{V}_k.{UP}.2_1"), gap("b", "k", Some(V), &format!("{M}__shadow:{V}_k.{UP}.2_1"), false, true)),
            (format!("s3://b/_u MISSING {M}___u"), gap("b", "_u", None, &format!("{M}___u"), false, true)),
            (format!("s3://b/ap MISSING {M}__shadow_ap.QmeTJR66RPFocC7r5_1"), gap("b", "ap", None, &format!("{M}__shadow_ap.QmeTJR66RPFocC7r5_1"), false, true)),
        ];
        for (line, want) in cases {
            assert_eq!(parsed(&line), want, "{line}");
            let g = parse_line(&line).unwrap();
            assert_eq!(g.to_string(), line, "renders back");
        }
    }

    #[test]
    fn keys_no_oid_names() {
        let tail = format!("{M}__shadow_.QmeTJR66RPFocC7r5-Uu_Tn4Kpp4X_1");
        // as upstream: the last ' MISSING ', the first '/'
        assert_eq!(parsed(&format!("s3://b/a MISSING b MISSING {tail}")), gap("b", "a MISSING b", None, &tail, false, false));
        assert_eq!(parsed(&format!("s3://t/b/k MISSING {tail}")), gap("t", "b/k", None, &tail, false, false));
        assert_eq!(parsed(&format!("s3://b/k[{V}] MISSING {tail}")), gap("b", "k", Some(V), &tail, false, false));
        assert_eq!(parsed(&format!("s3://b/a STILL MISSING b STILL MISSING {tail}")), gap("b", "a MISSING b", None, &tail, true, false));
        // a part or tail can be a copy's source's, named by its key: it splits no tenant off
        let part = format!("{M}__multipart_photo.jpg.{UP}.1");
        let copied = format!("s3://b/archive/photo.jpg MISSING {part}");
        assert_eq!(parsed(&copied), gap("b", "archive/photo.jpg", None, &part, false, false));
        let shadow = format!("{M}__shadow_y/z.{UP}.1_3");
        assert_eq!(parsed(&format!("s3://b/x/y/z MISSING {shadow}")), gap("b", "x/y/z", None, &shadow, false, false));
        assert_eq!(parsed(&format!("s3://t/b/k MISSING {M}__multipart_k.{UP}.1")).0, "t");
        let mut gaps: Vec<GapLine> = [copied.clone(), format!("s3://b/archive/photo.jpg MISSING {tail}")].iter().map(|l| parse_line(l).unwrap()).collect();
        resolve(&mut gaps);
        assert!(gaps.iter().all(|g| (g.bucket.as_str(), g.key.as_str(), g.exact) == ("b", "archive/photo.jpg", false)));
        // a head of the same object settles the split
        let lines = [format!("s3://t/b/k MISSING {tail}"), format!("s3://t/b/k MISSING {M}__multipart_k.{UP}.1"), format!("s3://t/b/k MISSING {M}_k")];
        let mut gaps: Vec<GapLine> = lines.iter().map(|l| parse_line(l).unwrap()).collect();
        resolve(&mut gaps);
        assert!(gaps.iter().all(|g| (g.bucket.as_str(), g.key.as_str(), g.exact) == ("t/b", "k", true)), "{gaps:?}");
        let mut gaps: Vec<GapLine> = [copied, format!("s3://b/archive/photo.jpg MISSING {M}_archive/photo.jpg")].iter().map(|l| parse_line(l).unwrap()).collect();
        resolve(&mut gaps);
        assert!(gaps.iter().all(|g| (g.bucket.as_str(), g.key.as_str(), g.exact) == ("b", "archive/photo.jpg", true)));
        // a stripped -x line whose key ended in a blank
        let g = parse_line(&format!("s3://b/k  MISSING {M}_k ")).unwrap();
        assert_eq!((g.key.as_str(), g.exact), ("k ", true));
        let g = parse_line(&format!("s3://b/k  STILL MISSING {M}_k")).unwrap();
        assert_eq!((g.key.as_str(), g.oid.as_str(), g.still, g.exact), ("k ", format!("{M}_k").as_str(), true, false));
    }

    #[test]
    fn upstream_keys_ending_in_blanks() {
        // rgw-gap-list.py strips the radoslist line: the key's trailing blank goes, the oid's stays
        assert_eq!(parsed(&format!("s3://b/k MISSING {M}_k ")), gap("b", "k ", None, &format!("{M}_k "), false, true));
        assert_eq!(parsed(&format!("s3://b/k MISSING {M}_k \t ")), gap("b", "k \t ", None, &format!("{M}_k \t "), false, true));
        assert_eq!(parsed(&format!("s3://t/b/k MISSING {M}_k ")), gap("t/b", "k ", None, &format!("{M}_k "), false, true));
        // -x strips its lines again: the blanks are lost, and the oid read as written
        assert_eq!(parsed(&format!("s3://b/k STILL MISSING {M}_k")), gap("b", "k", None, &format!("{M}_k"), true, true));
        // a version's key ends in its instance, which the strip leaves be
        let v = format!("s3://b/k [{V}] MISSING {M}__:{V}_k ");
        assert_eq!(parsed(&v), gap("b", "k ", Some(V), &format!("{M}__:{V}_k "), false, true));
    }

    /// A line resolve() settles is one of the same bucket's object: a global
    /// bucket t's key b/k and a tenant bucket t/b's key k read the same.
    #[test]
    fn resolve_keeps_to_a_marker() {
        let m2 = "1b14fa0e-7ecf-44dd-8b56-ba8e1473a227.4200.9";
        let (head, tail) = (format!("s3://t/b/k MISSING {M}_k"), format!("s3://t/b/k MISSING {m2}__shadow_.x_1"));
        let gaps = read(&format!("{head}\n{tail}\n")).unwrap().gaps;
        assert_eq!((gaps[0].bucket.as_str(), gaps[0].key.as_str(), gaps[0].exact), ("t/b", "k", true));
        assert_eq!((gaps[1].bucket.as_str(), gaps[1].key.as_str(), gaps[1].exact), ("t", "b/k", false));
        let fs: Vec<(String, String, Option<String>)> = findings(&gaps).into_iter().map(|f| (f.check, f.bucket, f.key)).collect();
        assert_eq!(
            fs,
            [("missing_data".to_string(), "t".to_string(), Some("b/k".to_string())), ("listed_without_head".into(), "t/b".into(), Some("k".into()))]
        );
        // the same marker's tail is the head's object
        let gaps = read(&format!("{head}\ns3://t/b/k MISSING {M}__shadow_.x_1\n")).unwrap().gaps;
        assert!(gaps.iter().all(|g| (g.bucket.as_str(), g.key.as_str(), g.exact) == ("t/b", "k", true)), "{gaps:?}");
    }

    /// What the oid cannot settle, the cluster's bucket names do: a tenant's
    /// bucket t/b if there is one, else the global bucket t.
    #[test]
    fn bucket_names_settle_tenants() {
        let tail = format!("{M}__shadow_.x_1");
        let part = format!("{M}__multipart_k.{UP}.1");
        let body = format!("s3://t/b/k MISSING {tail}
s3://t/b/k MISSING {part}
s3://t/b/c/d MISSING {tail}
s3://g/k MISSING {tail}
");
        let split = |gaps: &[GapLine]| gaps.iter().map(|g| (g.bucket.clone(), g.key.clone())).collect::<Vec<_>>();
        let pair = |b: &str, k: &str| (b.to_string(), k.to_string());
        let mut gaps = read(&body).unwrap().gaps;
        assert_eq!(settle_buckets(&mut gaps, &["t/b".to_string(), "t".to_string(), "g".to_string()].into()), 3);
        assert_eq!(split(&gaps), [pair("t/b", "k"), pair("t/b", "k"), pair("t/b", "c/d"), pair("g", "k")]);
        let fs: Vec<(String, Option<String>)> = findings(&gaps).into_iter().map(|f| (f.bucket, f.key)).collect();
        assert_eq!(fs, [("g".to_string(), Some("k".to_string())), ("t/b".into(), Some("c/d".into())), ("t/b".into(), Some("k".into()))]);
        // no tenant's bucket t/b: the global t's b/k, as upstream splits it
        let mut gaps = read(&body).unwrap().gaps;
        assert_eq!(settle_buckets(&mut gaps, &["t".to_string(), "g".to_string()].into()), 0);
        assert_eq!(split(&gaps), [pair("t", "b/k"), pair("t", "b/k"), pair("t", "b/c/d"), pair("g", "k")]);
        // an exact line is left be: a global t's b/k whose part names it
        let mut gaps = read(&format!("s3://t/b/k MISSING {M}__multipart_b/k.{UP}.1
")).unwrap().gaps;
        settle_buckets(&mut gaps, &["t/b".to_string()].into());
        assert_eq!(split(&gaps), [pair("t", "b/k")]);
        // a version keeps its instance
        let mut gaps = read(&format!("s3://t/b/k[{V}] MISSING {tail}
")).unwrap().gaps;
        settle_buckets(&mut gaps, &["t/b".to_string()].into());
        assert_eq!((gaps[0].bucket.as_str(), gaps[0].display_key()), ("t/b", format!("k[{V}]")));
    }

    #[tokio::test]
    async fn bucket_names_read_once_or_warned_of() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rgwi-gaplist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("radosgw-admin");
        let calls = dir.join("calls");
        let script = format!("#!/bin/sh
echo \"$1 $2\" >> '{}'
[ \"$1 $2\" = \"bucket list\" ] && echo '[\"t/b\", \"t\"]'
", calls.display());
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let admin = Admin::new(program.display().to_string(), None, None, crate::admin::DEFAULT_CONCURRENCY);
        let tail = format!("{M}__shadow_.x_1");
        let mut gaps = read(&format!("s3://t/b/k MISSING {tail}
s3://t/b/j MISSING {tail}
")).unwrap().gaps;
        assert_eq!(settle_tenants(&admin, &mut gaps).await, None);
        assert!(gaps.iter().all(|g| g.bucket == "t/b"), "{gaps:?}");
        assert_eq!(std::fs::read_to_string(&calls).unwrap(), "bucket list\n", "once");
        // nothing to settle: no call
        let mut gaps = read(&format!("s3://b/k MISSING {tail}
")).unwrap().gaps;
        assert_eq!(settle_tenants(&admin, &mut gaps).await, None);
        assert_eq!(std::fs::read_to_string(&calls).unwrap(), "bucket list\n");
        // names that cannot be read: upstream's split, and a warning
        let failing = Admin::new("false".into(), None, None, crate::admin::DEFAULT_CONCURRENCY);
        let mut gaps = read(&format!("s3://t/b/k MISSING {tail}
")).unwrap().gaps;
        let w = settle_tenants(&failing, &mut gaps).await.unwrap();
        assert!(w.contains("1 `x/y/<key>` line(s)"), "{w}");
        assert_eq!((gaps[0].bucket.as_str(), gaps[0].key.as_str()), ("t", "b/k"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn v3_records() {
        let rec = |k: &str, o: &str| json!({ "epoch": 1790000000.123, "bucket": "b", "user_object": k, "rados_object": o });
        let a = rec(&format!("k[{V}]"), &format!("{M}__:{V}_k"));
        let b = rec("k MISSING j", &format!("{M}__shadow_.abc_1"));
        let arr = Value::Array(vec![a.clone(), b.clone()]);
        let pretty = serde_json::to_string_pretty(&arr).unwrap();
        let lines = format!("{a}\n{b}\n");
        for body in [arr.to_string(), pretty, lines] {
            let i = read(&body).unwrap();
            assert!(i.findings.is_empty());
            assert_eq!(i.gaps.len(), 2, "{body}");
            assert_eq!((i.gaps[0].key.as_str(), i.gaps[0].instance.as_deref()), ("k", Some(V)));
            assert_eq!(i.gaps[1].key, "k MISSING j");
            assert_eq!(i.gaps[0].to_string(), format!("s3://b/k[{V}] MISSING {M}__:{V}_k"));
        }
        assert!(read("[{\"epoch\": 1, \"bucket\": \"b\", \"rados_object\": \"o\"}]").is_err());
        assert_eq!(read("[]").unwrap().gaps.len(), 0);
    }

    #[test]
    fn mixed_files() {
        let f = Finding::new(Class::AtRisk, "completed_upload_open", "b").key("k").upload("u");
        let body = format!(
            "{}\n\ns3://b/k MISSING {M}__shadow_.x_1\r\nb/k MISSING {M}__shadow_.x_2\n{}\n",
            serde_json::to_string(&f).unwrap(),
            json!({ "epoch": 1, "bucket": "c", "user_object": "o", "rados_object": format!("{M}_o") })
        );
        let i = read(&body).unwrap();
        assert_eq!(i.findings, vec![f]);
        assert_eq!(i.gaps.iter().map(|g| g.bucket.as_str()).collect::<Vec<_>>(), ["b", "b", "c"]);
        assert_eq!(i.gaps[0].oid, format!("{M}__shadow_.x_1"));
        // the bad line is named
        let err = read(&format!("s3://b/k MISSING {M}_k\nnot a line\n")).unwrap_err();
        assert!(format!("{err:#}").starts_with("line 2:"), "{err:#}");
        let err = read(&format!("s3://b/k MISSING {M}_k\n{{\"class\": \"nope\"}}\n")).unwrap_err();
        assert!(format!("{err:#}").starts_with("line 2:"), "{err:#}");
    }

    #[test]
    fn findings_a_scan_makes() {
        let text = format!(
            "s3://b/big MISSING {M}__shadow_.x_2\ns3://b/big STILL MISSING {M}__shadow_.x_1\ns3://b/big MISSING {M}__shadow_.x_1\n\
             Not Versioned Instance: s3://b/gone[{V}] MISSING {M}__:{V}_gone\n"
        );
        let fs = findings(&read(&text).unwrap().gaps);
        assert_eq!(fs.len(), 2);
        let tails = [format!("{M}__shadow_.x_1"), format!("{M}__shadow_.x_2")];
        // the same fingerprint as the scan's findings, whose causes and class replace these
        let scan = Finding::new(Class::DataLoss, "missing_data", "b").key("big").oids(&[tails[1].clone(), tails[0].clone()]);
        assert_eq!(fs[0].fingerprint(), scan.fingerprint());
        assert_eq!((fs[0].class, fs[0].oids.as_slice(), fs[0].causes.is_empty()), (Class::DataLoss, tails.as_slice(), true));
        assert_eq!(fs[0].evidence["lines"].as_array().unwrap().len(), 3);
        assert_eq!((&fs[0].evidence["verified"], &fs[0].evidence["still_missing"]), (&json!(false), &json!(false)));
        assert!(fs[0].hint.is_some());
        let scan = Finding::new(Class::Inconsistency, "listed_without_head", "b").key(format!("gone[{V}]")).oids(&[format!("{M}__:{V}_gone")]);
        assert_eq!(fs[1].fingerprint(), scan.fingerprint());
        assert_eq!((fs[1].check.as_str(), &fs[1].evidence["not_versioned"]), ("listed_without_head", &json!(true)));
    }
}
