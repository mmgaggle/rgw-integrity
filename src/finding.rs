//! Findings, their candidate causes, and the catalog of known issues.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oid::iso;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    DataLoss,
    PendingLoss,
    AtRisk,
    Inconsistency,
    Leak,
    LatentLeak,
}

impl Class {
    pub const ALL: [Class; 6] =
        [Class::DataLoss, Class::PendingLoss, Class::AtRisk, Class::Inconsistency, Class::Leak, Class::LatentLeak];

    pub fn as_str(self) -> &'static str {
        match self {
            Class::DataLoss => "data_loss",
            Class::PendingLoss => "pending_loss",
            Class::AtRisk => "at_risk",
            Class::Inconsistency => "inconsistency",
            Class::Leak => "leak",
            Class::LatentLeak => "latent_leak",
        }
    }

    pub fn parse(s: &str) -> Option<Class> {
        Class::ALL.into_iter().find(|c| c.as_str() == s)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Class::DataLoss => "a listed object's manifest names RADOS objects that are gone",
            Class::PendingLoss => "data a listed object needs is queued in GC with no other reference",
            Class::AtRisk => "a completed multipart upload is still open; aborting or retrying it frees the object's data",
            Class::Inconsistency => "the bucket index and the objects disagree",
            Class::Leak => "RADOS objects nothing references",
            Class::LatentLeak => "a tail object keeps a reference no head holds",
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cause {
    pub cause: String,
    pub confidence: Confidence,
    pub what: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fixed_here: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// One finding, as one line of the findings file; the same schema as
/// rgw-gap-list.py's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub class: Class,
    pub check: String,
    pub bucket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(default)]
    pub causes: Vec<Cause>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub after_fix: bool,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub evidence: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl Finding {
    pub fn new(class: Class, check: &str, bucket: &str) -> Finding {
        Finding {
            class,
            check: check.to_string(),
            bucket: bucket.to_string(),
            key: None,
            upload_id: None,
            oids: Vec::new(),
            oid_count: None,
            time: None,
            causes: Vec::new(),
            after_fix: false,
            evidence: serde_json::Value::Null,
            hint: None,
        }
    }

    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    pub fn upload(mut self, upload: impl Into<String>) -> Self {
        self.upload_id = Some(upload.into());
        self
    }

    pub fn oids(mut self, oids: &[String]) -> Self {
        self.oids = oids.iter().take(100).cloned().collect();
        if oids.len() > 100 {
            self.oid_count = Some(oids.len());
        }
        self
    }

    pub fn evidence(mut self, evidence: serde_json::Value) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn top_cause(&self) -> Option<&Cause> {
        self.causes.first()
    }

    /// Identifies the same artifact across scans.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        for part in [self.check.as_str(), &self.bucket, self.key.as_deref().unwrap_or(""), self.upload_id.as_deref().unwrap_or("")] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        let mut oids: Vec<&String> = self.oids.iter().collect();
        oids.sort();
        for o in oids {
            h.update(o.as_bytes());
            h.update([0]);
        }
        hex::encode(&h.finalize()[..16])
    }
}

/// A candidate cause before ranking.
pub struct Candidate {
    pub name: &'static str,
    pub confidence: Confidence,
    pub why: Option<String>,
}

pub fn cause(name: &'static str, confidence: Confidence, why: impl Into<Option<String>>) -> Candidate {
    Candidate { name, confidence, why: why.into() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: String,
    #[serde(default)]
    pub tracker: Option<u32>,
    #[serde(default)]
    pub fix: Option<u32>,
    #[serde(default)]
    pub min: Option<u32>,
    #[serde(default)]
    pub max: Option<u32>,
    pub what: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(rename = "issue")]
    pub issues: Vec<Issue>,
}

impl Catalog {
    pub fn builtin() -> Catalog {
        toml::from_str(include_str!("../catalog.toml")).expect("the built-in catalog parses")
    }

    /// The built-in catalog, with a file's issues added or replacing theirs.
    pub fn load(extra: Option<&Path>) -> Result<Catalog> {
        let mut cat = Catalog::builtin();
        if let Some(path) = extra {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let more: Catalog = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
            for issue in more.issues {
                cat.issues.retain(|i| i.id != issue.id);
                cat.issues.push(issue);
            }
        }
        Ok(cat)
    }

    pub fn get(&self, id: &str) -> Option<&Issue> {
        self.issues.iter().find(|i| i.id == id)
    }
}

/// What ranking needs: the catalog, the cluster's releases, and the fixes
/// its build carries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub catalog: Catalog,
    /// the major versions of the cluster's RGWs and OSDs; empty: any
    pub majors: BTreeSet<u32>,
    pub fixed: BTreeSet<u32>,
    pub fixed_since: Option<i64>,
}

impl Context {
    pub fn applies(&self, issue: &Issue) -> bool {
        let (lo, hi) = (issue.min.unwrap_or(0), issue.max.unwrap_or(u32::MAX));
        self.majors.is_empty() || self.majors.iter().any(|m| (lo..=hi).contains(m))
    }

    /// Rank the candidates, drop those the release cannot have, and stamp
    /// the finding's time.
    pub fn rank(&self, mut f: Finding, candidates: Vec<Candidate>, when: Option<i64>) -> Finding {
        let mut candidates = candidates;
        candidates.sort_by_key(|c| c.confidence);
        let mut seen = BTreeSet::new();
        for c in candidates {
            let Some(issue) = self.catalog.get(c.name) else { continue };
            if !seen.insert(c.name) || !self.applies(issue) {
                continue;
            }
            let fixed_here = issue.fix.is_some_and(|f| self.fixed.contains(&f));
            f.causes.push(Cause {
                cause: c.name.to_string(),
                confidence: c.confidence,
                what: issue.what.clone(),
                tracker: issue.tracker.map(|t| format!("https://tracker.ceph.com/issues/{t}")),
                fix: issue.fix.map(|p| format!("https://github.com/ceph/ceph/pull/{p}")),
                fixed_here,
                evidence: c.why,
            });
        }
        if let Some(when) = when {
            f.time = Some(iso(when));
            if let Some(since) = self.fixed_since {
                f.after_fix = when > since && !f.causes.is_empty() && f.causes.iter().all(|c| c.fixed_here);
            }
        }
        f
    }
}

/// Counts of findings and of skipped candidates, for summaries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tally {
    pub classes: BTreeMap<String, u64>,
    pub causes: BTreeMap<String, u64>,
    pub skipped: BTreeMap<String, u64>,
}

impl Tally {
    pub fn add(&mut self, f: &Finding) {
        *self.classes.entry(f.class.to_string()).or_default() += 1;
        if let Some(c) = f.top_cause() {
            *self.causes.entry(c.cause.clone()).or_default() += 1;
        }
    }

    pub fn skip(&mut self, reason: &str) {
        *self.skipped.entry(reason.to_string()).or_default() += 1;
    }

    pub fn merge(&mut self, other: &Tally) {
        for (dst, src) in [(&mut self.classes, &other.classes), (&mut self.causes, &other.causes), (&mut self.skipped, &other.skipped)] {
            for (k, v) in src {
                *dst.entry(k.clone()).or_default() += v;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::parse_time;

    #[test]
    fn release_filter() {
        let mut ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let cands = || {
            vec![
                cause("abort-race", Confidence::High, None),
                cause("ix-fail", Confidence::High, None),
                cause("delete-race", Confidence::Medium, None),
                cause("mp-meta-left", Confidence::Low, None),
            ]
        };
        for (majors, names) in [
            (vec![19], vec!["abort-race", "mp-meta-left"]),
            (vec![20], vec!["delete-race", "mp-meta-left"]),
            (vec![21], vec!["ix-fail", "delete-race", "mp-meta-left"]),
            (vec![], vec!["abort-race", "ix-fail", "delete-race", "mp-meta-left"]),
        ] {
            ctx.majors = majors.into_iter().collect();
            let f = ctx.rank(Finding::new(Class::DataLoss, "missing_data", "b"), cands(), None);
            assert_eq!(f.causes.iter().map(|c| c.cause.as_str()).collect::<Vec<_>>(), names);
        }
    }

    #[test]
    fn after_fix() {
        let ctx = Context {
            catalog: Catalog::builtin(),
            fixed: [72103].into(),
            fixed_since: parse_time("2026-09-01 00:00:00"),
            ..Default::default()
        };
        let f = ctx.rank(
            Finding::new(Class::AtRisk, "completed_upload_open", "b"),
            vec![cause("mp-meta-left", Confidence::High, None)],
            parse_time("2026-09-20 00:00:00"),
        );
        assert!(f.causes[0].fixed_here && f.after_fix);
        let line = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&line).unwrap();
        assert_eq!(back, f);
        assert_eq!(back.fingerprint(), f.fingerprint());
    }

    #[test]
    fn catalog_override() {
        let dir = std::env::temp_dir().join(format!("cat-{}", std::process::id()));
        std::fs::write(&dir, "[[issue]]\nid = \"dedup\"\nfix = 1\nwhat = \"x\"\n[[issue]]\nid = \"new\"\nwhat = \"y\"\n").unwrap();
        let cat = Catalog::load(Some(&dir)).unwrap();
        assert_eq!(cat.get("dedup").unwrap().fix, Some(1));
        assert!(cat.get("new").is_some() && cat.get("mp-meta-left").is_some());
        std::fs::remove_file(dir).unwrap();
    }
}
