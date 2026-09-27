//! What clients and the server say to each other, as JSON over HTTPS.

use serde::{Deserialize, Serialize};

use crate::admin::BucketStats;
use crate::finding::Context;
use crate::scan::{BucketReport, Options};

/// A client's periodic status; the server answers with a Control.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    pub client: String,
    pub host: String,
    pub version: String,
    /// the units it is scanning, and how far along each is
    pub units: Vec<UnitProgress>,
    pub inflight_size: usize,
    pub inflight_in_use: usize,
    /// RADOS objects checked since it started
    pub checked: u64,
    pub errors: u64,
    pub draining: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnitProgress {
    pub unit: i64,
    pub bucket: String,
    pub rados_objects: u64,
    /// the RADOS objects found missing so far ( none from older clients )
    #[serde(default)]
    pub gaps: u64,
}

/// What a client should do now.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Control {
    /// RADOS operations it may have in flight
    pub inflight: usize,
    /// units it may scan at once
    pub parallel: usize,
    pub paused: bool,
    /// the running scan, and its GC snapshot's version
    pub scan: Option<i64>,
    pub gc_version: i64,
    /// how long a lease lasts without a heartbeat
    pub lease_secs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub client: String,
    pub max: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unit {
    pub id: i64,
    pub scan: i64,
    /// the bucket, or a label for a pool slice or a join
    pub bucket: String,
    pub stats: Option<BucketStats>,
    /// bucket, list ( a pool slice ) or join ( a partition )
    #[serde(default = "bucket_kind")]
    pub kind: String,
    /// a list unit's detect::Slice, a join unit's detect::Join
    #[serde(default)]
    pub spec: Option<serde_json::Value>,
}

fn bucket_kind() -> String {
    "bucket".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Leased {
    pub units: Vec<Unit>,
}

/// A scan's checks and what its findings are judged against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSpec {
    pub id: i64,
    pub options: Options,
    pub context: Context,
    pub gc_min_wait: i64,
    /// orphan detection's partitions and work pool, when the scan finds orphans
    #[serde(default)]
    pub plan: Option<crate::detect::Plan>,
}

/// A unit's report, to /api/v1/report.  One too big for a post goes in
/// parts first, to /api/v1/report/part: Reports that carry only findings,
/// references and orphan candidates, while the client holds the unit.
#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub client: String,
    pub unit: i64,
    pub report: BucketReport,
    /// the findings its parts carried, which the unit's count includes
    #[serde(default, skip_serializing_if = "is_zero")]
    pub earlier_findings: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// About the most a report's post carries; well under the server's limit
/// on a request, and quick enough to send within a request's timeout.
pub const REPORT_PART_BYTES: usize = 64 << 20;

/// A writer that only counts what it is given.
struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The JSON length of a value, and the comma ( or a key's colon ) after it:
/// counted, not written out.
fn json_len<T: Serialize + ?Sized>(v: &T) -> usize {
    let mut n = Count(0);
    serde_json::to_writer(&mut n, v).map_or(0, |_| n.0) + 1
}

/// The parts a report is split into, as they fill.
struct Parts {
    room: usize,
    bucket: String,
    done: Vec<BucketReport>,
    part: BucketReport,
    bytes: usize,
}

impl Parts {
    /// The part with room for `n` more bytes; a new one when this one is
    /// full, unless it is empty ( an item bigger than a part goes alone ).
    fn room_for(&mut self, n: usize) -> &mut BucketReport {
        if self.bytes > 0 && self.bytes + n > self.room {
            let full = std::mem::replace(&mut self.part, BucketReport { bucket: self.bucket.clone(), ..Default::default() });
            self.done.push(full);
            self.bytes = 0;
        }
        self.bytes += n;
        &mut self.part
    }
}

/// Split a unit's report into posts of at most `limit` bytes: the parts,
/// then the report with the rest.  A report that fits is the report alone,
/// as older servers take it, errors and all.  One that does not is split: a
/// head's references and the tags that carry them stay in one part, as the
/// server merges them together; errors beyond a quarter of `limit` are
/// counted, not sent.  The MISSING lines go in parts too; the report keeps
/// their count, `gaps`.  Each item is counted with a separator, and each
/// post with every key it may carry, so a post is no bigger than `limit`,
/// if a few bytes smaller than it could be; but an item bigger than a part
/// goes in a post of its own, however big.
pub fn split_report(client: &str, unit: i64, report: BucketReport, limit: usize) -> (Vec<Report>, Report) {
    let whole = Report { client: client.into(), unit, report, earlier_findings: 0 };
    if json_len(&whole) - 1 <= limit {
        return (Vec::new(), whole);
    }
    let mut report = whole.report;
    let findings = std::mem::take(&mut report.findings);
    let missing = std::mem::take(&mut report.missing);
    let needed = std::mem::take(&mut report.refs.needed);
    let mut carried = std::mem::take(&mut report.refs.carried);
    let candidates = std::mem::take(&mut report.candidates);
    let mut left = limit / 4;
    if let Some(keep) = report.errors.iter().position(|e| match left.checked_sub(json_len(e)) {
        Some(l) => {
            left = l;
            false
        }
        None => true,
    }) {
        let more = report.errors.len() - keep;
        report.errors.truncate(keep);
        report.errors.push(format!("{more} more errors, not reported"));
    }
    let bucket = report.bucket.clone();
    let empty = || BucketReport { bucket: bucket.clone(), ..Default::default() };
    // a post's fields but its items: the widest count of earlier findings,
    // and the candidates' key, which an empty report leaves out
    let widest = BucketReport { candidates: vec![String::new()], ..empty() };
    let envelope = json_len(&Report { client: client.into(), unit, report: widest, earlier_findings: usize::MAX });
    // the report's own fields, beyond an empty one's
    let rest = json_len(&report).saturating_sub(json_len(&empty()));
    let mut parts = Parts {
        room: limit.saturating_sub(envelope),
        part: empty(),
        bucket: bucket.clone(),
        done: Vec::new(),
        bytes: 0,
    };
    for f in findings {
        parts.room_for(json_len(&f)).findings.push(f);
    }
    for (oid, needs) in needed {
        let carriers = carried.remove(&oid);
        let n = json_len(&oid) + json_len(&needs) + carriers.as_ref().map_or(0, |c| json_len(&oid) + json_len(c));
        let part = parts.room_for(n);
        if let Some(c) = carriers {
            part.refs.carried.insert(oid.clone(), c);
        }
        part.refs.needed.insert(oid, needs);
    }
    for (oid, c) in carried {
        parts.room_for(json_len(&oid) + json_len(&c)).refs.carried.insert(oid, c);
    }
    for oid in candidates {
        parts.room_for(json_len(&oid)).candidates.push(oid);
    }
    for line in missing {
        parts.room_for(json_len(&line)).missing.push(line);
    }
    // the last part goes with the report, if the two fit together
    let Parts { mut done, part: last, bytes, room, .. } = parts;
    if bytes == 0 || bytes + rest <= room {
        report.findings = last.findings;
        report.refs = last.refs;
        report.candidates = last.candidates;
        report.missing = last.missing;
    } else {
        done.push(last);
    }
    let earlier_findings = done.iter().map(|p| p.findings.len()).sum();
    let wrap = |report: BucketReport| Report { client: client.into(), unit, report, earlier_findings: 0 };
    (done.into_iter().map(wrap).collect(), Report { client: client.into(), unit, report, earlier_findings })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub client: String,
    pub unit: i64,
    pub error: String,
}

/// Starting a scan, from the dashboard or the API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartScan {
    pub options: Options,
    /// only these buckets; every bucket if empty
    #[serde(default)]
    pub buckets: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Class, Finding};

    fn big() -> BucketReport {
        let mut r = BucketReport { bucket: "b".into(), rados_objects: 5000, gaps: 1000, seconds: 1.5, ..Default::default() };
        for i in 0..1000 {
            r.findings.push(Finding::new(Class::DataLoss, "missing_data", "b").key(format!("key{i}")).oids(&[format!("m_key{i}")]));
        }
        for i in 0..50 {
            let tail = format!("{}{i}", "m__shadow_.".repeat(40));
            r.refs.needed.insert(tail.clone(), ("b".into(), [format!("tag{i}")].into()));
            r.refs.carried.insert(tail, [format!("tag{i}")].into());
        }
        for i in 0..10 {
            r.refs.carried.insert(format!("elsewhere{i}"), ["t".to_string()].into());
        }
        r.candidates = (0..200).map(|i| format!("orphan{i}")).collect();
        r.missing = (0..1000).map(|i| format!("s3://b/key{i} MISSING m_key{i}")).collect();
        r.errors = (0..500).map(|i| format!("stat of m_key{i}: timed out")).collect();
        r.tally.classes.insert("data_loss".into(), 1000);
        r
    }

    #[test]
    fn a_report_that_fits_goes_alone() {
        let r = big();
        let want = serde_json::to_value(&r).unwrap();
        let (parts, last) = split_report("c", 7, r, 1 << 20);
        assert!(parts.is_empty());
        assert_eq!(last.earlier_findings, 0);
        assert_eq!(serde_json::to_value(&last.report).unwrap(), want);
        // as older servers take it
        assert!(serde_json::to_value(&last).unwrap().get("earlier_findings").is_none());
    }

    #[test]
    fn a_big_report_goes_in_parts() {
        let r = big();
        let limit = 16 << 10;
        let (parts, last) = split_report("c", 7, r, limit);
        assert!(parts.len() > 5, "{} parts", parts.len());
        for p in parts.iter().chain([&last]) {
            assert!(serde_json::to_vec(p).unwrap().len() <= limit, "a post over the limit");
            assert_eq!((p.client.as_str(), p.unit), ("c", 7));
        }
        let all: Vec<&BucketReport> = parts.iter().chain([&last]).map(|p| &p.report).collect();
        let keys: Vec<String> = all.iter().flat_map(|r| &r.findings).map(|f| f.key.clone().unwrap()).collect();
        assert_eq!(keys, (0..1000).map(|i| format!("key{i}")).collect::<Vec<_>>(), "every finding, once, in order");
        assert_eq!(last.earlier_findings + last.report.findings.len(), 1000);
        assert!(parts.iter().all(|p| p.earlier_findings == 0 && p.report.rados_objects == 0));
        assert_eq!((last.report.rados_objects, last.report.gaps, last.report.seconds), (5000, 1000, 1.5));
        assert_eq!(last.report.tally.classes.get("data_loss"), Some(&1000));
        // a head's references and their carriers in one part
        for r in &all {
            for oid in r.refs.needed.keys() {
                assert!(r.refs.carried.contains_key(oid), "{oid} without its carriers");
            }
        }
        assert_eq!(all.iter().map(|r| r.refs.needed.len()).sum::<usize>(), 50);
        assert_eq!(all.iter().map(|r| r.refs.carried.len()).sum::<usize>(), 60);
        assert_eq!(all.iter().map(|r| r.candidates.len()).sum::<usize>(), 200);
        let missing: Vec<&String> = all.iter().flat_map(|r| &r.missing).collect();
        assert_eq!(missing.len(), 1000, "every MISSING line, once");
        assert!(parts.iter().filter(|p| !p.report.missing.is_empty()).count() > 1, "the lines span parts");
        // the errors that did not fit are counted
        let errors = &last.report.errors;
        assert!(errors.len() < 500 && errors.last().unwrap().ends_with("more errors, not reported"), "{errors:?}");
        assert_eq!(errors.last().unwrap(), &format!("{} more errors, not reported", 500 - (errors.len() - 1)));
    }

    #[test]
    fn an_item_bigger_than_a_part_goes_alone() {
        let mut r = BucketReport { bucket: "b".into(), ..Default::default() };
        r.findings.push(Finding::new(Class::DataLoss, "missing_data", "b").key("small"));
        r.findings.push(Finding::new(Class::DataLoss, "missing_data", "b").key("x".repeat(4096)));
        r.findings.push(Finding::new(Class::DataLoss, "missing_data", "b").key("small2"));
        let (parts, last) = split_report("c", 1, r, 1024);
        let sizes: Vec<usize> = parts.iter().chain([&last]).map(|p| p.report.findings.len()).collect();
        assert_eq!(sizes, [1, 1, 1]);
        assert_eq!(last.earlier_findings, 2);
    }

    /// Errors are cut only from a report that is split: one that fits in a
    /// post keeps them all, though they are more than a quarter of it.
    #[test]
    fn a_report_that_fits_keeps_its_errors() {
        let r = BucketReport { bucket: "b".into(), errors: (0..100).map(|i| format!("stat of m_key{i}: timed out")).collect(), ..Default::default() };
        let limit = serde_json::to_vec(&Report { client: "c".into(), unit: 7, report: r, earlier_findings: 0 }).unwrap().len();
        let r = BucketReport { bucket: "b".into(), errors: (0..100).map(|i| format!("stat of m_key{i}: timed out")).collect(), ..Default::default() };
        let (parts, last) = split_report("c", 7, r, limit);
        assert!(parts.is_empty());
        assert_eq!(last.report.errors.len(), 100, "no error cut from a report that fits");
        // a byte less, and it is split: the errors are cut to a quarter of it
        let r = BucketReport { bucket: "b".into(), errors: (0..100).map(|i| format!("stat of m_key{i}: timed out")).collect(), ..Default::default() };
        let (_, last) = split_report("c", 7, r, limit - 1);
        assert!(last.report.errors.len() < 100 && last.report.errors.last().unwrap().ends_with("more errors, not reported"));
    }

    /// No post is over the limit, however tightly its items fill it: the
    /// candidates' key, which an empty report does not carry, is counted.
    #[test]
    fn posts_are_never_over_the_limit() {
        for limit in 600..700 {
            let r = BucketReport { bucket: "b".into(), candidates: (0..200).map(|i| format!("orphan{i:04}")).collect(), ..Default::default() };
            let (parts, last) = split_report("c", 7, r, limit);
            assert!(parts.len() > 1);
            for p in parts.iter().chain([&last]) {
                let n = serde_json::to_vec(p).unwrap().len();
                assert!(n <= limit, "a post of {n} bytes, over {limit}");
            }
            let all: Vec<&String> = parts.iter().chain([&last]).flat_map(|p| &p.report.candidates).collect();
            assert_eq!(all.len(), 200);
        }
    }

    /// The last part goes alone when it does not fit alongside the report's
    /// own fields ( its errors, tally and counts ): then the report carries
    /// those only, and every finding is in the parts before it.
    #[test]
    fn the_last_part_goes_alone_when_the_report_is_full() {
        let limit = 4096;
        let (mut alone, mut together) = (0, 0);
        for n in 1..80 {
            let mut r = BucketReport { bucket: "b".into(), rados_objects: 9, ..Default::default() };
            r.findings = (0..n).map(|i| Finding::new(Class::DataLoss, "missing_data", "b").key(format!("key{i}"))).collect();
            r.errors = (0..20).map(|i| format!("stat of m_key{i}: timed out")).collect();
            let (parts, last) = split_report("c", 7, r, limit);
            if parts.is_empty() {
                continue;
            }
            for p in parts.iter().chain([&last]) {
                assert!(serde_json::to_vec(p).unwrap().len() <= limit, "a post over the limit");
            }
            let keys: Vec<String> = parts.iter().chain([&last]).flat_map(|p| &p.report.findings).map(|f| f.key.clone().unwrap()).collect();
            assert_eq!(keys, (0..n).map(|i| format!("key{i}")).collect::<Vec<_>>(), "every finding, once, in order");
            assert_eq!(last.earlier_findings + last.report.findings.len(), n);
            assert_eq!((last.report.rados_objects, last.report.errors.len()), (9, 20));
            if last.report.findings.is_empty() {
                alone += 1;
                assert_eq!(last.earlier_findings, n);
            } else {
                together += 1;
            }
        }
        assert!(alone > 0 && together > 0, "{alone} alone, {together} with the report");
    }

    #[test]
    fn progress_from_older_clients() {
        let p: UnitProgress = serde_json::from_str(r#"{"unit":1,"bucket":"b","rados_objects":5}"#).unwrap();
        assert_eq!((p.rados_objects, p.gaps), (5, 0));
    }
}
