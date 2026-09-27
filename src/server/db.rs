//! The server's state, in SQLite: a local file, or a database in RADOS
//! through Ceph's SQLite VFS ( libcephsqlite ).

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, bail};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Tally};
use crate::proto::{Heartbeat, Unit};
use crate::scan::{Options, RefLedger};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    created INTEGER NOT NULL,
    finished INTEGER,
    state TEXT NOT NULL,
    options TEXT NOT NULL,
    context TEXT NOT NULL,
    gc_min_wait INTEGER NOT NULL,
    gc_entries INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    class TEXT NOT NULL,
    check_name TEXT NOT NULL,
    bucket TEXT NOT NULL,
    key TEXT,
    top_cause TEXT,
    confidence TEXT,
    after_fix INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    first_scan INTEGER,
    last_scan INTEGER,
    record TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS findings_by_class ON findings (class, status);
CREATE INDEX IF NOT EXISTS findings_by_bucket ON findings (bucket);
CREATE INDEX IF NOT EXISTS findings_by_cause ON findings (top_cause);
CREATE TABLE IF NOT EXISTS refs (
    scan_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    bucket TEXT NOT NULL,
    needed TEXT NOT NULL,
    carried TEXT NOT NULL,
    PRIMARY KEY (scan_id, oid)
);
CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    version TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    status TEXT NOT NULL,
    inflight_override INTEGER
);
CREATE TABLE IF NOT EXISTS scan_writers (
    scan_id INTEGER NOT NULL,
    client TEXT NOT NULL,
    PRIMARY KEY (scan_id, client)
);
CREATE TABLE IF NOT EXISTS orphan_candidates (
    scan_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    PRIMARY KEY (scan_id, oid)
);
-- the parts of a report sent ahead of it, by the client that sent them:
-- they count once that client's report comes in
CREATE TABLE IF NOT EXISTS report_parts (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    unit_id INTEGER NOT NULL,
    client TEXT NOT NULL,
    report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS report_parts_by_unit ON report_parts (unit_id, client);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    time INTEGER NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gap_lines (
    scan_id INTEGER NOT NULL,
    unit_id INTEGER NOT NULL,
    line TEXT NOT NULL,
    PRIMARY KEY (scan_id, unit_id, line)
);
CREATE INDEX IF NOT EXISTS gap_lines_by_line ON gap_lines (scan_id, line);
"#;

/// The units table's columns.  A unit is its kind and label: a shard unit's
/// label, bucket#shard, can be a Swift container's name ( Swift allows any
/// but '/' ), and a join's can too.
const UNITS: &str = r#"(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    bucket TEXT NOT NULL,
    objects INTEGER NOT NULL DEFAULT 0,
    stats TEXT,
    state TEXT NOT NULL,
    client TEXT,
    lease_expires INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    started INTEGER,
    finished INTEGER,
    rados_objects INTEGER,
    gaps INTEGER,
    findings INTEGER,
    seconds REAL,
    error TEXT,
    kind TEXT NOT NULL DEFAULT 'bucket',
    spec TEXT,
    skipped TEXT,
    UNIQUE (scan_id, kind, bucket)
)"#;

/// The finding statuses: a scan sets open and gone; people set the rest.
pub const STATUSES: [&str; 4] = ["open", "confirmed", "false_positive", "gone"];

/// Checks whose findings come from bucket scans, so a later scan of the
/// bucket that checked them again and no longer finds them marks them gone.
const BUCKET_CHECKS: [&str; 7] =
    ["missing_data", "queued_for_gc", "completed_upload_open", "part_entries_missing", "listed_without_head", "olh_missing", "stale_entry"];

/// The bucket checks a scan with these options runs, so the ones whose
/// findings it can mark gone.  `gc`: every unit had the GC snapshot.  With
/// the refcount check, its unheld references too: each is filed under the
/// bucket whose head needs the reference, and has no key, so only a scan of
/// every key retires it ( one under a prefix reads only its heads' tails ).
/// Of every bucket's keys too: the tail's references are merged across the
/// scan's buckets ( one filed under b may be for a copy in c ).
fn rechecked(o: &Options, gc: bool) -> Vec<&'static str> {
    let runs = |check: &str| match check {
        "queued_for_gc" => gc,
        // both come from the open uploads the index lists
        "completed_upload_open" | "part_entries_missing" => o.uploads,
        "stale_entry" => o.check_index,
        _ => true,
    };
    let refcount = (o.refcount && (o.every_bucket || o.orphans) && o.match_prefix.is_none()).then_some("unheld_reference");
    BUCKET_CHECKS.into_iter().filter(|c| runs(c)).chain(refcount).collect()
}

/// Checks whose findings come from orphan detection.
const ORPHAN_CHECKS: &str = "('orphan_parts', 'orphan_tail', 'orphan_other', 'orphan_of_removed_bucket', 'unlisted_head')";

/// Settings the dashboard controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// RADOS operations in flight across every client
    pub global_inflight: usize,
    /// units each client scans at once
    pub parallel: usize,
    pub paused: bool,
    pub lease_secs: i64,
    /// pull requests of the fixes the build carries, and since when
    pub fixed: Vec<u32>,
    pub fixed_since: Option<String>,
    /// the release, instead of `ceph versions`
    pub release: Option<String>,
    /// start a scan this many hours after the last one finished; 0: never
    pub auto_scan_hours: u64,
    pub default_options: Options,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            global_inflight: 1024,
            parallel: 2,
            paused: false,
            lease_secs: 120,
            fixed: Vec::new(),
            fixed_since: None,
            release: None,
            auto_scan_hours: 0,
            default_options: Options::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRow {
    pub id: i64,
    pub created: i64,
    pub finished: Option<i64>,
    pub state: String,
    pub options: Options,
    pub gc_entries: i64,
    pub note: String,
    pub units: i64,
    pub pending: i64,
    pub leased: i64,
    pub done: i64,
    pub failed: i64,
    pub objects: i64,
    pub objects_done: i64,
    pub rados_objects: i64,
    pub findings: i64,
    /// the RADOS objects the done units found missing
    #[serde(default)]
    pub gaps: i64,
    /// units done, but with errors: some of their bucket is unchecked
    #[serde(default)]
    pub errored: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitRow {
    pub id: i64,
    pub kind: String,
    pub bucket: String,
    pub objects: i64,
    pub state: String,
    pub client: Option<String>,
    pub attempts: i64,
    pub started: Option<i64>,
    pub finished: Option<i64>,
    pub rados_objects: Option<i64>,
    /// the RADOS objects it found missing, its lines in the scan's gap list
    pub gaps: Option<i64>,
    pub findings: Option<i64>,
    pub seconds: Option<f64>,
    pub error: Option<String>,
    /// what its checks skipped, by reason
    #[serde(default)]
    pub skipped: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRow {
    pub id: i64,
    pub status: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub first_scan: Option<i64>,
    pub last_scan: Option<i64>,
    pub note: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRow {
    pub id: String,
    pub host: String,
    pub version: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub status: Heartbeat,
    pub inflight_override: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub time: i64,
    pub kind: String,
    pub message: String,
}

/// Filters of the findings list; every field narrows it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Filter {
    pub class: Option<String>,
    pub check: Option<String>,
    pub bucket: Option<String>,
    pub cause: Option<String>,
    pub status: Option<String>,
    pub confidence: Option<String>,
    /// a substring of the key
    pub key: Option<String>,
    pub after_fix: Option<bool>,
    pub scan: Option<i64>,
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}

impl Filter {
    fn clause(&self) -> (String, Vec<rusqlite::types::Value>) {
        use rusqlite::types::Value;
        let mut conds = Vec::new();
        let mut args: Vec<Value> = Vec::new();
        let mut eq = |col: &str, v: &Option<String>| {
            if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
                conds.push(format!("{col} = ?"));
                args.push(Value::Text(v.clone()));
            }
        };
        eq("class", &self.class);
        eq("check_name", &self.check);
        eq("bucket", &self.bucket);
        eq("top_cause", &self.cause);
        // "active": open or confirmed
        eq("status", &self.status.clone().filter(|s| s != "active"));
        eq("confidence", &self.confidence);
        if self.status.as_deref() == Some("active") {
            conds.push("status IN ('open', 'confirmed')".into());
        }
        if let Some(k) = self.key.as_ref().filter(|k| !k.is_empty()) {
            conds.push("instr(key, ?) > 0".into());
            args.push(Value::Text(k.clone()));
        }
        if let Some(a) = self.after_fix {
            conds.push("after_fix = ?".into());
            args.push(Value::Integer(a as i64));
        }
        if let Some(s) = self.scan {
            conds.push("last_scan = ?".into());
            args.push(Value::Integer(s));
        }
        let clause = if conds.is_empty() { String::new() } else { format!("WHERE {}", conds.join(" AND ")) };
        (clause, args)
    }
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    pub location: String,
}

impl Db {
    /// `file:<path>`, or `ceph:<pool>[:<namespace>]/<name>` through
    /// libcephsqlite, which is loaded from `cephsqlite`.
    pub fn open(spec: &str, cephsqlite: &str) -> Result<Db> {
        let conn = if let Some(path) = spec.strip_prefix("file:") {
            let conn = Connection::open(path).with_context(|| format!("opening {path}"))?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn
        } else if let Some(rest) = spec.strip_prefix("ceph:") {
            let Some((pool, name)) = rest.split_once('/') else { bail!("--db ceph:<pool>[:<namespace>]/<name>") };
            // loading the extension registers the "ceph" VFS for every connection
            let loader = Connection::open_in_memory()?;
            unsafe {
                let _guard = rusqlite::LoadExtensionGuard::new(&loader)?;
                loader
                    .load_extension(Path::new(cephsqlite), None::<&str>)
                    .with_context(|| format!("loading {cephsqlite}"))?;
            }
            // libcephsqlite's URIs are file:///<pool>:[<namespace>]/<name>, with the colon
            let pool = if pool.contains(':') { pool.to_string() } else { format!("{pool}:") };
            let uri = format!("file:///{pool}/{name}?vfs=ceph");
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_URI;
            let conn = Connection::open_with_flags(&uri, flags).with_context(|| format!("opening {uri}"))?;
            // as libcephsqlite recommends: one writer, and large pages
            conn.pragma_update(None, "page_size", 65536)?;
            conn.pragma_update(None, "cache_size", 4096)?;
            conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
            conn.pragma_update(None, "journal_mode", "PERSIST")?;
            conn
        } else {
            bail!("--db is file:<path> or ceph:<pool>[:<namespace>]/<name>");
        };
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(&format!("CREATE TABLE IF NOT EXISTS units {UNITS};"))?;
        migrate(&conn)?;
        Ok(Db { conn: Arc::new(Mutex::new(conn)), location: spec.to_string() })
    }

    /// Run `f` on the connection, off the async threads.
    pub async fn call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || f(&mut conn.lock().unwrap())).await?
    }
}

/// Columns added since the first schema.
fn migrate(c: &Connection) -> Result<()> {
    let columns = |table: &str| -> Result<Vec<String>> {
        let mut st = c.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = st.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<_>>()?;
        Ok(names)
    };
    let units = columns("units")?;
    if !units.iter().any(|c| c == "kind") {
        c.execute_batch("ALTER TABLE units ADD COLUMN kind TEXT NOT NULL DEFAULT 'bucket'; ALTER TABLE units ADD COLUMN spec TEXT;")?;
    }
    // what a unit's checks skipped, and why
    if !units.iter().any(|c| c == "skipped") {
        c.execute_batch("ALTER TABLE units ADD COLUMN skipped TEXT;")?;
    }
    let scans = columns("scans")?;
    if !scans.iter().any(|c| c == "plan") {
        c.execute_batch("ALTER TABLE scans ADD COLUMN plan TEXT;")?;
    }
    // set when a unit may have scanned without the GC snapshot
    if !scans.iter().any(|c| c == "no_gc") {
        c.execute_batch("ALTER TABLE scans ADD COLUMN no_gc INTEGER NOT NULL DEFAULT 0;")?;
    }
    // the status a scan marked a finding gone from, which finding it again restores
    let findings = columns("findings")?;
    if !findings.iter().any(|c| c == "gone_from") {
        c.execute_batch("ALTER TABLE findings ADD COLUMN gone_from TEXT;")?;
    }
    // and the scan that did, which evidence from before it does not undo
    if !findings.iter().any(|c| c == "gone_scan") {
        let tx = c.unchecked_transaction()?;
        tx.execute_batch("ALTER TABLE findings ADD COLUMN gone_scan INTEGER;")?;
        // what went gone before: the scan is not recorded, but none after the
        // last one done can have marked it ( a person may have: from before
        // gone_from, theirs is not told from a scan's ).  So a late report of
        // a scan no newer reopens it no more, as for what is marked gone since
        let by = if findings.iter().any(|c| c == "gone_from") { "AND gone_from IS NOT NULL" } else { "" };
        tx.execute(
            &format!("UPDATE findings SET gone_scan = (SELECT MAX(id) FROM scans WHERE state = 'done') WHERE status = 'gone' {by}"),
            [],
        )?;
        tx.commit()?;
    }
    // units were once unique by label alone; SQLite cannot change a table's
    // constraints, so copy it into one of the new shape
    let by_label = {
        let mut st = c.prepare(
            "SELECT COUNT(*) FROM pragma_index_list('units') l
             WHERE l.\"unique\" AND l.origin = 'u'
               AND (SELECT group_concat(name, ',') FROM (SELECT name FROM pragma_index_info(l.name) ORDER BY seqno)) = 'scan_id,bucket'",
        )?;
        st.query_row([], |r| r.get::<_, i64>(0))? > 0
    };
    if by_label {
        let names = columns("units")?.join(", ");
        let tx = c.unchecked_transaction()?;
        tx.execute_batch(&format!(
            "CREATE TABLE units_new {UNITS};
             INSERT INTO units_new ({names}) SELECT {names} FROM units;
             DROP TABLE units;
             ALTER TABLE units_new RENAME TO units;"
        ))?;
        tx.commit()?;
    }
    c.execute_batch("CREATE INDEX IF NOT EXISTS units_by_state ON units (scan_id, state);")?;
    Ok(())
}

pub fn settings(c: &Connection) -> Result<Settings> {
    let v: Option<String> = c.query_row("SELECT value FROM settings WHERE key = 'settings'", [], |r| r.get(0)).optional()?;
    Ok(v.map(|v| serde_json::from_str(&v)).transpose()?.unwrap_or_default())
}

pub fn save_settings(c: &Connection, s: &Settings) -> Result<()> {
    c.execute(
        "INSERT INTO settings (key, value) VALUES ('settings', ?1) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [serde_json::to_string(s)?],
    )?;
    Ok(())
}

pub fn event(c: &Connection, now: i64, kind: &str, message: &str) -> Result<()> {
    c.execute("INSERT INTO events (time, kind, message) VALUES (?1, ?2, ?3)", params![now, kind, message])?;
    tracing::info!("{kind}: {message}");
    Ok(())
}

pub fn events(c: &Connection, limit: usize) -> Result<Vec<Event>> {
    let mut st = c.prepare("SELECT time, kind, message FROM events ORDER BY id DESC LIMIT ?1")?;
    let rows = st.query_map([limit as i64], |r| Ok(Event { time: r.get(0)?, kind: r.get(1)?, message: r.get(2)? }))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// A unit of a new scan: a bucket to scan, a slice of a pool to list, or a
/// partition to join; joins wait for the rest.
pub struct NewUnit {
    pub label: String,
    pub kind: &'static str,
    pub objects: u64,
    pub stats: Option<String>,
    pub spec: Option<String>,
    pub blocked: bool,
}

impl NewUnit {
    pub fn bucket(name: String, objects: u64, stats: Option<String>) -> NewUnit {
        NewUnit { label: name, kind: "bucket", objects, stats, spec: None, blocked: false }
    }

    /// One index shard of a bucket, labelled bucket#shard: the bucket is its
    /// spec's, as a Swift container's name can have a # of its own
    pub fn shard(st: &crate::admin::BucketStats, shard: u32, stats: Option<String>) -> Result<NewUnit> {
        let (bucket, shards) = (st.name(), st.num_shards.max(1) as u32);
        let spec = crate::detect::ShardUnit { bucket: bucket.clone(), shard, shards };
        Ok(NewUnit {
            label: format!("{bucket}#{shard}"),
            kind: "shard",
            objects: st.num_objects() / shards as u64,
            stats,
            spec: Some(serde_json::to_string(&spec)?),
            blocked: false,
        })
    }
}

/// The bucket a bucket or shard unit scans.
const UNIT_BUCKET: &str = "CASE kind WHEN 'shard' THEN json_extract(spec, '$.bucket') ELSE bucket END";

#[allow(clippy::too_many_arguments)]
pub fn insert_scan(
    c: &mut Connection,
    now: i64,
    options: &Options,
    context: &crate::finding::Context,
    gc_min_wait: i64,
    gc_entries: usize,
    note: &str,
    plan: Option<&crate::detect::Plan>,
    units: &[NewUnit],
) -> Result<i64> {
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO scans (created, state, options, context, gc_min_wait, gc_entries, note, plan) VALUES (?1, 'running', ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            now,
            serde_json::to_string(options)?,
            serde_json::to_string(context)?,
            gc_min_wait,
            gc_entries as i64,
            note,
            plan.map(serde_json::to_string).transpose()?
        ],
    )?;
    let id = tx.last_insert_rowid();
    {
        let mut st = tx.prepare("INSERT OR IGNORE INTO units (scan_id, bucket, objects, stats, state, kind, spec) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")?;
        for u in units {
            st.execute(params![id, u.label, u.objects as i64, u.stats, if u.blocked { "blocked" } else { "pending" }, u.kind, u.spec])?;
        }
    }
    tx.commit()?;
    Ok(id)
}

/// Record that a unit of the scan may run without its GC snapshot ( none was
/// taken, or the server lost it ): the scan cannot tell queued_for_gc gone.
pub fn gc_missed(c: &Connection, scan: i64) -> Result<()> {
    c.execute("UPDATE scans SET no_gc = 1 WHERE id = ?1", [scan])?;
    Ok(())
}

pub fn running_scan(c: &Connection) -> Result<Option<i64>> {
    Ok(c.query_row("SELECT id FROM scans WHERE state = 'running' ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).optional()?)
}

pub fn scan_spec(c: &Connection, id: i64) -> Result<Option<crate::proto::ScanSpec>> {
    let row: Option<(String, String, i64, Option<String>)> = c
        .query_row("SELECT options, context, gc_min_wait, plan FROM scans WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .optional()?;
    row.map(|(o, ctx, w, plan)| {
        Ok(crate::proto::ScanSpec {
            id,
            options: serde_json::from_str(&o)?,
            context: serde_json::from_str(&ctx)?,
            gc_min_wait: w,
            plan: plan.map(|p| serde_json::from_str(&p)).transpose()?,
        })
    })
    .transpose()
}

/// The clients that leased any unit of a scan: the ones that may have
/// written its partitions.
pub fn scan_writers(c: &Connection, scan: i64) -> Result<Vec<String>> {
    let mut st = c.prepare("SELECT client FROM scan_writers WHERE scan_id = ?1 ORDER BY client")?;
    let rows = st.query_map([scan], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The stats of the buckets a scan covers.
pub fn scan_buckets(c: &Connection, scan: i64) -> Result<Vec<crate::admin::BucketStats>> {
    let mut st = c.prepare(&format!(
        "SELECT MIN(stats) FROM units WHERE scan_id = ?1 AND kind IN ('bucket', 'shard') AND stats IS NOT NULL GROUP BY {UNIT_BUCKET}"
    ))?;
    let rows = st.query_map([scan], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for s in rows {
        if let Ok(st) = serde_json::from_str(&s?) {
            out.push(st);
        }
    }
    Ok(out)
}

/// Once every bucket and pool slice of a scan is in, let its joins be
/// leased; if any failed, the references are incomplete, so cancel them.
/// So too if a bucket listed with radoslist is done with errors: radoslist
/// leaves out open uploads' parts, which the bucket's upload listing names,
/// and a failed one leaves them for orphans ( a native listing reads them
/// from the index, and its errors cut the bucket's scan short ).  A unit
/// that cannot list them or read its stats fails, as a standalone scan's
/// does; this is for the reports of clients from before that.
fn unblock_joins(c: &Connection, scan: i64) -> Result<Option<String>> {
    let count = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [scan], |r| r.get(0))?) };
    let blocked = count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind = 'join' AND state = 'blocked'")?;
    if blocked == 0 {
        return Ok(None);
    }
    if count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind != 'join' AND state IN ('pending', 'leased')")? > 0 {
        return Ok(None);
    }
    let cancel = |why: &str| -> Result<()> {
        c.execute("UPDATE units SET state = 'cancelled', error = ?2 WHERE scan_id = ?1 AND kind = 'join' AND state = 'blocked'", params![scan, why])?;
        Ok(())
    };
    let failed = count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind != 'join' AND state = 'failed'")?;
    if failed > 0 {
        cancel("a bucket or pool slice failed, so its references are incomplete")?;
        return Ok(Some(format!("scan {scan}: {failed} buckets or pool slices failed; orphan detection skipped")));
    }
    let options: String = c.query_row("SELECT options FROM scans WHERE id = ?1", [scan], |r| r.get(0))?;
    let options: Options = serde_json::from_str(&options)?;
    if options.listing == crate::scan::Listing::Radoslist && options.uploads {
        let errored = count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind = 'bucket' AND state = 'done' AND error IS NOT NULL")?;
        if errored > 0 {
            cancel("a bucket listed with radoslist had errors, so its open uploads' parts may be unreferenced")?;
            return Ok(Some(format!(
                "scan {scan}: {errored} buckets listed with radoslist had errors, which may leave their open uploads' parts out of the references; orphan detection skipped"
            )));
        }
    }
    let writers = scan_writers(c, scan)?;
    let joins: Vec<(i64, String)> = {
        let mut st = c.prepare("SELECT id, spec FROM units WHERE scan_id = ?1 AND kind = 'join' AND state = 'blocked'")?;
        st.query_map([scan], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
    };
    for (id, spec) in &joins {
        let mut j: crate::detect::Join = serde_json::from_str(spec)?;
        j.writers = writers.clone();
        c.execute("UPDATE units SET state = 'pending', spec = ?1 WHERE id = ?2", params![serde_json::to_string(&j)?, id])?;
    }
    Ok(Some(format!("scan {scan}: every bucket and pool slice is in; {} partitions to join", joins.len())))
}



pub fn scans(c: &Connection, limit: usize) -> Result<Vec<ScanRow>> {
    let mut st = c.prepare(
        "SELECT s.id, s.created, s.finished, s.state, s.options, s.gc_entries, s.note,
                COUNT(u.id),
                SUM(u.state = 'pending'), SUM(u.state = 'leased'), SUM(u.state = 'done'), SUM(u.state = 'failed'),
                SUM(u.objects), SUM(CASE WHEN u.state = 'done' THEN u.objects ELSE 0 END),
                SUM(COALESCE(u.rados_objects, 0)), SUM(COALESCE(u.findings, 0)),
                SUM(COALESCE(u.gaps, 0)), SUM(u.state = 'done' AND u.error IS NOT NULL)
         FROM scans s LEFT JOIN units u ON u.scan_id = s.id
         GROUP BY s.id ORDER BY s.id DESC LIMIT ?1",
    )?;
    let rows = st.query_map([limit as i64], |r| {
        let options: String = r.get(4)?;
        Ok(ScanRow {
            id: r.get(0)?,
            created: r.get(1)?,
            finished: r.get(2)?,
            state: r.get(3)?,
            options: serde_json::from_str(&options).unwrap_or_default(),
            gc_entries: r.get(5)?,
            note: r.get(6)?,
            units: r.get(7)?,
            pending: r.get::<_, Option<i64>>(8)?.unwrap_or(0),
            leased: r.get::<_, Option<i64>>(9)?.unwrap_or(0),
            done: r.get::<_, Option<i64>>(10)?.unwrap_or(0),
            failed: r.get::<_, Option<i64>>(11)?.unwrap_or(0),
            objects: r.get::<_, Option<i64>>(12)?.unwrap_or(0),
            objects_done: r.get::<_, Option<i64>>(13)?.unwrap_or(0),
            rados_objects: r.get::<_, Option<i64>>(14)?.unwrap_or(0),
            findings: r.get::<_, Option<i64>>(15)?.unwrap_or(0),
            gaps: r.get::<_, Option<i64>>(16)?.unwrap_or(0),
            errored: r.get::<_, Option<i64>>(17)?.unwrap_or(0),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn units(c: &Connection, scan: i64, state: Option<&str>, limit: usize) -> Result<Vec<UnitRow>> {
    let mut st = c.prepare(
        "SELECT id, bucket, objects, state, client, attempts, started, finished, rados_objects, findings, seconds, error, kind, gaps, skipped
         FROM units WHERE scan_id = ?1 AND (?2 IS NULL OR state = ?2)
         ORDER BY CASE state WHEN 'leased' THEN 0 WHEN 'failed' THEN 1 WHEN 'pending' THEN 2 ELSE 3 END, objects DESC LIMIT ?3",
    )?;
    let rows = st.query_map(params![scan, state, limit as i64], |r| {
        Ok(UnitRow {
            id: r.get(0)?,
            bucket: r.get(1)?,
            objects: r.get(2)?,
            state: r.get(3)?,
            client: r.get(4)?,
            attempts: r.get(5)?,
            started: r.get(6)?,
            finished: r.get(7)?,
            rados_objects: r.get(8)?,
            findings: r.get(9)?,
            seconds: r.get(10)?,
            error: r.get(11)?,
            kind: r.get(12)?,
            gaps: r.get(13)?,
            skipped: r.get::<_, Option<String>>(14)?.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Lease up to `max` pending units of the running scan, largest first.
pub fn lease(c: &mut Connection, client: &str, max: usize, now: i64, lease_secs: i64) -> Result<Vec<Unit>> {
    let tx = c.transaction()?;
    let Some(scan) = running_scan(&tx)? else { return Ok(Vec::new()) };
    let picked: Vec<(i64, String, Option<String>, String, Option<String>)> = {
        let mut st = tx.prepare(
            "SELECT id, bucket, stats, kind, spec FROM units WHERE scan_id = ?1 AND state = 'pending' ORDER BY objects DESC, id LIMIT ?2",
        )?;
        st.query_map(params![scan, max as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    if !picked.is_empty() {
        tx.execute("INSERT OR IGNORE INTO scan_writers (scan_id, client) VALUES (?1, ?2)", params![scan, client])?;
    }
    let mut units = Vec::new();
    for (id, bucket, stats, kind, spec) in picked {
        tx.execute(
            "UPDATE units SET state = 'leased', client = ?1, lease_expires = ?2, started = COALESCE(started, ?3) WHERE id = ?4",
            params![client, now + lease_secs, now, id],
        )?;
        // a new attempt: what the parts of an earlier one sent may be stale
        tx.execute("DELETE FROM gap_lines WHERE scan_id = ?1 AND unit_id = ?2", params![scan, id])?;
        units.push(Unit {
            id,
            scan,
            bucket,
            stats: stats.and_then(|s| serde_json::from_str(&s).ok()),
            kind,
            spec: spec.and_then(|s| serde_json::from_str(&s).ok()),
        });
    }
    tx.commit()?;
    Ok(units)
}

/// Extend a client's leases on the units it reports it is scanning.
pub fn renew(c: &Connection, client: &str, units: &[i64], expires: i64) -> Result<()> {
    let mut st = c.prepare("UPDATE units SET lease_expires = ?1 WHERE id = ?2 AND client = ?3 AND state = 'leased'")?;
    for u in units {
        st.execute(params![expires, u, client])?;
    }
    Ok(())
}

/// Leases whose clients stopped renewing them go back to pending, or fail
/// after three attempts.  Returns the buckets.
pub fn reap(c: &Connection, now: i64) -> Result<Vec<(String, Option<String>)>> {
    let expired: Vec<(i64, String, Option<String>)> = {
        let mut st = c.prepare("SELECT id, bucket, client FROM units WHERE state = 'leased' AND lease_expires < ?1")?;
        st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?
    };
    for (id, _, _) in &expired {
        c.execute(
            "UPDATE units SET state = CASE WHEN attempts + 1 >= 3 THEN 'failed' ELSE 'pending' END,
                              attempts = attempts + 1, client = NULL, lease_expires = NULL, error = 'lease expired'
             WHERE id = ?1",
            [id],
        )?;
    }
    Ok(expired.into_iter().map(|(_, b, c)| (b, c)).collect())
}

/// A client's attempt at a unit failed: the unit goes back to pending, or
/// fails after three attempts, and the parts the attempt sent do not count.
pub fn fail(c: &Connection, unit: i64, client: &str, error: &str, now: i64) -> Result<()> {
    let tx = c.unchecked_transaction()?;
    tx.execute(
        "UPDATE units SET state = CASE WHEN attempts + 1 >= 3 THEN 'failed' ELSE 'pending' END,
                          attempts = attempts + 1, client = NULL, lease_expires = NULL, error = ?1
         WHERE id = ?2 AND client = ?3 AND state = 'leased'",
        params![error, unit, client],
    )?;
    drop_parts(&tx, "unit_id = ?1 AND client = ?2", params![unit, client], Some(now))?;
    tx.commit()?;
    Ok(())
}

/// Record a finding `scan` found, or one found outside a scan ( imported, or
/// in the parts of a failed attempt ): a finding a scan marked gone gets
/// back the status it had, so a person's triage survives it.  Its last scan
/// only moves forward: a late report of an older scan ( cancelled, say )
/// does not make a newer scan that found it too retire it, nor reopen one a
/// newer scan marked gone, as it looked before that scan did.
pub fn upsert_finding(c: &Connection, scan: Option<i64>, f: &Finding, now: i64) -> Result<()> {
    let top = f.top_cause();
    c.execute(
        &format!(
            "INSERT INTO findings (fingerprint, class, check_name, bucket, key, top_cause, confidence, after_fix,
                                   first_seen, last_seen, first_scan, last_scan, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?10, ?11)
             ON CONFLICT (fingerprint) DO UPDATE SET
                 class = excluded.class, top_cause = excluded.top_cause, confidence = excluded.confidence,
                 after_fix = excluded.after_fix, last_seen = excluded.last_seen,
                 last_scan = COALESCE(MAX(excluded.last_scan, last_scan), excluded.last_scan, last_scan), record = excluded.record,
                 status = CASE WHEN status = 'gone' AND {STALE} THEN status WHEN status = 'gone' THEN COALESCE(gone_from, 'open') ELSE status END,
                 gone_from = CASE WHEN status = 'gone' AND {STALE} THEN gone_from END,
                 gone_scan = CASE WHEN status = 'gone' AND {STALE} THEN gone_scan END"
        ),
        params![
            f.fingerprint(),
            f.class.as_str(),
            f.check,
            f.bucket,
            f.key,
            top.map(|c| c.cause.clone()),
            top.map(|c| c.confidence.as_str()),
            f.after_fix as i64,
            now,
            scan,
            serde_json::to_string(f)?
        ],
    )?;
    Ok(())
}

/// In upsert_finding's update: the evidence is of a scan no newer than the
/// one that marked the finding gone.  Evidence of no scan is newer: it comes
/// from attempts of the scan running, and a scan retires only as it closes.
const STALE: &str = "excluded.last_scan <= gone_scan";

/// Record a finding only if none has its fingerprint: an unverified one, as
/// imported from rgw-gap-list, neither replaces what a scan found nor reopens
/// what a scan marked gone.  true: it was new.
///
/// A gap list says not when it was made, so a stale one is not told from a
/// loss that came back after a scan marked it gone: the loss stays gone
/// until a scan of its bucket finds it again.
pub fn insert_finding(c: &Connection, f: &Finding, now: i64) -> Result<bool> {
    let known: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM findings WHERE fingerprint = ?1)", [f.fingerprint()], |r| r.get(0))?;
    if !known {
        upsert_finding(c, None, f, now)?;
    }
    Ok(!known)
}

/// Record a unit's report in one post: its findings, its references, and
/// the unit done.
#[cfg(test)]
pub fn complete(c: &mut Connection, scan: i64, unit: i64, client: &str, r: &crate::scan::BucketReport, now: i64) -> Result<()> {
    complete_after_parts(c, scan, unit, client, r, 0, now)
}

/// Keep a part of a unit's report, sent ahead of the report itself, if the
/// client still holds the unit.  Whether it did.  The part counts once the
/// client's report comes in: the parts of an attempt that fails, or whose
/// report never arrives, record no finding of the scan and no reference.
pub fn report_part(c: &mut Connection, scan: i64, unit: i64, client: &str, r: &crate::scan::BucketReport, _now: i64) -> Result<bool> {
    let tx = c.transaction()?;
    let held: i64 =
        tx.query_row("SELECT COUNT(*) FROM units WHERE id = ?1 AND client = ?2 AND state = 'leased'", params![unit, client], |row| row.get(0))?;
    if held == 0 {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO report_parts (scan_id, unit_id, client, report) VALUES (?1, ?2, ?3, ?4)",
        params![scan, unit, client, serde_json::to_string(r)?],
    )?;
    tx.commit()?;
    Ok(true)
}

/// The kept parts `filter` selects, one at a time.
fn each_part(tx: &Connection, filter: &str, args: impl rusqlite::Params, mut f: impl FnMut(crate::scan::BucketReport) -> Result<()>) -> Result<()> {
    let ids: Vec<i64> = {
        let mut st = tx.prepare(&format!("SELECT id FROM report_parts WHERE {filter} ORDER BY id"))?;
        st.query_map(args, |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    for id in ids {
        let part: String = tx.query_row("SELECT report FROM report_parts WHERE id = ?1", [id], |r| r.get(0))?;
        f(serde_json::from_str(&part)?)?;
    }
    Ok(())
}

/// Drop the kept parts `filter` selects.  `evidence`: the time to record
/// their findings at, as still what the cluster held, but as of no scan:
/// they neither count as the scan's nor keep it from marking them gone.
fn drop_parts(tx: &Connection, filter: &str, args: impl rusqlite::Params + Clone, evidence: Option<i64>) -> Result<()> {
    if let Some(now) = evidence {
        each_part(tx, filter, args.clone(), |part| part.findings.iter().try_for_each(|f| upsert_finding(tx, None, f, now)))?;
    }
    tx.execute(&format!("DELETE FROM report_parts WHERE {filter}"), args)?;
    Ok(())
}

/// Record a unit's report, the last of it when the client sent parts first
/// carrying `earlier` findings: the parts and the report's findings, their
/// references, and the unit done.  Once another attempt's report is in, it
/// adds nothing.  A unit of a scan that no longer runs ( cancelled, or closed
/// without it ) stays as it is, and only its findings are recorded: nothing
/// finishes that scan, so its references and candidates would count for
/// nothing, but what it found may still be in the cluster.  They are recorded
/// as that scan's, which does not take a finding a newer scan found back to
/// it, nor reopen one a newer scan marked gone.
pub fn complete_after_parts(c: &mut Connection, scan: i64, unit: i64, client: &str, r: &crate::scan::BucketReport, earlier: usize, now: i64) -> Result<()> {
    let tx = c.transaction()?;
    let (state, running): (String, bool) = tx.query_row(
        "SELECT u.state, s.state = 'running' FROM units u JOIN scans s ON s.id = u.scan_id WHERE u.id = ?1 AND s.id = ?2",
        params![unit, scan],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if state == "done" {
        return Ok(());
    }
    if !running || state == "cancelled" {
        for f in &r.findings {
            upsert_finding(&tx, Some(scan), f, now)?;
        }
        tx.commit()?;
        return Ok(());
    }
    let (mut kept, mut missing) = (0, Vec::new());
    each_part(&tx, "unit_id = ?1 AND client = ?2", params![unit, client], |part| {
        kept += part.findings.len();
        missing.extend(part.missing.iter().cloned());
        record(&tx, scan, &part, now)
    })?;
    if kept < earlier {
        bail!("unit {unit}: {earlier} findings were sent ahead of the report, but {kept} are here; scan it again");
    }
    // what other attempts sent ahead: this one's report supersedes it
    drop_parts(&tx, "unit_id = ?1", [unit], None)?;
    record(&tx, scan, r, now)?;
    let errors = if r.errors.is_empty() { None } else { Some(r.errors.join("; ")) };
    let skipped = if r.tally.skipped.is_empty() { None } else { Some(serde_json::to_string(&r.tally.skipped)?) };
    let done = tx.execute(
        "UPDATE units SET state = 'done', finished = ?1, rados_objects = ?2, gaps = ?3, findings = ?4, seconds = ?5,
                          error = ?6, client = ?7, lease_expires = NULL, skipped = ?9
         WHERE id = ?8 AND state != 'done'",
        params![now, r.rados_objects as i64, r.gaps as i64, (r.findings.len() + earlier) as i64, r.seconds, errors, client, unit, skipped],
    )?;
    // only the report that marks the unit done adds to its gap list: a
    // duplicate or a late one adds nothing
    if done > 0 {
        missing.extend(r.missing.iter().cloned());
        let held = gap_list(&tx, scan, unit, &missing)?;
        if held > 0 {
            tx.execute("UPDATE units SET gaps = MAX(gaps - ?1, 0) WHERE id = ?2", params![held as i64, unit])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// A report's findings, references and orphan candidates.
fn record(tx: &Connection, scan: i64, r: &crate::scan::BucketReport, now: i64) -> Result<()> {
    for f in &r.findings {
        upsert_finding(&tx, Some(scan), f, now)?;
    }
    // a tail object's references and carriers can come from several buckets'
    // reports, as copies cross buckets: merge them
    for (oid, (bucket, needed)) in &r.refs.needed {
        let carried = r.refs.carried.get(oid).cloned().unwrap_or_default();
        let old: Option<(String, String)> = tx
            .query_row("SELECT needed, carried FROM refs WHERE scan_id = ?1 AND oid = ?2", params![scan, oid], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let (mut n, mut c) = (needed.clone(), carried);
        if let Some((on, oc)) = old {
            n.extend(serde_json::from_str::<std::collections::BTreeSet<String>>(&on)?);
            c.extend(serde_json::from_str::<std::collections::BTreeSet<String>>(&oc)?);
        }
        // a row only carriers made so far takes the bucket of the reference
        tx.execute(
            "INSERT INTO refs (scan_id, oid, bucket, needed, carried) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (scan_id, oid) DO UPDATE SET needed = excluded.needed, carried = excluded.carried,
                 bucket = CASE WHEN refs.needed = '[]' THEN excluded.bucket ELSE refs.bucket END",
            params![scan, oid, bucket, serde_json::to_string(&n)?, serde_json::to_string(&c)?],
        )?;
    }
    // heads that name a refcounted object this report did not see referenced
    // ( outside the scan's prefix ): kept for the report that does, whichever
    // comes first
    for (oid, carried) in r.refs.carried.iter().filter(|(o, _)| !r.refs.needed.contains_key(*o)) {
        let old: Option<String> =
            tx.query_row("SELECT carried FROM refs WHERE scan_id = ?1 AND oid = ?2", params![scan, oid], |row| row.get(0)).optional()?;
        let mut c = carried.clone();
        if let Some(oc) = old {
            c.extend(serde_json::from_str::<std::collections::BTreeSet<String>>(&oc)?);
        }
        tx.execute(
            "INSERT INTO refs (scan_id, oid, bucket, needed, carried) VALUES (?1, ?2, ?3, '[]', ?4)
             ON CONFLICT (scan_id, oid) DO UPDATE SET carried = excluded.carried",
            params![scan, oid, r.bucket, serde_json::to_string(&c)?],
        )?;
    }
    for oid in &r.candidates {
        tx.execute("INSERT OR IGNORE INTO orphan_candidates (scan_id, oid) VALUES (?1, ?2)", params![scan, oid])?;
    }
    Ok(())
}

/// Add to a unit's lines in the scan's gap list, rgw-gap-list's
/// `s3://bucket/key MISSING <oid>`; a line it has already is kept once ( a
/// null version's head, listed as its key's OLH too ), and one another unit
/// of the scan has is left to it: a Swift large object's segment that units
/// in several buckets or shards follow.  Returns how many of the lines are
/// either, which the unit's gaps do not count.
fn gap_list(tx: &Connection, scan: i64, unit: i64, lines: &[String]) -> Result<usize> {
    let mut held = tx.prepare("SELECT EXISTS (SELECT 1 FROM gap_lines WHERE scan_id = ?1 AND line = ?2 AND unit_id != ?3)")?;
    let mut st = tx.prepare("INSERT OR IGNORE INTO gap_lines (scan_id, unit_id, line) VALUES (?1, ?2, ?3)")?;
    let mut others = 0;
    for line in lines {
        if held.query_row(params![scan, line, unit], |r| r.get::<_, bool>(0))? {
            others += 1;
            continue;
        }
        if st.execute(params![scan, unit, line])? == 0 {
            others += 1;
        }
    }
    Ok(others)
}

/// A page of a scan's gap list, by unit: up to `limit` lines after `after`,
/// the unit and line a page ended with.
pub fn gap_lines(c: &Connection, scan: i64, after: Option<&(i64, String)>, limit: usize) -> Result<Vec<(i64, String)>> {
    let (unit, line) = after.map_or((i64::MIN, ""), |(u, l)| (*u, l.as_str()));
    let mut st = c.prepare(
        "SELECT unit_id, line FROM gap_lines WHERE scan_id = ?1 AND (unit_id, line) > (?2, ?3) ORDER BY unit_id, line LIMIT ?4",
    )?;
    let rows = st.query_map(params![scan, unit, line, limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The units of a scan done with errors.
pub fn errored_units(c: &Connection, scan: i64) -> Result<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND state = 'done' AND error IS NOT NULL", [scan], |r| r.get(0))?)
}

/// Once every join of a scan is in, queue the classification of what they
/// found unreferenced, in units that keep each bucket's objects together.
fn plan_classification(c: &Connection, scan: i64) -> Result<Option<String>> {
    let count = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [scan], |r| r.get(0))?) };
    if count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind = 'join'")? == 0
        || count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind = 'join' AND state IN ('pending', 'leased', 'blocked')")? > 0
        || count("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind = 'classify'")? > 0
    {
        return Ok(None);
    }
    let candidates: Vec<String> = {
        let mut st = c.prepare("SELECT oid FROM orphan_candidates WHERE scan_id = ?1")?;
        st.query_map([scan], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    if candidates.is_empty() {
        return Ok(None);
    }
    let n = candidates.len();
    let units = crate::detect::classification_units(candidates, 20_000);
    let total = units.len();
    for (i, oids) in units.into_iter().enumerate() {
        let spec = serde_json::to_string(&crate::detect::Classify { oids })?;
        c.execute(
            "INSERT INTO units (scan_id, bucket, objects, state, kind, spec) VALUES (?1, ?2, 0, 'pending', 'classify', ?3)",
            params![scan, format!("orphans, classification {}/{total}", i + 1), spec],
        )?;
    }
    Ok(Some(format!("scan {scan}: {n} objects nothing references, to classify in {total} units")))
}

/// Whether every unit of the scan is done or failed.
pub fn scan_complete(c: &Connection, scan: i64) -> Result<bool> {
    let open: i64 =
        c.query_row("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND state IN ('pending', 'leased', 'blocked')", [scan], |r| r.get(0))?;
    Ok(open == 0)
}

/// Move a running scan on, and close it once its last unit is in: let its
/// joins go once the rest is in, queue its classification once they are
/// ( events say so ), and once every unit is done or failed, resolve its
/// references and mark gone the findings of its buckets that it checked
/// again and did not find: those of the checks it ran, with keys under its
/// prefix and times it did not skip as too young, in buckets whose every
/// unit is done without errors.  All in one transaction, as reports and
/// housekeeping move scans on at once: the last join's candidates cannot
/// come in between judging the scan complete and closing it.  The unheld
/// references and the findings gone, once closed; none for a scan still
/// open, or that no longer runs ( cancelled, or closed already ), which is
/// left as it is.
pub fn finish_scan(c: &mut Connection, scan: i64, now: i64) -> Result<Option<(usize, usize)>> {
    let tx = c.transaction()?;
    let Some((options, no_gc, created, plan, ctx)) = tx
        .query_row("SELECT options, no_gc, created, plan, context FROM scans WHERE id = ?1 AND state = 'running'", [scan], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, String>(4)?))
        })
        .optional()?
    else {
        return Ok(None);
    };
    for msg in [unblock_joins(&tx, scan)?, plan_classification(&tx, scan)?].into_iter().flatten() {
        event(&tx, now, "scan", &msg)?;
    }
    if !scan_complete(&tx, scan)? {
        tx.commit()?;
        return Ok(None);
    }
    let ctx: crate::finding::Context = serde_json::from_str(&ctx)?;
    // the parts of attempts that never reported
    drop_parts(&tx, "scan_id = ?1", [scan], Some(now))?;
    let mut ledger = RefLedger::default();
    {
        let mut st = tx.prepare("SELECT oid, bucket, needed, carried FROM refs WHERE scan_id = ?1")?;
        let rows = st.query_map([scan], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?;
        for row in rows {
            let (oid, bucket, needed, carried) = row?;
            ledger.needed.insert(oid.clone(), (bucket, serde_json::from_str(&needed)?));
            ledger.carried.insert(oid, serde_json::from_str(&carried)?);
        }
    }
    let leaks = ledger.resolve(&ctx);
    for f in &leaks {
        upsert_finding(&tx, Some(scan), f, now)?;
    }
    let options: Options = serde_json::from_str(&options)?;
    let plan: Option<crate::detect::Plan> = plan.map(|p| serde_json::from_str(&p)).transpose()?;
    let young = young_after(created, plan.as_ref(), options.grace);
    let checks = rechecked(&options, !no_gc).iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(", ");
    // what the scan checked again and did not find: of the checks it ran,
    // under its prefix, not too young; and no unheld reference to a tail it
    // finds unheld again under another bucket ( a tail's references are
    // filed under the first bucket to report a head that needs one )
    let unheld: Vec<&String> = leaks.iter().flat_map(|f| &f.oids).collect();
    let unseen = format!(
        "check_name IN ({checks}) AND COALESCE(last_scan, 0) < ?1 AND {OLD_ENOUGH}
         AND (?2 IS NULL OR substr(key, 1, length(?2)) = ?2)
         AND (check_name != 'unheld_reference' OR NOT EXISTS (SELECT 1 FROM json_each(record, '$.oids') o WHERE o.value IN (SELECT value FROM json_each(?4))))"
    );
    let unheld = serde_json::to_string(&unheld)?;
    // the buckets whose every unit is done without errors ( `op` "= 0" ), or not ( "> 0" )
    let buckets = |op: &str| {
        format!(
            "bucket IN (SELECT {UNIT_BUCKET} AS b FROM units WHERE scan_id = ?1 AND kind IN ('bucket', 'shard')
                        GROUP BY b HAVING SUM(state != 'done' OR error IS NOT NULL) {op})"
        )
    };
    // a unit's errors ( a listing cut short, a stat that failed ) leave some of
    // its bucket unchecked: its findings are kept, and the event says so, as a
    // bucket whose units always fail would otherwise keep them unnoticed
    let kept: Vec<(String, i64)> = {
        let mut st = tx.prepare(&format!(
            "SELECT bucket, COUNT(*) FROM findings WHERE status IN ('open', 'confirmed') AND {unseen} AND {} GROUP BY bucket ORDER BY bucket",
            buckets("> 0")
        ))?;
        let rows = st.query_map(params![scan, options.match_prefix, young, unheld], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    if !kept.is_empty() {
        event(&tx, now, "scan", &kept_message(scan, &kept))?;
    }
    // what an earlier scan marked gone, this one checked again: evidence
    // from before it ( a late report ) reopens it no more
    tx.execute(
        &format!("UPDATE findings SET gone_scan = ?1 WHERE status = 'gone' AND gone_scan IS NOT NULL AND {unseen} AND {}", buckets("= 0")),
        params![scan, options.match_prefix, young, unheld],
    )?;
    let gone = tx.execute(
        &format!(
            "UPDATE findings SET gone_from = status, gone_scan = ?1, status = 'gone' WHERE status IN ('open', 'confirmed') AND {unseen} AND {}",
            buckets("= 0")
        ),
        params![scan, options.match_prefix, young, unheld],
    )?;
    // a complete orphan detection that no longer finds an orphan, whether a
    // scan or an import found it
    let joins: (i64, i64) = tx.query_row(
        "SELECT SUM(kind = 'join'), SUM(state = 'done') FROM units WHERE scan_id = ?1 AND kind IN ('join', 'classify')",
        [scan],
        |r| Ok((r.get::<_, Option<i64>>(0)?.unwrap_or(0), r.get::<_, Option<i64>>(1)?.unwrap_or(0))),
    )?;
    let classify: i64 = tx.query_row("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND kind = 'classify'", [scan], |r| r.get(0))?;
    let gone = gone
        + if joins.0 > 0 && joins.0 + classify == joins.1 {
            let unseen = format!("check_name IN {ORPHAN_CHECKS} AND COALESCE(last_scan, 0) < ?1 AND {OLD_ENOUGH}");
            tx.execute(
                &format!("UPDATE findings SET gone_scan = ?1 WHERE status = 'gone' AND gone_scan IS NOT NULL AND {unseen}"),
                params![scan, None::<String>, young],
            )?;
            tx.execute(
                &format!("UPDATE findings SET gone_from = status, gone_scan = ?1, status = 'gone' WHERE status IN ('open', 'confirmed') AND {unseen}"),
                params![scan, None::<String>, young],
            )?
        } else {
            0
        };
    tx.execute("DELETE FROM refs WHERE scan_id = ?1", [scan])?;
    tx.execute("DELETE FROM orphan_candidates WHERE scan_id = ?1", [scan])?;
    tx.execute("UPDATE scans SET state = 'done', finished = ?1 WHERE id = ?2", params![now, scan])?;
    tx.commit()?;
    Ok(Some((leaks.len(), gone)))
}

/// The event of the findings finish_scan kept, though the scan did not find
/// them again, as their buckets' units failed or had errors: by bucket, the
/// first ten named.
fn kept_message(scan: i64, kept: &[(String, i64)]) -> String {
    let findings: i64 = kept.iter().map(|(_, n)| n).sum();
    let mut named: Vec<String> = kept.iter().take(10).map(|(b, n)| format!("{b} ( {n} )")).collect();
    if kept.len() > 10 {
        named.push(format!("and {} more", kept.len() - 10));
    }
    format!(
        "scan {scan} kept {findings} finding(s) it did not find again in {} bucket(s) whose units failed or had errors, so were not checked in full: {}",
        kept.len(),
        named.join(", ")
    )
}

/// A finding whose time is after this was maybe skipped as younger than the
/// grace period: the checks compare against their own time, which is no
/// earlier than the scan's start, nor its orphan detection's plan.
fn young_after(created: i64, plan: Option<&crate::detect::Plan>, grace: i64) -> i64 {
    plan.map_or(created, |p| p.created.min(created)) - grace
}

/// A finding a scan did not skip for its age, `young_after` being ?3; one
/// without a time is not skipped.
const OLD_ENOUGH: &str = "COALESCE(CAST(strftime('%s', json_extract(record, '$.time')) AS INTEGER) <= ?3, 1)";

/// Cancel a running scan and its open units.  Whether it was running.  What
/// only finishing it would use goes: its references, orphan candidates and
/// the parts of reports ( whose findings are kept ).
pub fn cancel_scan(c: &Connection, scan: i64, now: i64) -> Result<bool> {
    let tx = c.unchecked_transaction()?;
    let running = tx.execute("UPDATE scans SET state = 'cancelled', finished = ?1 WHERE id = ?2 AND state = 'running'", params![now, scan])? == 1;
    tx.execute("UPDATE units SET state = 'cancelled' WHERE scan_id = ?1 AND state IN ('pending', 'leased', 'blocked')", [scan])?;
    if running {
        drop_parts(&tx, "scan_id = ?1", [scan], Some(now))?;
        tx.execute("DELETE FROM refs WHERE scan_id = ?1", [scan])?;
        tx.execute("DELETE FROM orphan_candidates WHERE scan_id = ?1", [scan])?;
    }
    tx.commit()?;
    Ok(running)
}

/// A scan's state: running, done or cancelled.
pub fn scan_state(c: &Connection, scan: i64) -> Result<Option<String>> {
    Ok(c.query_row("SELECT state FROM scans WHERE id = ?1", [scan], |r| r.get(0)).optional()?)
}

pub fn findings(c: &Connection, filter: &Filter) -> Result<(Vec<FindingRow>, i64)> {
    let (clause, args) = filter.clause();
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM findings {clause}"), params_from_iter(args.iter()), |r| r.get(0))?;
    let per_page = filter.per_page.unwrap_or(50).clamp(1, 1000);
    let offset = filter.page.unwrap_or(0) * per_page;
    let sql = format!(
        "SELECT id, status, first_seen, last_seen, first_scan, last_scan, note, record FROM findings {clause}
         ORDER BY CASE class WHEN 'data_loss' THEN 0 WHEN 'pending_loss' THEN 1 WHEN 'at_risk' THEN 2
                             WHEN 'inconsistency' THEN 3 WHEN 'leak' THEN 4 ELSE 5 END, last_seen DESC, id DESC
         LIMIT {per_page} OFFSET {offset}"
    );
    let mut st = c.prepare(&sql)?;
    let rows = st.query_map(params_from_iter(args.iter()), finding_row)?;
    Ok((rows.collect::<rusqlite::Result<_>>()?, total))
}

fn finding_row(r: &rusqlite::Row) -> rusqlite::Result<FindingRow> {
    let record: String = r.get(7)?;
    Ok(FindingRow {
        id: r.get(0)?,
        status: r.get(1)?,
        first_seen: r.get(2)?,
        last_seen: r.get(3)?,
        first_scan: r.get(4)?,
        last_scan: r.get(5)?,
        note: r.get(6)?,
        finding: serde_json::from_str(&record)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e)))?,
    })
}

pub fn finding(c: &Connection, id: i64) -> Result<Option<FindingRow>> {
    Ok(c.query_row(
        "SELECT id, status, first_seen, last_seen, first_scan, last_scan, note, record FROM findings WHERE id = ?1",
        [id],
        finding_row,
    )
    .optional()?)
}

pub fn set_status(c: &Connection, id: i64, status: &str, note: Option<&str>) -> Result<bool> {
    if !STATUSES.contains(&status) {
        bail!("status is one of {STATUSES:?}");
    }
    // a person's status is the one to keep, not what a scan retired
    Ok(c.execute("UPDATE findings SET status = ?1, gone_from = NULL, gone_scan = NULL, note = COALESCE(?2, note) WHERE id = ?3", params![status, note, id])? == 1)
}

/// Counts of the findings the filter matches, per class, cause and status,
/// and the buckets with the most.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Facets {
    pub tally: Tally,
    pub statuses: Vec<(String, i64)>,
    pub buckets: Vec<(String, i64)>,
    pub checks: Vec<(String, i64)>,
}

pub fn facets(c: &Connection, filter: &Filter) -> Result<Facets> {
    let (clause, args) = filter.clause();
    let group = |col: &str, limit: usize| -> Result<Vec<(String, i64)>> {
        let sql = format!("SELECT COALESCE({col}, ''), COUNT(*) FROM findings {clause} GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}");
        let mut st = c.prepare(&sql)?;
        let rows = st.query_map(params_from_iter(args.iter()), |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    };
    let mut f = Facets::default();
    f.tally.classes = group("class", 20)?.into_iter().map(|(k, v)| (k, v as u64)).collect();
    f.tally.causes = group("top_cause", 50)?.into_iter().filter(|(k, _)| !k.is_empty()).map(|(k, v)| (k, v as u64)).collect();
    f.statuses = group("status", 10)?;
    f.buckets = group("bucket", 20)?;
    f.checks = group("check_name", 30)?;
    Ok(f)
}

pub fn heartbeat(c: &Connection, hb: &Heartbeat, now: i64) -> Result<Option<usize>> {
    c.execute(
        "INSERT INTO clients (id, host, version, first_seen, last_seen, status) VALUES (?1, ?2, ?3, ?4, ?4, ?5)
         ON CONFLICT (id) DO UPDATE SET host = excluded.host, version = excluded.version, last_seen = excluded.last_seen,
                                        status = excluded.status",
        params![hb.client, hb.host, hb.version, now, serde_json::to_string(hb)?],
    )?;
    Ok(c.query_row("SELECT inflight_override FROM clients WHERE id = ?1", [&hb.client], |r| r.get::<_, Option<i64>>(0))?
        .map(|v| v as usize))
}

pub fn clients(c: &Connection) -> Result<Vec<ClientRow>> {
    let mut st = c.prepare("SELECT id, host, version, first_seen, last_seen, status, inflight_override FROM clients ORDER BY last_seen DESC")?;
    let rows = st.query_map([], |r| {
        let status: String = r.get(5)?;
        Ok(ClientRow {
            id: r.get(0)?,
            host: r.get(1)?,
            version: r.get(2)?,
            first_seen: r.get(3)?,
            last_seen: r.get(4)?,
            status: serde_json::from_str(&status).unwrap_or_default(),
            inflight_override: r.get::<_, Option<i64>>(6)?.map(|v| v as usize),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn active_clients(c: &Connection, since: i64) -> Result<usize> {
    Ok(c.query_row("SELECT COUNT(*) FROM clients WHERE last_seen >= ?1", [since], |r| r.get::<_, i64>(0))? as usize)
}

pub fn set_override(c: &Connection, client: &str, inflight: Option<usize>) -> Result<()> {
    c.execute("UPDATE clients SET inflight_override = ?1 WHERE id = ?2", params![inflight.map(|v| v as i64), client])?;
    Ok(())
}

pub fn forget_clients(c: &Connection, before: i64) -> Result<usize> {
    Ok(c.execute("DELETE FROM clients WHERE last_seen < ?1", [before])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Catalog, Class, Context};
    use crate::scan::BucketReport;

    fn db() -> Db {
        let path = std::env::temp_dir().join(format!("rgwi-{}-{}.db", std::process::id(), rand::random::<u32>()));
        Db::open(&format!("file:{}", path.display()), "").unwrap()
    }

    #[tokio::test]
    async fn lifecycle() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db
            .call(move |c| {
                insert_scan(c, 100, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("small".into(), 1, None), NewUnit::bucket("big".into(), 10, None), NewUnit::bucket("mid".into(), 5, None)])
            })
            .await
            .unwrap();
        // largest first, and no unit twice
        let a = db.call(|c| lease(c, "a", 2, 100, 60)).await.unwrap();
        assert_eq!(a.iter().map(|u| u.bucket.as_str()).collect::<Vec<_>>(), ["big", "mid"]);
        let b = db.call(|c| lease(c, "b", 5, 100, 60)).await.unwrap();
        assert_eq!(b.len(), 1);
        // a renews one lease; the other expires and goes back to pending
        let (keep, lapse) = (a[0].id, a[1].id);
        db.call(move |c| renew(c, "a", &[keep], 1000)).await.unwrap();
        let reaped = db.call(|c| reap(c, 500)).await.unwrap();
        assert_eq!(reaped.len(), 2, "a's lapsed lease and b's");
        let again = db.call(|c| lease(c, "c", 5, 600, 60)).await.unwrap();
        assert!(again.iter().any(|u| u.id == lapse));

        let mut report = BucketReport::default();
        report.findings.push(Finding::new(Class::DataLoss, "missing_data", "big").key("k"));
        db.call(move |c| complete(c, scan, keep, "a", &report, 700)).await.unwrap();
        for u in again {
            db.call(move |c| complete(c, scan, u.id, "c", &BucketReport::default(), 700)).await.unwrap();
        }
        assert!(db.call(move |c| scan_complete(c, scan)).await.unwrap());
        db.call(move |c| finish_scan(c, scan, 800)).await.unwrap();
        let (rows, total) = db.call(|c| findings(c, &Filter { class: Some("data_loss".into()), ..Default::default() })).await.unwrap();
        assert_eq!((total, rows[0].status.as_str()), (1, "open"));

        // a second scan of the bucket that no longer finds it marks it gone
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan2 = db.call(move |c| insert_scan(c, 900, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        let u = db.call(|c| lease(c, "a", 1, 900, 60)).await.unwrap();
        let uid = u[0].id;
        db.call(move |c| complete(c, scan2, uid, "a", &BucketReport::default(), 950)).await.unwrap();
        db.call(move |c| finish_scan(c, scan2, 960)).await.unwrap();
        let (rows, _) = db.call(|c| findings(c, &Filter::default())).await.unwrap();
        assert_eq!(rows[0].status, "gone");
        let f = db.call(|c| facets(c, &Filter::default())).await.unwrap();
        assert_eq!(f.tally.classes.get("data_loss"), Some(&1));
    }

    /// The findings a second scan of bucket big marks gone that a full first
    /// scan found, when the second finds nothing, with these options.
    async fn gone_after(opts: Options, gc: bool, errors: Vec<String>) -> std::collections::BTreeSet<String> {
        let db = db();
        let scan = |at: i64, opts: Options, gc: bool, r: BucketReport| {
            let db = db.clone();
            async move {
                let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
                let c2 = ctx.clone();
                let id = db
                    .call(move |c| {
                        let id = insert_scan(c, at, &opts, &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])?;
                        if !gc {
                            gc_missed(c, id)?;
                        }
                        Ok(id)
                    })
                    .await
                    .unwrap();
                let uid = db.call(move |c| lease(c, "a", 1, at, 60)).await.unwrap()[0].id;
                db.call(move |c| complete(c, id, uid, "a", &r, at + 1)).await.unwrap();
                db.call(move |c| finish_scan(c, id, at + 2)).await.unwrap();
            }
        };
        let mut first = BucketReport::default();
        for (check, key) in [
            ("missing_data", "data/x"),
            ("listed_without_head", "logs/h"),
            ("olh_missing", "logs/o"),
            ("queued_for_gc", "logs/g"),
            ("completed_upload_open", "logs/u"),
            ("part_entries_missing", "logs/p"),
            ("stale_entry", "logs/s"),
        ] {
            first.findings.push(Finding::new(Class::Inconsistency, check, "big").key(key));
        }
        scan(1, Options { check_index: true, ..Default::default() }, true, first).await;
        scan(10, opts, gc, BucketReport { errors, ..Default::default() }).await;
        let (rows, _) = db.call(|c| findings(c, &Filter { status: Some("gone".into()), ..Default::default() })).await.unwrap();
        rows.into_iter().map(|r| r.finding.check).collect()
    }

    #[tokio::test]
    async fn only_what_a_scan_checked_again_goes() {
        let all = Options { check_index: true, ..Default::default() };
        let every: std::collections::BTreeSet<String> = BUCKET_CHECKS.iter().map(|c| c.to_string()).collect();
        let but = |skip: &[&str]| every.iter().filter(|c| !skip.contains(&c.as_str())).cloned().collect::<std::collections::BTreeSet<_>>();
        // a full, clean rescan
        assert_eq!(gone_after(all.clone(), true, vec![]).await, every);
        // keys outside the prefix were not listed
        assert_eq!(gone_after(Options { match_prefix: Some("logs/".into()), ..all.clone() }, true, vec![]).await, but(&["missing_data"]));
        // checks the scan did not run
        assert_eq!(gone_after(Options::default(), true, vec![]).await, but(&["stale_entry"]));
        let no_uploads = Options { uploads: false, ..all.clone() };
        assert_eq!(gone_after(no_uploads, true, vec![]).await, but(&["completed_upload_open", "part_entries_missing"]));
        assert_eq!(gone_after(all.clone(), false, vec![]).await, but(&["queued_for_gc"]));
        // a listing cut short, or a stat that failed
        assert!(gone_after(all, true, vec!["stat of big_data/x: Input/output error".into()]).await.is_empty());
    }

    #[tokio::test]
    async fn imported_gaps_give_way_to_scans() {
        // rgw-gap-list's lines become the findings a scan replaces, or marks gone
        let db = db();
        let tail = |n: u32| format!("m.1__shadow_.x_{n}");
        let text = format!("s3://big/k MISSING {}\ns3://big/j MISSING {}\n", tail(1), tail(2));
        let gaps = crate::gaplist::findings(&crate::gaplist::read(&text).unwrap().gaps);
        let g2 = gaps.clone();
        let added = db.call(move |c| g2.iter().map(|f| insert_finding(c, f, 10).map(usize::from)).sum::<Result<usize>>()).await.unwrap();
        assert_eq!(added, 2);
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 100, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 1, None)])).await.unwrap();
        let uid = db.call(|c| lease(c, "a", 1, 100, 60)).await.unwrap()[0].id;
        let mut report = BucketReport::default();
        let found = Finding::new(Class::DataLoss, "missing_data", "big").key("k").oids(&[tail(1)]);
        report.findings.push(ctx.rank(found, vec![crate::finding::cause("ix-fail", crate::finding::Confidence::Medium, None)], None));
        db.call(move |c| complete(c, scan, uid, "a", &report, 200)).await.unwrap();
        db.call(move |c| finish_scan(c, scan, 300)).await.unwrap();
        // importing the lines again changes neither
        let added = db.call(move |c| gaps.iter().map(|f| insert_finding(c, f, 400).map(usize::from)).sum::<Result<usize>>()).await.unwrap();
        assert_eq!(added, 0);
        let (rows, _) = db.call(|c| findings(c, &Filter::default())).await.unwrap();
        let row = |k: &str| rows.iter().find(|r| r.finding.key.as_deref() == Some(k)).unwrap();
        assert_eq!((row("k").status.as_str(), row("k").finding.causes.len()), ("open", 1));
        assert_eq!(row("k").finding.evidence, serde_json::Value::Null, "the scan's record");
        assert_eq!(row("j").status, "gone");
    }

    #[tokio::test]
    async fn shard_units_mark_gone_together() {
        // a finding of a sharded bucket is gone only once every shard's unit is done
        let db = db();
        let st: crate::admin::BucketStats =
            serde_json::from_value(serde_json::json!({ "bucket": "big", "id": "i", "marker": "m", "num_shards": 3 })).unwrap();
        let shards = |st: &crate::admin::BucketStats| (0..3).map(|s| NewUnit::shard(st, s, Some(serde_json::to_string(st).unwrap())).unwrap()).collect::<Vec<_>>();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let (c2, units) = (ctx.clone(), shards(&st));
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &c2, 7200, 0, "", None, &units)).await.unwrap();
        let leased = db.call(|c| lease(c, "a", 5, 1, 60)).await.unwrap();
        assert_eq!(leased.iter().map(|u| u.bucket.as_str()).collect::<std::collections::BTreeSet<_>>(), ["big#0", "big#1", "big#2"].into());
        assert_eq!(db.call(move |c| scan_buckets(c, scan)).await.unwrap().len(), 1, "one bucket, not one per shard");
        for (i, u) in leased.iter().enumerate() {
            let (id, mut r) = (u.id, BucketReport::default());
            if i == 0 {
                r.findings.push(Finding::new(Class::DataLoss, "missing_data", "big").key("k"));
            }
            db.call(move |c| complete(c, scan, id, "a", &r, 2)).await.unwrap();
        }
        db.call(move |c| finish_scan(c, scan, 3)).await.unwrap();

        // the next scan does not find it, but one shard fails: not gone
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let (c2, units) = (ctx.clone(), shards(&st));
        let scan2 = db.call(move |c| insert_scan(c, 10, &Options::default(), &c2, 7200, 0, "", None, &units)).await.unwrap();
        let leased = db.call(|c| lease(c, "a", 5, 10, 60)).await.unwrap();
        for (i, u) in leased.iter().enumerate() {
            let id = u.id;
            if i == 0 {
                db.call(move |c| c.execute("UPDATE units SET state = 'failed' WHERE id = ?1", [id]).map_err(Into::into)).await.unwrap();
            } else {
                db.call(move |c| complete(c, scan2, id, "a", &BucketReport::default(), 11)).await.unwrap();
            }
        }
        let (_, gone) = db.call(move |c| finish_scan(c, scan2, 12)).await.unwrap().unwrap();
        assert_eq!(gone, 0);
        // not silently: the event says which bucket kept what
        let said = db.call(|c| events(c, 10)).await.unwrap();
        let kept = format!("scan {scan2} kept 1 finding(s) it did not find again in 1 bucket(s) whose units failed or had errors");
        assert!(said.iter().any(|e| e.message.starts_with(&kept) && e.message.ends_with(": big ( 1 )")), "{:?}", said.iter().map(|e| &e.message).collect::<Vec<_>>());

        // or every shard is done, but one with errors: not gone
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let (c2, units) = (ctx.clone(), shards(&st));
        let scan2 = db.call(move |c| insert_scan(c, 15, &Options::default(), &c2, 7200, 0, "", None, &units)).await.unwrap();
        for (i, u) in db.call(|c| lease(c, "a", 5, 15, 60)).await.unwrap().into_iter().enumerate() {
            let r = BucketReport { errors: if i == 0 { vec!["listing big: timed out".into()] } else { vec![] }, ..Default::default() };
            db.call(move |c| complete(c, scan2, u.id, "a", &r, 16)).await.unwrap();
        }
        let (_, gone) = db.call(move |c| finish_scan(c, scan2, 17)).await.unwrap().unwrap();
        assert_eq!(gone, 0);

        // one that covers every shard does
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let (c2, units) = (ctx.clone(), shards(&st));
        let scan3 = db.call(move |c| insert_scan(c, 20, &Options::default(), &c2, 7200, 0, "", None, &units)).await.unwrap();
        for u in db.call(|c| lease(c, "a", 5, 20, 60)).await.unwrap() {
            db.call(move |c| complete(c, scan3, u.id, "a", &BucketReport::default(), 21)).await.unwrap();
        }
        let (_, gone) = db.call(move |c| finish_scan(c, scan3, 22)).await.unwrap().unwrap();
        assert_eq!(gone, 1);
        let said = db.call(|c| events(c, 10)).await.unwrap();
        assert!(!said.iter().any(|e| e.message.starts_with(&format!("scan {scan3} kept"))), "nothing kept");
    }

    #[test]
    fn kept_findings_are_named() {
        let kept: Vec<(String, i64)> = (0..12).map(|i| (format!("b{i:02}"), i + 1)).collect();
        let m = kept_message(4, &kept);
        assert!(m.starts_with("scan 4 kept 78 finding(s) it did not find again in 12 bucket(s)"), "{m}");
        assert!(m.ends_with(": b00 ( 1 ), b01 ( 2 ), b02 ( 3 ), b03 ( 4 ), b04 ( 5 ), b05 ( 6 ), b06 ( 7 ), b07 ( 8 ), b08 ( 9 ), b09 ( 10 ), and 2 more"), "{m}");
    }

    #[tokio::test]
    async fn joins_wait_for_the_rest() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let join = |p: u32| NewUnit {
            label: format!("partition {p}"),
            kind: "join",
            objects: 0,
            stats: None,
            spec: Some(serde_json::to_string(&crate::detect::Join { partition: p, writers: vec![] }).unwrap()),
            blocked: true,
        };
        let units = vec![NewUnit::bucket("b".into(), 1, None), join(0), join(1)];
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &ctx, 7200, 0, "", None, &units)).await.unwrap();
        let first = db.call(|c| lease(c, "a:1", 5, 1, 60)).await.unwrap();
        assert_eq!(first.len(), 1, "the joins wait");
        assert!(db.call(move |c| unblock_joins(c, scan)).await.unwrap().is_none());
        let uid = first[0].id;
        db.call(move |c| complete(c, scan, uid, "a:1", &BucketReport::default(), 2)).await.unwrap();
        assert!(db.call(move |c| unblock_joins(c, scan)).await.unwrap().is_some());
        let joins = db.call(|c| lease(c, "b:2", 5, 3, 60)).await.unwrap();
        assert_eq!(joins.len(), 2);
        let j: crate::detect::Join = serde_json::from_value(joins[0].spec.clone().unwrap()).unwrap();
        assert_eq!(j.writers, vec!["a:1".to_string()]);
    }

    #[tokio::test]
    async fn a_container_named_like_a_shard_is_a_unit_of_its_own() {
        // Swift lets a container be called big#1, the label of big's shard 1
        let db = db();
        let st: crate::admin::BucketStats =
            serde_json::from_value(serde_json::json!({ "bucket": "big", "id": "i", "marker": "m", "num_shards": 2 })).unwrap();
        let mut units: Vec<NewUnit> = (0..2).map(|s| NewUnit::shard(&st, s, None).unwrap()).collect();
        units.push(NewUnit::bucket("big#1".into(), 1, None));
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        db.call(move |c| insert_scan(c, 1, &Options::default(), &ctx, 7200, 0, "", None, &units)).await.unwrap();
        let mut leased: Vec<(String, String)> =
            db.call(|c| lease(c, "a", 5, 1, 60)).await.unwrap().into_iter().map(|u| (u.kind, u.bucket)).collect();
        leased.sort();
        assert_eq!(leased, [("bucket".into(), "big#1".into()), ("shard".into(), "big#0".into()), ("shard".into(), "big#1".into())]);
    }

    #[test]
    fn units_unique_by_label_are_migrated() {
        // a database from before units were unique by kind and label
        let path = std::env::temp_dir().join(format!("rgwi-{}-{}.db", std::process::id(), rand::random::<u32>()));
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE units (id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, bucket TEXT NOT NULL, objects INTEGER NOT NULL DEFAULT 0,
                     stats TEXT, state TEXT NOT NULL, client TEXT, lease_expires INTEGER, attempts INTEGER NOT NULL DEFAULT 0, started INTEGER,
                     finished INTEGER, rados_objects INTEGER, gaps INTEGER, findings INTEGER, seconds REAL, error TEXT, UNIQUE (scan_id, bucket));
                 INSERT INTO units (scan_id, bucket, state, attempts) VALUES (1, 'old', 'done', 2);",
            )
            .unwrap();
        }
        let db = Db::open(&format!("file:{}", path.display()), "").unwrap();
        let c = db.conn.lock().unwrap();
        let (kind, attempts, skipped): (String, i64, Option<String>) =
            c.query_row("SELECT kind, attempts, skipped FROM units WHERE bucket = 'old'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((kind.as_str(), attempts, skipped), ("bucket", 2, None));
        c.execute("INSERT INTO units (scan_id, bucket, state, kind) VALUES (1, 'old', 'pending', 'shard')", []).unwrap();
        drop(c);
        // and opening it again leaves it be
        drop(db);
        let db = Db::open(&format!("file:{}", path.display()), "").unwrap();
        let n: i64 = db.conn.lock().unwrap().query_row("SELECT COUNT(*) FROM units", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn a_report_in_parts() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("b".into(), 2, None)])).await.unwrap();
        let uid = db.call(|c| lease(c, "a", 1, 1, 60)).await.unwrap()[0].id;
        let part = || {
            let mut r = BucketReport::default();
            r.findings.push(Finding::new(Class::DataLoss, "missing_data", "b").key("k1"));
            r.refs.needed.insert("m__shadow_.x_1".into(), ("b".into(), ["tag".to_string()].into()));
            r.refs.carried.insert("m__shadow_.x_1".into(), ["tag".to_string()].into());
            r
        };
        // only from the client that holds the unit
        let r = part();
        assert!(!db.call(move |c| report_part(c, scan, uid, "b", &r, 2)).await.unwrap());
        let r = part();
        assert!(db.call(move |c| report_part(c, scan, uid, "a", &r, 2)).await.unwrap());
        let mut last = BucketReport { rados_objects: 2, ..Default::default() };
        last.findings.push(Finding::new(Class::DataLoss, "missing_data", "b").key("k2"));
        db.call(move |c| complete_after_parts(c, scan, uid, "a", &last, 1, 3)).await.unwrap();
        let r = part();
        assert!(!db.call(move |c| report_part(c, scan, uid, "a", &r, 4)).await.unwrap(), "the unit is done");
        let u = db.call(move |c| units(c, scan, None, 10)).await.unwrap();
        assert_eq!((u[0].state.as_str(), u[0].findings, u[0].rados_objects), ("done", Some(2), Some(2)));
        let (_, total) = db.call(|c| findings(c, &Filter::default())).await.unwrap();
        assert_eq!(total, 2);
        // the part's references kept their carriers
        let (leaks, _) = db.call(move |c| finish_scan(c, scan, 5)).await.unwrap().unwrap();
        assert_eq!(leaks, 0);
    }

    /// The scan's gap list, sorted.
    async fn gap_list_of(db: &Db, scan: i64) -> Vec<String> {
        db.call(move |c| gap_lines(c, scan, None, 1000)).await.unwrap().into_iter().map(|(_, l)| l).collect()
    }

    #[tokio::test]
    async fn the_gap_list_is_kept_once_per_unit() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let new = vec![NewUnit::bucket("a".into(), 2, None), NewUnit::bucket("b".into(), 1, None)];
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &ctx, 7200, 0, "", None, &new)).await.unwrap();
        let leased = db.call(|c| lease(c, "c", 2, 1, 60)).await.unwrap();
        let (a, b) = (leased[0].id, leased[1].id);
        let line = |k: &str| format!("s3://a/{k} MISSING m_{k}");
        // a's lines: one in a part, two with the report
        let part = BucketReport { missing: vec![line("k1")], ..Default::default() };
        assert!(db.call(move |c| report_part(c, scan, a, "c", &part, 2)).await.unwrap());
        // k3's line twice, as a null version's lost tail is
        let mut last = BucketReport { gaps: 4, missing: vec![line("k2"), line("k3"), line("k3")], ..Default::default() };
        last.tally.skip("younger than the grace period");
        let again = BucketReport { gaps: 9, missing: vec![line("late")], ..Default::default() };
        db.call(move |c| complete_after_parts(c, scan, a, "c", &last, 0, 3)).await.unwrap();
        // a duplicate or late report adds nothing, and changes no count
        db.call(move |c| complete(c, scan, a, "c", &again, 4)).await.unwrap();
        // b finishes with errors
        let r = BucketReport { rados_objects: 1, errors: vec!["stat of m_x: Operation not permitted".into()], ..Default::default() };
        db.call(move |c| complete(c, scan, b, "c", &r, 4)).await.unwrap();
        assert_eq!(gap_list_of(&db, scan).await, [line("k1"), line("k2"), line("k3")]);
        let u = db.call(move |c| units(c, scan, None, 10)).await.unwrap();
        let ua = u.iter().find(|u| u.id == a).unwrap();
        assert_eq!(ua.gaps, Some(3));
        assert_eq!(ua.skipped.get("younger than the grace period"), Some(&1));
        assert!(u.iter().find(|u| u.id == b).unwrap().skipped.is_empty());
        let s = db.call(|c| scans(c, 10)).await.unwrap();
        assert_eq!((s[0].gaps, s[0].errored, s[0].done), (3, 1, 2));
        assert_eq!(db.call(move |c| errored_units(c, scan)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_retry_starts_its_gap_list_again() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &ctx, 7200, 0, "", None, &[NewUnit::bucket("a".into(), 1, None)])).await.unwrap();
        let uid = db.call(|c| lease(c, "c", 1, 1, 60)).await.unwrap()[0].id;
        let part = BucketReport { missing: vec!["s3://a/gone MISSING m_gone".into()], ..Default::default() };
        assert!(db.call(move |c| report_part(c, scan, uid, "c", &part, 2)).await.unwrap());
        db.call(move |c| fail(c, uid, "c", "delivering the report: timed out", 3)).await.unwrap();
        // the retry no longer lists the key
        let uid = db.call(|c| lease(c, "d", 1, 3, 60)).await.unwrap()[0].id;
        let r = BucketReport { gaps: 1, missing: vec!["s3://a/k MISSING m_k".into()], ..Default::default() };
        db.call(move |c| complete(c, scan, uid, "d", &r, 4)).await.unwrap();
        assert_eq!(gap_list_of(&db, scan).await, ["s3://a/k MISSING m_k"]);
    }

    #[tokio::test]
    async fn references_merge_across_buckets() {
        // a copy in another bucket carries the tag the source's tail holds
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("src".into(), 2, None), NewUnit::bucket("dst".into(), 1, None)])).await.unwrap();
        let units = db.call(|c| lease(c, "a", 2, 1, 60)).await.unwrap();
        let (src, dst) = (units[0].id, units[1].id);
        let tail = "m__shadow_.x_1".to_string();
        let mut a = BucketReport::default();
        a.refs.needed.insert(tail.clone(), ("src".into(), ["copytag".to_string()].into()));
        a.refs.carried.insert(tail.clone(), ["srctag".to_string()].into());
        let mut b = BucketReport::default();
        b.refs.needed.insert(tail.clone(), ("dst".into(), ["copytag".to_string()].into()));
        b.refs.carried.insert(tail, ["copytag".to_string()].into());
        db.call(move |c| complete(c, scan, dst, "a", &b, 2)).await.unwrap();
        db.call(move |c| complete(c, scan, src, "a", &a, 3)).await.unwrap();
        let (leaks, _) = db.call(move |c| finish_scan(c, scan, 4)).await.unwrap().unwrap();
        assert_eq!(leaks, 0);
    }

    #[tokio::test]
    async fn carriers_before_references() {
        // a prefixed scan: a copy outside the prefix only carries references,
        // and its unit can report before the one that needs them
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("src".into(), 2, None), NewUnit::bucket("dst".into(), 1, None)])).await.unwrap();
        let units = db.call(|c| lease(c, "a", 2, 1, 60)).await.unwrap();
        let (src, dst) = (units[0].id, units[1].id);
        let (held, lost) = ("m__shadow_.x_1".to_string(), "m__shadow_.y_1".to_string());
        let mut b = BucketReport { bucket: "dst".into(), ..Default::default() };
        b.refs.carried.insert(held.clone(), ["copytag".to_string()].into());
        b.refs.carried.insert(lost.clone(), ["other".to_string()].into());
        let mut a = BucketReport { bucket: "src".into(), ..Default::default() };
        for oid in [&held, &lost] {
            a.refs.needed.insert(oid.clone(), ("src".into(), ["copytag".to_string()].into()));
        }
        db.call(move |c| complete(c, scan, dst, "a", &b, 2)).await.unwrap();
        db.call(move |c| complete(c, scan, src, "a", &a, 3)).await.unwrap();
        let (leaks, _) = db.call(move |c| finish_scan(c, scan, 4)).await.unwrap().unwrap();
        assert_eq!(leaks, 1);
        let found: Vec<(String, String)> = db
            .call(|c| {
                let mut st = c.prepare("SELECT bucket, record FROM findings WHERE check_name = 'unheld_reference'")?;
                let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "src");
        assert!(found[0].1.contains(&lost));
    }

    /// A scan of bucket big at `at` with these options and one unit's report.
    async fn scan_big(db: &Db, at: i64, opts: Options, r: BucketReport) -> i64 {
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let id = db.call(move |c| insert_scan(c, at, &opts, &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        let uid = db.call(move |c| lease(c, "a", 1, at, 60)).await.unwrap()[0].id;
        db.call(move |c| complete(c, id, uid, "a", &r, at + 1)).await.unwrap();
        db.call(move |c| finish_scan(c, id, at + 2)).await.unwrap();
        id
    }

    fn found(fs: &[Finding]) -> BucketReport {
        BucketReport { findings: fs.to_vec(), ..Default::default() }
    }

    async fn status(db: &Db, key: &str) -> String {
        let key = key.to_string();
        db.call(move |c| Ok(c.query_row("SELECT status FROM findings WHERE key = ?1", [key], |r| r.get(0))?)).await.unwrap()
    }

    #[tokio::test]
    async fn triage_survives_a_finding_gone_and_back() {
        let db = db();
        let f = Finding::new(Class::DataLoss, "missing_data", "big").key("k");
        scan_big(&db, 1, Options::default(), found(&[f.clone()])).await;
        let id = db.call(|c| Ok(c.query_row("SELECT id FROM findings", [], |r| r.get::<_, i64>(0))?)).await.unwrap();
        assert!(db.call(move |c| set_status(c, id, "confirmed", None)).await.unwrap());
        scan_big(&db, 10, Options::default(), BucketReport::default()).await;
        assert_eq!(status(&db, "k").await, "gone");
        // found again: confirmed, as a person left it
        scan_big(&db, 20, Options::default(), found(&[f.clone()])).await;
        assert_eq!(status(&db, "k").await, "confirmed");
        // and again, once found open
        db.call(move |c| set_status(c, id, "open", None)).await.unwrap();
        scan_big(&db, 30, Options::default(), BucketReport::default()).await;
        scan_big(&db, 40, Options::default(), found(&[f.clone()])).await;
        assert_eq!(status(&db, "k").await, "open");
        // a person's gone is theirs: found again, it is open
        db.call(move |c| set_status(c, id, "confirmed", None)).await.unwrap();
        scan_big(&db, 50, Options::default(), BucketReport::default()).await;
        db.call(move |c| set_status(c, id, "gone", None)).await.unwrap();
        scan_big(&db, 60, Options::default(), found(&[f])).await;
        assert_eq!(status(&db, "k").await, "open");
    }

    #[test]
    fn findings_gain_gone_from() {
        let path = std::env::temp_dir().join(format!("rgwi-{}-{}.db", std::process::id(), rand::random::<u32>()));
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE findings (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, class TEXT NOT NULL, check_name TEXT NOT NULL,
                     bucket TEXT NOT NULL, key TEXT, top_cause TEXT, confidence TEXT, after_fix INTEGER NOT NULL DEFAULT 0,
                     status TEXT NOT NULL DEFAULT 'open', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, first_scan INTEGER,
                     last_scan INTEGER, record TEXT NOT NULL, note TEXT NOT NULL DEFAULT '');",
            )
            .unwrap();
        }
        let db = Db::open(&format!("file:{}", path.display()), "").unwrap();
        let c = db.conn.lock().unwrap();
        upsert_finding(&c, None, &Finding::new(Class::DataLoss, "missing_data", "b").key("k"), 1).unwrap();
        let from: Option<String> = c.query_row("SELECT gone_from FROM findings", [], |r| r.get(0)).unwrap();
        assert_eq!(from, None);
    }

    #[tokio::test]
    async fn young_findings_are_not_gone() {
        // a rescan skips what is younger than its grace period
        let db = db();
        let at = |key: &str, t: Option<i64>| Finding { time: t.map(crate::oid::iso), ..Finding::new(Class::DataLoss, "missing_data", "big").key(key) };
        scan_big(&db, 1, Options::default(), found(&[at("old", Some(100)), at("young", Some(5000)), at("timeless", None)])).await;
        scan_big(&db, 6000, Options { grace: 3600, ..Default::default() }, BucketReport::default()).await;
        assert_eq!((status(&db, "old").await, status(&db, "young").await, status(&db, "timeless").await), ("gone".into(), "open".into(), "gone".into()));
        // one later, or of a shorter grace period, checked it
        scan_big(&db, 6100, Options { grace: 60, ..Default::default() }, BucketReport::default()).await;
        assert_eq!(status(&db, "young").await, "gone");
    }

    /// A scan of bucket b with orphan detection that finds no orphan, in two
    /// joins, the second of which fails unless `every_join`.  How many
    /// findings it marks gone.
    async fn detection(db: &Db, at: i64, every_join: bool) -> usize {
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let join = |p: u32| NewUnit {
            label: format!("partition {p}"),
            kind: "join",
            objects: 0,
            stats: None,
            spec: Some(serde_json::to_string(&crate::detect::Join { partition: p, writers: vec![] }).unwrap()),
            blocked: true,
        };
        let units = vec![NewUnit::bucket("b".into(), 1, None), join(0), join(1)];
        let opts = Options { orphans: true, ..Default::default() };
        let scan = db.call(move |c| insert_scan(c, at, &opts, &c2, 7200, 0, "", None, &units)).await.unwrap();
        let b = db.call(move |c| lease(c, "a", 1, at, 60)).await.unwrap()[0].id;
        db.call(move |c| complete(c, scan, b, "a", &BucketReport::default(), at)).await.unwrap();
        db.call(move |c| unblock_joins(c, scan)).await.unwrap();
        for (i, j) in db.call(move |c| lease(c, "a", 2, at, 60)).await.unwrap().into_iter().enumerate() {
            if i == 1 && !every_join {
                db.call(move |c| c.execute("UPDATE units SET state = 'failed' WHERE id = ?1", [j.id]).map_err(Into::into)).await.unwrap();
            } else {
                db.call(move |c| complete(c, scan, j.id, "a", &BucketReport::default(), at)).await.unwrap();
            }
        }
        assert!(db.call(move |c| plan_classification(c, scan)).await.unwrap().is_none(), "no candidates");
        db.call(move |c| finish_scan(c, scan, at + 1)).await.unwrap().unwrap().1
    }

    #[tokio::test]
    async fn imported_orphans_go_with_a_complete_detection() {
        let db = db();
        let orphan = Finding::new(Class::Leak, "orphan_tail", "b").key("k").oids(&["m__shadow_.x_1".to_string()]);
        db.call(move |c| upsert_finding(c, None, &orphan, 1)).await.unwrap();
        // not while a join failed
        assert_eq!(detection(&db, 10, false).await, 0);
        assert_eq!(status(&db, "k").await, "open");
        assert_eq!(detection(&db, 20, true).await, 1);
        assert_eq!(status(&db, "k").await, "gone");
    }

    #[tokio::test]
    async fn a_cancelled_scan_stays_cancelled() {
        let db = db();
        let old = Finding::new(Class::DataLoss, "missing_data", "big").key("old");
        scan_big(&db, 1, Options::default(), found(&[old])).await;
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db
            .call(move |c| insert_scan(c, 10, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None), NewUnit::bucket("b".into(), 1, None)]))
            .await
            .unwrap();
        let leased = db.call(|c| lease(c, "a", 2, 10, 60)).await.unwrap();
        let (big, b) = (leased[0].id, leased[1].id);
        // done before the cancel, with a reference no head holds
        let mut r = BucketReport::default();
        r.refs.needed.insert("m__shadow_.x_1".into(), ("b".into(), ["tag".to_string()].into()));
        db.call(move |c| complete(c, scan, b, "a", &r, 11)).await.unwrap();
        assert!(db.call(move |c| cancel_scan(c, scan, 12)).await.unwrap());
        assert!(!db.call(move |c| cancel_scan(c, scan, 13)).await.unwrap(), "not running");
        // a client still scanning big reports late: what it found is kept, but
        // the unit and the scan stay cancelled
        let mut r = found(&[Finding::new(Class::DataLoss, "missing_data", "big").key("new")]);
        r.candidates.push("m_orphan".into());
        db.call(move |c| complete(c, scan, big, "a", &r, 14)).await.unwrap();
        assert!(db.call(move |c| scan_complete(c, scan)).await.unwrap());
        assert_eq!(db.call(move |c| finish_scan(c, scan, 15)).await.unwrap(), None);
        assert_eq!(db.call(move |c| scan_state(c, scan)).await.unwrap().as_deref(), Some("cancelled"));
        let u = db.call(move |c| units(c, scan, None, 10)).await.unwrap();
        assert_eq!(u.iter().find(|u| u.id == big).unwrap().state, "cancelled");
        assert_eq!((status(&db, "old").await, status(&db, "new").await), ("open".into(), "open".into()));
        let left: i64 = db
            .call(move |c| Ok(c.query_row("SELECT (SELECT COUNT(*) FROM refs WHERE scan_id = ?1) + (SELECT COUNT(*) FROM orphan_candidates WHERE scan_id = ?1)", [scan], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn a_failed_attempts_parts_do_not_count() {
        let db = db();
        let old = Finding::new(Class::DataLoss, "missing_data", "big").key("old");
        scan_big(&db, 1, Options::default(), found(&[old.clone()])).await;
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 10, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        let uid = db.call(|c| lease(c, "a", 1, 10, 60)).await.unwrap()[0].id;
        // the first attempt sends a part: the old finding again, and a
        // reference whose carriers it never gets to send
        let mut p = found(&[old]);
        p.refs.needed.insert("m__shadow_.x_1".into(), ("big".into(), ["tag".to_string()].into()));
        assert!(db.call(move |c| report_part(c, scan, uid, "a", &p, 11)).await.unwrap());
        db.call(move |c| fail(c, uid, "a", "delivering the report: timed out", 11)).await.unwrap();
        // the retry finds neither
        let uid = db.call(|c| lease(c, "b", 1, 12, 60)).await.unwrap()[0].id;
        db.call(move |c| complete(c, scan, uid, "b", &BucketReport::default(), 13)).await.unwrap();
        let (leaks, gone) = db.call(move |c| finish_scan(c, scan, 14)).await.unwrap().unwrap();
        assert_eq!((leaks, gone), (0, 1));
        assert_eq!(status(&db, "old").await, "gone");

        // a lapsed lease's parts count if its client reports after all
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 20, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        let uid = db.call(|c| lease(c, "a", 1, 20, 60)).await.unwrap()[0].id;
        let p = found(&[Finding::new(Class::DataLoss, "missing_data", "big").key("late")]);
        assert!(db.call(move |c| report_part(c, scan, uid, "a", &p, 21)).await.unwrap());
        db.call(|c| reap(c, 100)).await.unwrap();
        // not with fewer findings than it sent ahead
        assert!(db.call(move |c| complete_after_parts(c, scan, uid, "b", &BucketReport::default(), 1, 101)).await.is_err());
        db.call(move |c| complete_after_parts(c, scan, uid, "a", &BucketReport::default(), 1, 101)).await.unwrap();
        let u = db.call(move |c| units(c, scan, None, 10)).await.unwrap();
        assert_eq!((u[0].state.as_str(), u[0].findings), ("done", Some(1)));
        let last: Option<i64> = db.call(|c| Ok(c.query_row("SELECT last_scan FROM findings WHERE key = 'late'", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(last, Some(scan));
        db.call(move |c| finish_scan(c, scan, 102)).await.unwrap();

        // a unit that fails for good: what its parts found is kept, but as of
        // no scan, and nothing is marked gone
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 200, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        for at in 200..203 {
            let uid = db.call(move |c| lease(c, "a", 1, at, 60)).await.unwrap()[0].id;
            let p = found(&[Finding::new(Class::DataLoss, "missing_data", "big").key("seen")]);
            assert!(db.call(move |c| report_part(c, scan, uid, "a", &p, at)).await.unwrap());
            db.call(move |c| fail(c, uid, "a", "timed out", at)).await.unwrap();
        }
        assert!(db.call(move |c| scan_complete(c, scan)).await.unwrap());
        let (_, gone) = db.call(move |c| finish_scan(c, scan, 204)).await.unwrap().unwrap();
        assert_eq!(gone, 0);
        let (st, last): (String, Option<i64>) =
            db.call(|c| Ok(c.query_row("SELECT status, last_scan FROM findings WHERE key = 'seen'", [], |r| Ok((r.get(0)?, r.get(1)?)))?)).await.unwrap();
        assert_eq!((st.as_str(), last), ("open", None));
        assert_eq!(status(&db, "late").await, "open");
        let parts: i64 = db.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM report_parts", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(parts, 0);
    }

    #[tokio::test]
    async fn a_late_report_does_not_undo_a_newer_scan() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let s1 = db.call(move |c| insert_scan(c, 10, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        let u1 = db.call(|c| lease(c, "a", 1, 10, 60)).await.unwrap()[0].id;
        assert!(db.call(move |c| cancel_scan(c, s1, 11)).await.unwrap());
        // the next scan finds k while the cancelled one's client still scans big
        let c2 = ctx.clone();
        let s2 = db
            .call(move |c| insert_scan(c, 20, &Options::default(), &c2, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None), NewUnit::bucket("b".into(), 1, None)]))
            .await
            .unwrap();
        let leased = db.call(|c| lease(c, "b", 2, 20, 60)).await.unwrap();
        let (big, b) = (leased[0].id, leased[1].id);
        let k = Finding::new(Class::DataLoss, "missing_data", "big").key("k");
        let r = found(&[k.clone()]);
        db.call(move |c| complete(c, s2, big, "b", &r, 21)).await.unwrap();
        let r = found(&[k]);
        db.call(move |c| complete(c, s1, u1, "a", &r, 22)).await.unwrap();
        db.call(move |c| complete(c, s2, b, "b", &BucketReport::default(), 23)).await.unwrap();
        assert_eq!(db.call(move |c| finish_scan(c, s2, 24)).await.unwrap(), Some((0, 0)));
        assert_eq!(status(&db, "k").await, "open", "scan 2 found it");
        let last: Option<i64> = db.call(|c| Ok(c.query_row("SELECT last_scan FROM findings WHERE key = 'k'", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(last, Some(s2));
        // nor does one of no scan
        let k = Finding::new(Class::DataLoss, "missing_data", "big").key("k");
        db.call(move |c| upsert_finding(c, None, &k, 25)).await.unwrap();
        let last: Option<i64> = db.call(|c| Ok(c.query_row("SELECT last_scan FROM findings WHERE key = 'k'", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(last, Some(s2));
    }

    /// Units in several shards or buckets that follow one Swift large
    /// object's segment each report its line: the scan's gap list and gaps
    /// count it once.
    #[tokio::test]
    async fn followed_segments_keep_one_gap_line() {
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let new = vec![NewUnit::bucket("m1".into(), 1, None), NewUnit::bucket("m2".into(), 1, None)];
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &ctx, 7200, 0, "", None, &new)).await.unwrap();
        let leased = db.call(|c| lease(c, "c", 2, 1, 60)).await.unwrap();
        let seg = "s3://segs/s2 MISSING MS_s2".to_string();
        for (i, u) in leased.iter().enumerate() {
            let own = format!("s3://m{}/k MISSING M_k", i + 1);
            let r = BucketReport { gaps: 2, missing: vec![own, seg.clone()], ..Default::default() };
            let id = u.id;
            db.call(move |c| complete(c, scan, id, "c", &r, 2)).await.unwrap();
        }
        assert_eq!(gap_list_of(&db, scan).await, ["s3://m1/k MISSING M_k", "s3://segs/s2 MISSING MS_s2", "s3://m2/k MISSING M_k"]);
        let u = db.call(move |c| units(c, scan, None, 10)).await.unwrap();
        let mut gaps: Vec<Option<i64>> = u.iter().map(|u| u.gaps).collect();
        gaps.sort();
        assert_eq!(gaps, [Some(1), Some(2)]);
        assert_eq!(db.call(|c| scans(c, 10)).await.unwrap()[0].gaps, 3);
    }

    /// A scan that follows segments into a bucket it has no unit of retires
    /// none of that bucket's findings: only a scan of the bucket does.
    #[tokio::test]
    async fn following_retires_nothing() {
        let db = db();
        let run = |at: i64, buckets: &'static [&'static str], r: BucketReport| {
            let db = db.clone();
            async move {
                let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
                let c2 = ctx.clone();
                let new: Vec<NewUnit> = buckets.iter().map(|b| NewUnit::bucket(b.to_string(), 1, None)).collect();
                let n = new.len();
                let scan = db.call(move |c| insert_scan(c, at, &Options::default(), &c2, 7200, 0, "", None, &new)).await.unwrap();
                let leased = db.call(move |c| lease(c, "c", n, at, 60)).await.unwrap();
                for u in leased {
                    let r = if u.bucket == "m" { found(&r.findings) } else { BucketReport::default() };
                    db.call(move |c| complete(c, scan, u.id, "c", &r, at + 1)).await.unwrap();
                }
                db.call(move |c| finish_scan(c, scan, at + 2)).await.unwrap();
            }
        };
        let lost = Finding::new(Class::Inconsistency, "listed_without_head", "segs").key("s2");
        // m's large object named segs/s2, which a scan of m followed
        run(1, &["m"], found(&[lost])).await;
        // a later scan of m only follows it again, and finds its head back
        run(10, &["m"], BucketReport::default()).await;
        assert_eq!(status(&db, "s2").await, "open");
        // a scan of segs checks it there
        run(20, &["m", "segs"], BucketReport::default()).await;
        assert_eq!(status(&db, "s2").await, "gone");
    }

    /// A partition to join, blocked until the rest is in.
    fn join_unit(p: u32) -> NewUnit {
        NewUnit {
            label: format!("partition {p}"),
            kind: "join",
            objects: 0,
            stats: None,
            spec: Some(serde_json::to_string(&crate::detect::Join { partition: p, writers: vec![] }).unwrap()),
            blocked: true,
        }
    }

    async fn unit_states(db: &Db, scan: i64, kind: &'static str) -> Vec<String> {
        db.call(move |c| {
            let mut st = c.prepare("SELECT state FROM units WHERE scan_id = ?1 AND kind = ?2 ORDER BY id")?;
            let rows = st.query_map(params![scan, kind], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .await
        .unwrap()
    }

    /// Housekeeping and the last join's report move the scan on at once:
    /// whatever comes in between, the join's candidates are classified
    /// before the scan closes, and no classification is queued in a scan
    /// that then closes without it.
    #[tokio::test]
    async fn the_last_join_cannot_race_the_close() {
        let db = db();
        let tail = "m__shadow_.x_1".to_string();
        let orphan = Finding::new(Class::Leak, "orphan_tail", "b").key("k").oids(std::slice::from_ref(&tail));
        let o2 = orphan.clone();
        db.call(move |c| upsert_finding(c, None, &o2, 1)).await.unwrap();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let opts = Options { orphans: true, ..Default::default() };
        let units = vec![NewUnit::bucket("b".into(), 1, None), join_unit(0)];
        let scan = db.call(move |c| insert_scan(c, 10, &opts, &ctx, 7200, 0, "", None, &units)).await.unwrap();
        let b = db.call(|c| lease(c, "a", 1, 10, 60)).await.unwrap()[0].id;
        db.call(move |c| complete(c, scan, b, "a", &BucketReport::default(), 11)).await.unwrap();
        // housekeeping: the bucket is in, so the join goes
        assert_eq!(db.call(move |c| finish_scan(c, scan, 12)).await.unwrap(), None);
        let j = db.call(|c| lease(c, "a", 1, 12, 60)).await.unwrap()[0].id;
        // housekeeping again, while the join is leased: nothing to plan yet
        assert_eq!(db.call(move |c| finish_scan(c, scan, 13)).await.unwrap(), None);
        // the join's report finds the tail unreferenced; the next to move
        // the scan on, housekeeping or the report, classifies it, not closes
        let r = BucketReport { candidates: vec![tail.clone()], ..Default::default() };
        db.call(move |c| complete(c, scan, j, "a", &r, 14)).await.unwrap();
        assert_eq!(db.call(move |c| finish_scan(c, scan, 15)).await.unwrap(), None);
        assert_eq!(unit_states(&db, scan, "classify").await, ["pending"]);
        assert_eq!(status(&db, "k").await, "open");
        // the other one then finds classification queued: the scan stays open
        assert_eq!(db.call(move |c| finish_scan(c, scan, 16)).await.unwrap(), None);
        assert_eq!(db.call(move |c| scan_state(c, scan)).await.unwrap().as_deref(), Some("running"));
        let said = db.call(|c| events(c, 10)).await.unwrap();
        assert!(said.iter().any(|e| e.message == format!("scan {scan}: 1 objects nothing references, to classify in 1 units")));
        assert!(said.iter().any(|e| e.message == format!("scan {scan}: every bucket and pool slice is in; 1 partitions to join")));
        // classified, it finds the orphan again, and the scan closes
        let u = db.call(|c| lease(c, "a", 1, 17, 60)).await.unwrap()[0].id;
        db.call(move |c| complete(c, scan, u, "a", &found(&[orphan]), 18)).await.unwrap();
        assert_eq!(db.call(move |c| finish_scan(c, scan, 19)).await.unwrap(), Some((0, 0)));
        assert_eq!(status(&db, "k").await, "open");
    }

    /// A late report of a cancelled scan, or of a failed unit of a closed
    /// one, looked before a newer scan that marked its findings gone: it
    /// reopens none of them.
    #[tokio::test]
    async fn a_late_report_does_not_reopen_what_a_newer_scan_retired() {
        let db = db();
        let k = Finding::new(Class::DataLoss, "missing_data", "big").key("k");
        scan_big(&db, 1, Options::default(), found(std::slice::from_ref(&k))).await;
        let late = |at: i64, cancel: bool| {
            let db = db.clone();
            async move {
                let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
                let s = db.call(move |c| insert_scan(c, at, &Options::default(), &ctx, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
                let u = db.call(move |c| lease(c, "slow", 1, at, 60)).await.unwrap()[0].id;
                if cancel {
                    assert!(db.call(move |c| cancel_scan(c, s, at + 1)).await.unwrap());
                } else {
                    db.call(move |c| c.execute("UPDATE units SET state = 'failed' WHERE id = ?1", [u]).map_err(Into::into)).await.unwrap();
                    assert!(db.call(move |c| finish_scan(c, s, at + 1)).await.unwrap().is_some());
                }
                (s, u)
            }
        };
        let (s2, u2) = late(10, true).await;
        scan_big(&db, 20, Options::default(), BucketReport::default()).await;
        assert_eq!(status(&db, "k").await, "gone");
        let r = found(std::slice::from_ref(&k));
        db.call(move |c| complete(c, s2, u2, "slow", &r, 30)).await.unwrap();
        assert_eq!(status(&db, "k").await, "gone", "scan 2 looked before scan 3");
        // one that closed with a failed unit, then a scan that checks again
        // what an earlier one marked gone
        let (s4, u4) = late(40, false).await;
        scan_big(&db, 50, Options::default(), BucketReport::default()).await;
        let r = found(std::slice::from_ref(&k));
        db.call(move |c| complete(c, s4, u4, "slow", &r, 60)).await.unwrap();
        assert_eq!(status(&db, "k").await, "gone", "scan 4 looked before scan 5");
        // a newer scan's evidence reopens it, and its attempts' of no scan
        scan_big(&db, 70, Options::default(), found(std::slice::from_ref(&k))).await;
        assert_eq!(status(&db, "k").await, "open");
        scan_big(&db, 80, Options::default(), BucketReport::default()).await;
        db.call(move |c| upsert_finding(c, None, &k, 90)).await.unwrap();
        assert_eq!(status(&db, "k").await, "open");
    }

    /// What a scan marked gone before gone_scan was recorded: a late report
    /// of a scan no newer than the last one done reopens it no more either.
    #[tokio::test]
    async fn gone_from_before_gone_scan_stays_gone() {
        let path = std::env::temp_dir().join(format!("rgwi-{}-{}.db", std::process::id(), rand::random::<u32>()));
        let spec = format!("file:{}", path.display());
        let db = Db::open(&spec, "").unwrap();
        let k = Finding::new(Class::DataLoss, "missing_data", "big").key("k");
        scan_big(&db, 1, Options::default(), found(std::slice::from_ref(&k))).await;
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let s2 = db.call(move |c| insert_scan(c, 10, &Options::default(), &ctx, 7200, 0, "", None, &[NewUnit::bucket("big".into(), 10, None)])).await.unwrap();
        let u2 = db.call(move |c| lease(c, "slow", 1, 10, 60)).await.unwrap()[0].id;
        assert!(db.call(move |c| cancel_scan(c, s2, 11)).await.unwrap());
        scan_big(&db, 20, Options::default(), BucketReport::default()).await;
        assert_eq!(status(&db, "k").await, "gone");
        // as a database from before the two columns has it
        db.call(|c| Ok(c.execute_batch("ALTER TABLE findings DROP COLUMN gone_scan; ALTER TABLE findings DROP COLUMN gone_from;")?)).await.unwrap();
        drop(db);
        let db = Db::open(&spec, "").unwrap();
        let r = found(std::slice::from_ref(&k));
        db.call(move |c| complete(c, s2, u2, "slow", &r, 30)).await.unwrap();
        assert_eq!(status(&db, "k").await, "gone", "scan 2 looked before scan 3");
        // a newer scan's evidence reopens it
        scan_big(&db, 40, Options::default(), found(std::slice::from_ref(&k))).await;
        assert_eq!(status(&db, "k").await, "open");
        drop(db);
        std::fs::remove_file(&path).ok();
    }

    /// A scan of these buckets with these options, each with its report;
    /// the unheld references it finds.
    async fn scan_refs(db: &Db, at: i64, opts: Options, reports: Vec<(&'static str, BucketReport)>) -> usize {
        let new: Vec<NewUnit> = reports.iter().map(|(b, _)| NewUnit::bucket(b.to_string(), 1, None)).collect();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let scan = db.call(move |c| insert_scan(c, at, &opts, &ctx, 7200, 0, "", None, &new)).await.unwrap();
        let n = reports.len();
        let mut reports: std::collections::HashMap<&str, BucketReport> = reports.into_iter().collect();
        for u in db.call(move |c| lease(c, "a", n, at, 60)).await.unwrap() {
            let r = reports.remove(u.bucket.as_str()).unwrap();
            db.call(move |c| complete(c, scan, u.id, "a", &r, at + 1)).await.unwrap();
        }
        db.call(move |c| finish_scan(c, scan, at + 2)).await.unwrap().unwrap().0
    }

    async fn unheld(db: &Db) -> Vec<(String, String)> {
        db.call(|c| {
            let mut st = c.prepare("SELECT bucket, status FROM findings WHERE check_name = 'unheld_reference' ORDER BY bucket")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .await
        .unwrap()
    }

    /// A refcount check that no longer finds an unheld reference marks it
    /// gone: only one of every bucket's every key, whose units of its bucket
    /// are clean, and that does not find the tail unheld under another bucket.
    #[tokio::test]
    async fn unheld_references_go_with_a_clean_refcount_check() {
        let db = db();
        let tail = "m__shadow_.x_1".to_string();
        let needs = |bucket: &str| {
            let mut r = BucketReport { bucket: bucket.into(), ..Default::default() };
            r.refs.needed.insert(tail.clone(), (bucket.into(), ["lost".to_string()].into()));
            r
        };
        let refcount = Options { refcount: true, every_bucket: true, ..Default::default() };
        let clean = || BucketReport::default();
        assert_eq!(scan_refs(&db, 1, refcount.clone(), vec![("big", needs("big"))]).await, 1);
        let open = || vec![("big".to_string(), "open".to_string())];
        assert_eq!(unheld(&db).await, open());
        // a scan without the check, under a prefix, of named buckets ( a copy
        // in another may need the tail ), or with errors in big: not gone
        scan_refs(&db, 10, Options::default(), vec![("big", clean())]).await;
        scan_refs(&db, 20, Options { match_prefix: Some("logs/".into()), ..refcount.clone() }, vec![("big", clean())]).await;
        scan_refs(&db, 25, Options { every_bucket: false, ..refcount.clone() }, vec![("big", clean())]).await;
        let errored = BucketReport { errors: vec!["stat of m_x: Input/output error".into()], ..Default::default() };
        scan_refs(&db, 30, refcount.clone(), vec![("big", errored)]).await;
        assert_eq!(unheld(&db).await, open());
        // the tail still unheld, filed under the copy's bucket this time
        assert_eq!(scan_refs(&db, 40, refcount.clone(), vec![("big", clean()), ("copy", needs("copy"))]).await, 1);
        assert_eq!(unheld(&db).await, [("big".to_string(), "open".to_string()), ("copy".to_string(), "open".to_string())]);
        // a clean check that finds it held
        let mut held = needs("big");
        held.refs.carried.insert(tail.clone(), ["lost".to_string()].into());
        assert_eq!(scan_refs(&db, 50, refcount, vec![("big", held), ("copy", clean())]).await, 0);
        assert_eq!(unheld(&db).await, [("big".to_string(), "gone".to_string()), ("copy".to_string(), "gone".to_string())]);
    }

    /// A bucket listed with radoslist that had errors may have left its open
    /// uploads' parts out of the references: its joins are cancelled.  A
    /// natively listed one's errors leave them complete.
    #[tokio::test]
    async fn radoslist_errors_cancel_the_joins() {
        for (listing, joins) in [(crate::scan::Listing::Radoslist, "cancelled"), (crate::scan::Listing::Native, "pending")] {
            let db = db();
            let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
            let opts = Options { orphans: true, listing, ..Default::default() };
            let units = vec![NewUnit::bucket("b".into(), 1, None), join_unit(0)];
            let scan = db.call(move |c| insert_scan(c, 1, &opts, &ctx, 7200, 0, "", None, &units)).await.unwrap();
            let b = db.call(|c| lease(c, "a", 1, 1, 60)).await.unwrap()[0].id;
            let r = BucketReport { errors: vec!["index object .dir.m.0 of b not found".into()], ..Default::default() };
            db.call(move |c| complete(c, scan, b, "a", &r, 2)).await.unwrap();
            let msg = db.call(move |c| unblock_joins(c, scan)).await.unwrap().unwrap();
            assert_eq!(msg.ends_with("orphan detection skipped"), joins == "cancelled", "{msg}");
            assert_eq!(unit_states(&db, scan, "join").await, [joins]);
        }
    }
}
