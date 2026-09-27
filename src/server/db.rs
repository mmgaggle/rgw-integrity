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
CREATE TABLE IF NOT EXISTS units (
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
    UNIQUE (scan_id, bucket)
);
CREATE INDEX IF NOT EXISTS units_by_state ON units (scan_id, state);
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
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    time INTEGER NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL
);
"#;

/// The finding statuses: a scan sets open and gone; people set the rest.
pub const STATUSES: [&str; 4] = ["open", "confirmed", "false_positive", "gone"];

/// Checks whose findings come from bucket scans, so a later scan of the
/// bucket that no longer finds them marks them gone.
const BUCKET_CHECKS: &str =
    "('missing_data', 'queued_for_gc', 'completed_upload_open', 'part_entries_missing', 'listed_without_head', 'stale_entry')";

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitRow {
    pub id: i64,
    pub bucket: String,
    pub objects: i64,
    pub state: String,
    pub client: Option<String>,
    pub attempts: i64,
    pub started: Option<i64>,
    pub finished: Option<i64>,
    pub rados_objects: Option<i64>,
    pub findings: Option<i64>,
    pub seconds: Option<f64>,
    pub error: Option<String>,
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
        eq("status", &self.status);
        eq("confidence", &self.confidence);
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

/// A new scan and its units: (bucket, objects, stats json).
pub fn insert_scan(
    c: &mut Connection,
    now: i64,
    options: &Options,
    context: &crate::finding::Context,
    gc_min_wait: i64,
    gc_entries: usize,
    note: &str,
    buckets: &[(String, u64, Option<String>)],
) -> Result<i64> {
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO scans (created, state, options, context, gc_min_wait, gc_entries, note) VALUES (?1, 'running', ?2, ?3, ?4, ?5, ?6)",
        params![now, serde_json::to_string(options)?, serde_json::to_string(context)?, gc_min_wait, gc_entries as i64, note],
    )?;
    let id = tx.last_insert_rowid();
    {
        let mut st = tx.prepare("INSERT OR IGNORE INTO units (scan_id, bucket, objects, stats, state) VALUES (?1, ?2, ?3, ?4, 'pending')")?;
        for (bucket, objects, stats) in buckets {
            st.execute(params![id, bucket, *objects as i64, stats])?;
        }
    }
    tx.commit()?;
    Ok(id)
}

pub fn running_scan(c: &Connection) -> Result<Option<i64>> {
    Ok(c.query_row("SELECT id FROM scans WHERE state = 'running' ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).optional()?)
}

pub fn scan_spec(c: &Connection, id: i64) -> Result<Option<crate::proto::ScanSpec>> {
    let row: Option<(String, String, i64)> = c
        .query_row("SELECT options, context, gc_min_wait FROM scans WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    row.map(|(o, ctx, w)| {
        Ok(crate::proto::ScanSpec { id, options: serde_json::from_str(&o)?, context: serde_json::from_str(&ctx)?, gc_min_wait: w })
    })
    .transpose()
}

pub fn scans(c: &Connection, limit: usize) -> Result<Vec<ScanRow>> {
    let mut st = c.prepare(
        "SELECT s.id, s.created, s.finished, s.state, s.options, s.gc_entries, s.note,
                COUNT(u.id),
                SUM(u.state = 'pending'), SUM(u.state = 'leased'), SUM(u.state = 'done'), SUM(u.state = 'failed'),
                SUM(u.objects), SUM(CASE WHEN u.state = 'done' THEN u.objects ELSE 0 END),
                SUM(COALESCE(u.rados_objects, 0)), SUM(COALESCE(u.findings, 0))
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
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn units(c: &Connection, scan: i64, state: Option<&str>, limit: usize) -> Result<Vec<UnitRow>> {
    let mut st = c.prepare(
        "SELECT id, bucket, objects, state, client, attempts, started, finished, rados_objects, findings, seconds, error
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
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Lease up to `max` pending units of the running scan, largest first.
pub fn lease(c: &mut Connection, client: &str, max: usize, now: i64, lease_secs: i64) -> Result<Vec<Unit>> {
    let tx = c.transaction()?;
    let Some(scan) = running_scan(&tx)? else { return Ok(Vec::new()) };
    let picked: Vec<(i64, String, Option<String>)> = {
        let mut st = tx.prepare("SELECT id, bucket, stats FROM units WHERE scan_id = ?1 AND state = 'pending' ORDER BY objects DESC, id LIMIT ?2")?;
        st.query_map(params![scan, max as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?
    };
    let mut units = Vec::new();
    for (id, bucket, stats) in picked {
        tx.execute(
            "UPDATE units SET state = 'leased', client = ?1, lease_expires = ?2, started = COALESCE(started, ?3) WHERE id = ?4",
            params![client, now + lease_secs, now, id],
        )?;
        units.push(Unit { id, scan, bucket, stats: stats.and_then(|s| serde_json::from_str(&s).ok()) });
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

pub fn fail(c: &Connection, unit: i64, client: &str, error: &str) -> Result<()> {
    c.execute(
        "UPDATE units SET state = CASE WHEN attempts + 1 >= 3 THEN 'failed' ELSE 'pending' END,
                          attempts = attempts + 1, client = NULL, lease_expires = NULL, error = ?1
         WHERE id = ?2 AND client = ?3 AND state = 'leased'",
        params![error, unit, client],
    )?;
    Ok(())
}

pub fn upsert_finding(c: &Connection, scan: Option<i64>, f: &Finding, now: i64) -> Result<()> {
    let top = f.top_cause();
    c.execute(
        "INSERT INTO findings (fingerprint, class, check_name, bucket, key, top_cause, confidence, after_fix,
                               first_seen, last_seen, first_scan, last_scan, record)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?10, ?11)
         ON CONFLICT (fingerprint) DO UPDATE SET
             class = excluded.class, top_cause = excluded.top_cause, confidence = excluded.confidence,
             after_fix = excluded.after_fix, last_seen = excluded.last_seen,
             last_scan = COALESCE(excluded.last_scan, last_scan), record = excluded.record,
             status = CASE WHEN status = 'gone' THEN 'open' ELSE status END",
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

/// Record a unit's report: its findings, its references, and the unit done.
pub fn complete(c: &mut Connection, scan: i64, unit: i64, client: &str, r: &crate::scan::BucketReport, now: i64) -> Result<()> {
    let tx = c.transaction()?;
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
        tx.execute(
            "INSERT INTO refs (scan_id, oid, bucket, needed, carried) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (scan_id, oid) DO UPDATE SET needed = excluded.needed, carried = excluded.carried",
            params![scan, oid, bucket, serde_json::to_string(&n)?, serde_json::to_string(&c)?],
        )?;
    }
    // heads that name a refcounted object this report did not see referenced
    for (oid, carried) in r.refs.carried.iter().filter(|(o, _)| !r.refs.needed.contains_key(*o)) {
        let old: Option<String> =
            tx.query_row("SELECT carried FROM refs WHERE scan_id = ?1 AND oid = ?2", params![scan, oid], |row| row.get(0)).optional()?;
        if let Some(oc) = old {
            let mut c = carried.clone();
            c.extend(serde_json::from_str::<std::collections::BTreeSet<String>>(&oc)?);
            tx.execute("UPDATE refs SET carried = ?1 WHERE scan_id = ?2 AND oid = ?3", params![serde_json::to_string(&c)?, scan, oid])?;
        }
    }
    let errors = if r.errors.is_empty() { None } else { Some(r.errors.join("; ")) };
    tx.execute(
        "UPDATE units SET state = 'done', finished = ?1, rados_objects = ?2, gaps = ?3, findings = ?4, seconds = ?5,
                          error = ?6, client = ?7, lease_expires = NULL
         WHERE id = ?8 AND state != 'done'",
        params![now, r.rados_objects as i64, r.gaps as i64, r.findings.len() as i64, r.seconds, errors, client, unit],
    )?;
    tx.commit()?;
    Ok(())
}

/// Whether every unit of the scan is done or failed.
pub fn scan_complete(c: &Connection, scan: i64) -> Result<bool> {
    let open: i64 = c.query_row("SELECT COUNT(*) FROM units WHERE scan_id = ?1 AND state IN ('pending', 'leased')", [scan], |r| r.get(0))?;
    Ok(open == 0)
}

/// Close a scan: resolve its references, and mark gone the findings of its
/// buckets that it did not find again.
pub fn finish_scan(c: &mut Connection, scan: i64, ctx: &crate::finding::Context, now: i64) -> Result<(usize, usize)> {
    let tx = c.transaction()?;
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
    let leaks = ledger.resolve(ctx);
    for f in &leaks {
        upsert_finding(&tx, Some(scan), f, now)?;
    }
    let gone = tx.execute(
        &format!(
            "UPDATE findings SET status = 'gone'
             WHERE status IN ('open', 'confirmed') AND check_name IN {BUCKET_CHECKS} AND COALESCE(last_scan, 0) < ?1
               AND bucket IN (SELECT bucket FROM units WHERE scan_id = ?1 AND state = 'done')"
        ),
        [scan],
    )?;
    tx.execute("DELETE FROM refs WHERE scan_id = ?1", [scan])?;
    tx.execute("UPDATE scans SET state = 'done', finished = ?1 WHERE id = ?2", params![now, scan])?;
    tx.commit()?;
    Ok((leaks.len(), gone))
}

pub fn cancel_scan(c: &Connection, scan: i64, now: i64) -> Result<()> {
    c.execute("UPDATE scans SET state = 'cancelled', finished = ?1 WHERE id = ?2 AND state = 'running'", params![now, scan])?;
    c.execute("UPDATE units SET state = 'cancelled' WHERE scan_id = ?1 AND state IN ('pending', 'leased')", [scan])?;
    Ok(())
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
    Ok(c.execute("UPDATE findings SET status = ?1, note = COALESCE(?2, note) WHERE id = ?3", params![status, note, id])? == 1)
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
                insert_scan(c, 100, &Options::default(), &c2, 7200, 0, "", &[("small".into(), 1, None), ("big".into(), 10, None), ("mid".into(), 5, None)])
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
        db.call(move |c| finish_scan(c, scan, &ctx, 800)).await.unwrap();
        let (rows, total) = db.call(|c| findings(c, &Filter { class: Some("data_loss".into()), ..Default::default() })).await.unwrap();
        assert_eq!((total, rows[0].status.as_str()), (1, "open"));

        // a second scan of the bucket that no longer finds it marks it gone
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan2 = db.call(move |c| insert_scan(c, 900, &Options::default(), &c2, 7200, 0, "", &[("big".into(), 10, None)])).await.unwrap();
        let u = db.call(|c| lease(c, "a", 1, 900, 60)).await.unwrap();
        let uid = u[0].id;
        db.call(move |c| complete(c, scan2, uid, "a", &BucketReport::default(), 950)).await.unwrap();
        db.call(move |c| finish_scan(c, scan2, &ctx, 960)).await.unwrap();
        let (rows, _) = db.call(|c| findings(c, &Filter::default())).await.unwrap();
        assert_eq!(rows[0].status, "gone");
        let f = db.call(|c| facets(c, &Filter::default())).await.unwrap();
        assert_eq!(f.tally.classes.get("data_loss"), Some(&1));
    }

    #[tokio::test]
    async fn references_merge_across_buckets() {
        // a copy in another bucket carries the tag the source's tail holds
        let db = db();
        let ctx = Context { catalog: Catalog::builtin(), ..Default::default() };
        let c2 = ctx.clone();
        let scan = db.call(move |c| insert_scan(c, 1, &Options::default(), &c2, 7200, 0, "", &[("src".into(), 2, None), ("dst".into(), 1, None)])).await.unwrap();
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
        let (leaks, _) = db.call(move |c| finish_scan(c, scan, &ctx, 4)).await.unwrap();
        assert_eq!(leaks, 0);
    }
}
