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
    pub bucket: String,
    pub stats: Option<BucketStats>,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub client: String,
    pub unit: i64,
    pub report: BucketReport,
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
