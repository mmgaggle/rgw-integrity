//! The radosgw-admin commands the checks run: listings that need RGW's own
//! decoding of manifests and index entries.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::json_stream;
use crate::oid::parse_time;

/// Separates radoslist's fields: a control character keys are unlikely to hold.
const FS: &str = "\u{1f}";

#[derive(Debug, Clone)]
pub struct Admin {
    pub program: String,
    pub conf: Option<PathBuf>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct BucketStats {
    pub bucket: String,
    #[serde(default)]
    pub tenant: String,
    pub id: String,
    pub marker: String,
    #[serde(default)]
    pub index_type: String,
    #[serde(default)]
    pub index_generation: u64,
    #[serde(default)]
    pub num_shards: u64,
    #[serde(default)]
    pub placement_rule: Value,
    #[serde(default)]
    pub usage: Value,
}

impl BucketStats {
    /// the name 'bucket list' uses
    pub fn name(&self) -> String {
        if self.tenant.is_empty() { self.bucket.clone() } else { format!("{}/{}", self.tenant, self.bucket) }
    }

    pub fn placement(&self) -> String {
        let rule = match &self.placement_rule {
            Value::String(s) => s.clone(),
            Value::Object(o) => o.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string(),
            _ => String::new(),
        };
        let name = rule.split('/').next().unwrap_or_default();
        if name.is_empty() { "default-placement".into() } else { name.into() }
    }

    pub fn num_objects(&self) -> u64 {
        self.usage.as_object().map_or(0, |u| u.values().filter_map(|c| c.get("num_objects")?.as_u64()).sum())
    }
}

/// The zone's pools.
#[derive(Debug, Clone, Default)]
pub struct ZonePools {
    /// every placement target's data pools, the default placement's STANDARD first
    pub data: Vec<String>,
    pub extra: Vec<String>,
    pub index: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcObj {
    #[serde(default)]
    pub oid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcEntry {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub objs: Vec<GcObj>,
}

/// One entry of `bi list`, with the fields the checks read.
#[derive(Debug, Clone, Default)]
pub struct IndexEntry {
    pub kind: String,
    pub name: String,
    pub instance: String,
    pub exists: bool,
    pub flags: u64,
    pub pending: bool,
    pub tag: String,
    pub etag: String,
    pub mtime: String,
}

pub const FLAG_DELETE_MARKER: u64 = 0x4;

impl IndexEntry {
    pub fn from_value(v: &Value) -> IndexEntry {
        let e = &v["entry"];
        let s = |x: &Value| x.as_str().unwrap_or_default().to_string();
        IndexEntry {
            kind: s(&v["type"]),
            name: s(&e["name"]),
            instance: s(&e["instance"]),
            exists: e["exists"].as_bool().unwrap_or(false),
            flags: e["flags"].as_u64().unwrap_or(0),
            pending: e["pending_map"].as_array().is_some_and(|p| !p.is_empty()),
            tag: s(&e["tag"]),
            etag: s(&e["meta"]["etag"]),
            mtime: s(&e["meta"]["mtime"]),
        }
    }

    pub fn is_delete_marker(&self) -> bool {
        self.flags & FLAG_DELETE_MARKER != 0
    }

    pub fn mtime(&self) -> Option<i64> {
        parse_time(&self.mtime)
    }
}

impl Admin {
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.program);
        if let Some(conf) = &self.conf {
            cmd.arg("-c").arg(conf);
        }
        if let Some(id) = &self.id {
            cmd.arg("--id").arg(id);
        }
        cmd.args(args);
        cmd
    }

    /// Run a command to completion and return its output; an error if it fails.
    pub async fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = tokio::process::Command::from(self.command(args));
        let out = cmd.output().await.with_context(|| format!("running {}", self.program))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.lines().filter(|l| !l.contains("dangerous and experimental")).collect::<Vec<_>>().join(" ");
            bail!("{} {} failed ( {} ): {}", self.program, args.join(" "), out.status, err.chars().rev().take(300).collect::<String>().chars().rev().collect::<String>());
        }
        Ok(out.stdout)
    }

    pub async fn json<T: DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        let out = self.run(args).await?;
        let text = String::from_utf8_lossy(&out);
        serde_json::from_str(&text).with_context(|| format!("parsing the output of {}", args.join(" ")))
    }

    /// Stream the elements of the JSON array a command prints.  The channel
    /// ends with an error if the command fails.
    pub fn stream<T: DeserializeOwned + Send + 'static>(&self, args: &[&str]) -> mpsc::Receiver<Result<T>> {
        let (tx, rx) = mpsc::channel(4096);
        let mut cmd = self.command(args);
        let what = args.join(" ");
        tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<()> {
                let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().context("running radosgw-admin")?;
                let stdout = child.stdout.take().expect("piped");
                json_stream::for_each(stdout, |item: T| {
                    tx.blocking_send(Ok(item)).map_err(|_| anyhow::anyhow!("the reader went away"))
                })?;
                let status = child.wait()?;
                if !status.success() {
                    bail!("radosgw-admin {what} failed ( {status} )");
                }
                Ok(())
            })();
            if let Err(e) = result {
                let _ = tx.blocking_send(Err(e));
            }
        });
        rx
    }

    /// radoslist's lines: (RADOS object, bucket, key), all of one S3 object's
    /// together.
    pub fn radoslist(&self, bucket: &str) -> mpsc::Receiver<Result<(String, String, String)>> {
        let (tx, rx) = mpsc::channel(16384);
        let fs = format!("--rgw-obj-fs={FS}");
        let b = format!("--bucket={bucket}");
        let mut cmd = self.command(&["bucket", "radoslist", &fs, &b]);
        let bucket = bucket.to_string();
        tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<()> {
                let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().context("running radosgw-admin")?;
                let reader = BufReader::with_capacity(1 << 20, child.stdout.take().expect("piped"));
                for line in reader.split(b'\n') {
                    let line = String::from_utf8_lossy(&line?).into_owned();
                    let mut fields = line.splitn(3, FS);
                    let (Some(oid), Some(b), Some(key)) = (fields.next(), fields.next(), fields.next()) else { continue };
                    if tx.blocking_send(Ok((oid.to_string(), b.to_string(), key.to_string()))).is_err() {
                        let _ = child.kill();
                        return Ok(());
                    }
                }
                let status = child.wait()?;
                if !status.success() {
                    bail!("radosgw-admin bucket radoslist --bucket={bucket} failed ( {status} )");
                }
                Ok(())
            })();
            if let Err(e) = result {
                let _ = tx.blocking_send(Err(e));
            }
        });
        rx
    }

    pub async fn zone_pools(&self) -> Result<ZonePools> {
        let zone: Value = self.json(&["zone", "get"]).await?;
        let mut pools = ZonePools::default();
        let mut placements: Vec<&Value> = zone["placement_pools"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
        placements.sort_by_key(|p| p["key"] != "default-placement");
        for p in placements {
            let val = &p["val"];
            if let (Some(key), Some(index)) = (p["key"].as_str(), val["index_pool"].as_str()) {
                pools.index.insert(key.to_string(), index.to_string());
            }
            if let Some(classes) = val["storage_classes"].as_object() {
                let mut names: Vec<&String> = classes.keys().collect();
                names.sort_by_key(|c| *c != "STANDARD");
                for sc in names {
                    if let Some(pool) = classes[sc]["data_pool"].as_str() {
                        if !pools.data.iter().any(|d| d == pool) {
                            pools.data.push(pool.to_string());
                        }
                    }
                }
            }
            if let Some(extra) = val["data_extra_pool"].as_str() {
                if !extra.is_empty() && !pools.extra.iter().any(|e| e == extra) {
                    pools.extra.push(extra.to_string());
                }
            }
        }
        Ok(pools)
    }

    pub async fn bucket_stats(&self, bucket: &str) -> Result<BucketStats> {
        self.json(&["bucket", "stats", &format!("--bucket={bucket}")]).await
    }

    /// every bucket's stats, from one call
    pub fn all_bucket_stats(&self) -> mpsc::Receiver<Result<BucketStats>> {
        self.stream(&["bucket", "stats"])
    }

    pub async fn bucket_list(&self) -> Result<Vec<String>> {
        self.json(&["bucket", "list"]).await
    }

    /// a key's index entry, or None
    pub async fn index_entry(&self, bucket: &str, name: &str, instance: &str) -> Option<IndexEntry> {
        let entries: Vec<Value> = self.json(&["bi", "list", &format!("--bucket={bucket}"), &format!("--object={name}")]).await.ok()?;
        entries
            .iter()
            .map(IndexEntry::from_value)
            .find(|e| (e.kind == "plain" || e.kind == "instance") && e.name == name && e.instance == instance)
    }

    pub fn bi_list(&self, bucket: &str) -> mpsc::Receiver<Result<Value>> {
        self.stream(&["bi", "list", &format!("--bucket={bucket}")])
    }

    pub fn gc_list(&self) -> mpsc::Receiver<Result<GcEntry>> {
        self.stream(&["gc", "list", "--include-all"])
    }

    /// whether the bucket's lifecycle has an AbortIncompleteMultipartUpload rule
    pub async fn has_mp_expiration(&self, bucket: &str) -> bool {
        let Ok(lc) = self.json::<Value>(&["lc", "get", &format!("--bucket={bucket}")]).await else { return false };
        lc["rule_map"].as_array().is_some_and(|rules| {
            rules.iter().any(|r| {
                let mp = &r["rule"]["mp_expiration"];
                [&mp["days"], &mp["date"]].iter().any(|v| match v {
                    Value::String(s) => !s.is_empty(),
                    Value::Number(n) => n.as_u64().is_some_and(|n| n > 0),
                    _ => false,
                })
            })
        })
    }

    /// the name prefixes of an object's tail objects, from its manifest
    pub async fn tail_prefixes(&self, bucket: &str, name: &str, instance: &str) -> Vec<String> {
        let mut args = vec!["object".to_string(), "stat".into(), format!("--bucket={bucket}"), format!("--object={name}")];
        if !instance.is_empty() {
            args.push(format!("--object-version={instance}"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let Ok(stat) = self.json::<Value>(&args).await else { return Vec::new() };
        let manifest = &stat["manifest"];
        let (Some(prefix), Some(marker)) = (manifest["prefix"].as_str(), manifest["tail_placement"]["bucket"]["marker"].as_str()) else {
            return Vec::new();
        };
        let multipart =
            manifest["rules"].as_array().is_some_and(|r| r.iter().any(|r| r["val"]["part_size"].as_u64().unwrap_or(0) > 0));
        if multipart {
            vec![format!("{marker}__multipart_{prefix}."), format!("{marker}__shadow_{prefix}.")]
        } else {
            vec![format!("{marker}__shadow_{prefix}")]
        }
    }
}
