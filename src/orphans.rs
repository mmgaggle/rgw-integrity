//! Classify rgw-orphan-list's output: one finding per unlisted head ( with its
//! tail ), per upload's leaked parts, and per leaked tail.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::json;

use crate::admin::BucketStats;
use crate::finding::{Class, Confidence::*, Finding, Tally, cause};
use crate::oid::{Kind, decode_refcount, head_key, parse_oid, tag_text};
use crate::scan::{Engine, XATTR_IDTAG, XATTR_REFCOUNT, now};
use crate::store::{PoolId, Pools};

#[derive(Default)]
struct Group {
    oids: Vec<String>,
    bytes: u64,
    mtime: Option<i64>,
    refs: BTreeSet<String>,
    upload: Option<String>,
    key: Option<String>,
}

struct Head {
    oid: String,
    bucket: String,
    key: String,
    idtag: String,
    mtime: i64,
    prefixes: Vec<String>,
    tails: Vec<String>,
}

impl Engine {
    /// The orphan's pool, size and mtime, unless it is gone, young or queued
    /// for GC.  `before`: the objects must also be older than this, less the
    /// grace period, as when the listings of a scan that began then left out
    /// writes in flight.
    async fn usable(&self, oid: &str, before: Option<i64>, tally: &mut Tally) -> Option<(PoolId, u64, i64)> {
        let Some(found) = self.store.find(oid, Pools::DataFirst).await else {
            tally.skip("orphan gone");
            return None;
        };
        if found.2 > now() - self.opts.grace {
            tally.skip("younger than the grace period");
            return None;
        }
        if before.is_some_and(|b| found.2 > b - self.opts.grace) {
            tally.skip("written while the scan listed");
            return None;
        }
        if self.gc.read().unwrap().map.contains_key(oid) {
            tally.skip("queued for GC");
            return None;
        }
        Some(found)
    }

    async fn add<'g>(
        &self,
        groups: &'g mut BTreeMap<(String, &'static str, String), Group>,
        gkey: (String, &'static str, String),
        oid: &str,
        found: (PoolId, u64, i64),
    ) -> &'g mut Group {
        let refs: Vec<String> = self
            .store
            .getxattr(found.0, oid, XATTR_REFCOUNT)
            .await
            .ok()
            .flatten()
            .and_then(|b| decode_refcount(&b).ok())
            .map(|rc| rc.tags().cloned().collect())
            .unwrap_or_default();
        let g = groups.entry(gkey).or_default();
        g.oids.push(oid.to_string());
        g.bytes += found.1;
        g.mtime = Some(g.mtime.map_or(found.2, |m| m.min(found.2)));
        g.refs.extend(refs);
        g
    }

    pub async fn classify_orphans(&self, oids: &[String], markers: &HashMap<String, BucketStats>, before: Option<i64>) -> (Vec<Finding>, Tally) {
        let mut tally = Tally::default();
        let mut heads: Vec<Head> = Vec::new();
        let mut groups: BTreeMap<(String, &'static str, String), Group> = BTreeMap::new();
        let mut upload_open: HashMap<String, bool> = HashMap::new();

        // heads first, so that an unlisted head's tail is reported with it
        for oid in oids {
            let o = parse_oid(oid);
            let Some(st) = markers.get(o.marker) else { continue };
            if o.kind != Kind::Head {
                continue;
            }
            let Some(found) = self.usable(oid, before, &mut tally).await else { continue };
            let idtag = self.store.getxattr(found.0, oid, XATTR_IDTAG).await.ok().flatten().map(|v| tag_text(&v));
            let Some(idtag) = idtag else {
                self.add(&mut groups, (o.marker.to_string(), "orphan_other", String::new()), oid, found).await;
                continue;
            };
            let (name, instance) = head_key(&oid[o.marker.len() + 1..]);
            let bucket = st.name();
            let prefixes = self.admin.tail_prefixes(&bucket, name, instance).await;
            let key = if instance.is_empty() { name.to_string() } else { format!("{name}[{instance}]") };
            heads.push(Head { oid: oid.clone(), bucket, key, idtag, mtime: found.2, prefixes, tails: Vec::new() });
        }

        for oid in oids {
            let o = parse_oid(oid);
            if o.kind == Kind::Head && markers.contains_key(o.marker) {
                continue;
            }
            if o.kind == Kind::Meta {
                tally.skip("open upload's meta object");
                continue;
            }
            if let Some(h) = heads.iter_mut().find(|h| h.prefixes.iter().any(|p| oid.starts_with(p.as_str()))) {
                h.tails.push(oid.clone());
                continue;
            }
            let Some(found) = self.usable(oid, before, &mut tally).await else { continue };
            let marker = o.marker.to_string();
            if !markers.contains_key(o.marker) {
                self.add(&mut groups, (marker, "orphan_of_removed_bucket", String::new()), oid, found).await;
            } else if let (true, Some(upload), Some(key)) = (o.kind.is_multipart(), o.upload, o.key) {
                let open = match upload_open.get(upload) {
                    Some(&open) => open,
                    None => {
                        let meta = format!("{marker}__multipart_{key}.{upload}.meta");
                        let open = self.store.find(&meta, Pools::ExtraFirst).await.is_some();
                        upload_open.insert(upload.to_string(), open);
                        open
                    }
                };
                if open {
                    tally.skip("part of an open upload");
                    continue;
                }
                let g = self.add(&mut groups, (marker, "orphan_parts", format!("{key}.{upload}")), oid, found).await;
                g.upload = Some(upload.to_string());
                g.key = Some(key.to_string());
            } else if o.kind == Kind::Shadow {
                let rest = &oid[o.marker.len() + "__shadow_".len()..];
                let prefix = rest.rfind('_').map_or(rest, |i| &rest[..=i]).to_string();
                self.add(&mut groups, (marker, "orphan_tail", prefix), oid, found).await;
            } else {
                self.add(&mut groups, (marker, "orphan_other", String::new()), oid, found).await;
            }
        }

        // parts of an upload whose completion came after its bucket was listed:
        // the head now names them
        let mut completed = Vec::new();
        for ((marker, check, prefix), g) in &groups {
            if *check != "orphan_parts" {
                continue;
            }
            let (Some(st), Some(key)) = (markers.get(marker), &g.key) else { continue };
            let names = format!("{marker}__multipart_{prefix}.");
            if self.admin.tail_prefixes(&st.name(), key, "").await.iter().any(|p| *p == names) {
                completed.push((marker.clone(), *check, prefix.clone()));
            }
        }
        for k in completed {
            if let Some(g) = groups.remove(&k) {
                for _ in &g.oids {
                    tally.skip("part of an upload completed since");
                }
            }
        }

        let mut findings = Vec::new();
        for h in heads {
            let mut oids = vec![h.oid];
            oids.extend(h.tails.iter().cloned());
            let f = Finding::new(Class::Inconsistency, "unlisted_head", &h.bucket)
                .key(h.key)
                .oids(&oids)
                .evidence(json!({ "head_idtag": h.idtag, "tail_objects": h.tails.len() }))
                .hint("GET by key reads this object, but no listing shows it; re-link it with radosgw-admin object reindex, or rgw-restore-bucket-index");
            let c = cause("stalled-write", High, "a new key's write stalled past the pending-op expiry, and a listing dropped its entry".to_string());
            findings.push(self.ctx.rank(f, vec![c], Some(h.mtime)));
        }
        for ((marker, check, _), g) in groups {
            let bucket = markers.get(&marker).map_or_else(|| format!("<marker {marker}>"), |st| st.name());
            let mut evidence = json!({ "objects": g.oids.len(), "bytes": g.bytes });
            let mut f = Finding::new(Class::Leak, check, &bucket).oids(&g.oids);
            let causes = if !g.refs.is_empty() {
                evidence["references"] = json!(g.refs);
                vec![
                    cause("lost-copy", High, "the objects keep a copy's reference, and nothing names them".to_string()),
                    cause("dedup", Medium, "dedup takes references like a copy".to_string()),
                ]
            } else if check == "orphan_parts" {
                evidence["upload_id"] = json!(g.upload);
                vec![
                    cause("lost-complete", High, "the parts of an upload that has no meta object, and that no head names".to_string()),
                    cause("dedup", Low, None),
                ]
            } else if check == "orphan_tail" {
                vec![
                    cause("delete-race", Medium, "a delete that raced an overwrite leaves the new object's tail".to_string()),
                    cause("cond-delete", Medium, "a conditional delete that raced an overwrite leaves the new object's tail".to_string()),
                    cause("copy-self", Medium, "a copy onto itself that raced an overwrite leaves the overwrite's tail".to_string()),
                    cause("dedup", Low, None),
                ]
            } else {
                Vec::new()
            };
            if let Some(k) = &g.key {
                f = f.key(k.clone());
            }
            if check == "orphan_of_removed_bucket" {
                f = f.hint("no bucket has this marker; the objects outlived their bucket");
            }
            findings.push(self.ctx.rank(f.evidence(evidence), causes, g.mtime));
        }
        for f in &findings {
            tally.add(f);
        }
        (findings, tally)
    }
}
