//! Ceph's encodings of what the native listing reads: bucket index entries,
//! and object manifests, and the manifest's walk over an object's stripes.
//! Ports of cls_rgw_types.h, rgw_obj_types.h, rgw_bucket_types.h and
//! rgw_obj_manifest.{h,cc}, legacy versions included, since clusters
//! upgraded from old releases still hold objects they wrote.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// A decoded struct header: its version, and where it ends, if it says.
pub struct Header {
    pub v: u8,
    end: Option<usize>,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len());
        let Some(end) = end else { bail!("truncated at byte {} of {}, wanting {n}", self.pos, self.buf.len()) };
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn string(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    /// ceph::real_time: seconds and nanoseconds, as u32s
    pub fn time(&mut self) -> Result<i64> {
        let s = self.u32()?;
        self.u32()?;
        Ok(s as i64)
    }
    /// cls_rgw's decode_packed_val
    pub fn packed(&mut self) -> Result<u64> {
        let c = self.u8()?;
        if c < 0x80 {
            return Ok(c as u64);
        }
        Ok(match c & !0x80 {
            1 => self.u8()? as u64,
            2 => self.u16()? as u64,
            4 => self.u32()? as u64,
            8 => self.u64()?,
            other => bail!("bad packed value tag {other:#x}"),
        })
    }

    /// DECODE_START_LEGACY_COMPAT_LEN{,_16,_32}: an old encoding may lack
    /// the compat byte ( skipping `skip_v` bytes of a wider version
    /// instead ), or the length.
    pub fn start_legacy(&mut self, compatv: u8, lenv: u8, skip_v: usize) -> Result<Header> {
        let v = self.u8()?;
        if compatv <= v {
            self.u8()?;
        } else if skip_v > 0 {
            self.take(skip_v)?;
        }
        if lenv > v {
            return Ok(Header { v, end: None });
        }
        let len = self.u32()? as usize;
        let end = self.pos.checked_add(len).filter(|&e| e <= self.buf.len());
        match end {
            Some(end) => Ok(Header { v, end: Some(end) }),
            None => bail!("a struct of {len} bytes at byte {} of {}", self.pos, self.buf.len()),
        }
    }

    /// DECODE_START: version, compat and length, always.
    pub fn start(&mut self) -> Result<Header> {
        self.start_legacy(0, 0, 0)
    }

    /// DECODE_FINISH: skip what this version does not know.
    pub fn finish(&mut self, h: Header) -> Result<()> {
        if let Some(end) = h.end {
            if self.pos > end {
                bail!("decoded past the struct's end");
            }
            self.pos = end;
        }
        Ok(())
    }

    /// Skip a whole struct, which must have a length.
    pub fn skip_struct(&mut self, compatv: u8, lenv: u8) -> Result<()> {
        let h = self.start_legacy(compatv, lenv, 0)?;
        if h.end.is_none() {
            bail!("cannot skip a struct without a length");
        }
        self.finish(h)
    }
}

// ---- buckets and objects

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bucket {
    pub tenant: String,
    pub name: String,
    pub marker: String,
    pub bucket_id: String,
}

/// rgw_pool, of which only the name matters here
fn skip_pool(c: &mut Cursor) -> Result<()> {
    let h = c.start_legacy(3, 3, 0)?;
    c.string()?;
    if h.v >= 10 {
        c.string()?;
    } else if h.end.is_none() {
        bail!("an rgw_pool of version {} without a length", h.v);
    }
    c.finish(h)
}

impl Bucket {
    /// rgw_bucket::decode, DECODE_START_LEGACY_COMPAT_LEN(10, 3, 3)
    pub fn decode(c: &mut Cursor) -> Result<Bucket> {
        let h = c.start_legacy(3, 3, 0)?;
        let v = h.v;
        let mut b = Bucket { name: c.string()?, ..Default::default() };
        if v < 10 {
            c.string()?; // explicit data pool
        }
        if v >= 2 {
            b.marker = c.string()?;
            b.bucket_id = if v <= 3 { c.u64()?.to_string() } else { c.string()? };
        }
        if v < 10 {
            if v >= 5 {
                c.string()?; // explicit index pool
            }
            if v >= 7 {
                c.string()?; // explicit extra pool
            }
        }
        if v >= 8 {
            b.tenant = c.string()?;
        }
        if v >= 10 && c.bool()? {
            for _ in 0..3 {
                skip_pool(c)?;
            }
        }
        c.finish(h)?;
        Ok(b)
    }
}

/// rgw_obj_key: a name, its namespace, and a version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Key {
    pub name: String,
    pub instance: String,
    pub ns: String,
}

impl Key {
    /// rgw_obj_key::parse_index_key: a bucket index entry's name
    pub fn from_index(index_name: &str, instance: &str) -> Key {
        let instance = instance.to_string();
        let b = index_name.as_bytes();
        if b.first() != Some(&b'_') {
            return Key { name: index_name.to_string(), instance, ns: String::new() };
        }
        if b.get(1) == Some(&b'_') {
            return Key { name: index_name[1..].to_string(), instance, ns: String::new() };
        }
        match index_name[1..].find('_') {
            Some(p) => Key { name: index_name[p + 2..].to_string(), instance, ns: index_name[1..p + 1].to_string() },
            None => Key { name: index_name.to_string(), instance, ns: String::new() },
        }
    }

    fn encode_instance(&self) -> bool {
        !self.instance.is_empty() && self.instance != "null"
    }

    /// rgw_obj_key::get_oid
    pub fn oid(&self) -> String {
        if self.ns.is_empty() && !self.encode_instance() {
            if !self.name.starts_with('_') {
                return self.name.clone();
            }
            return format!("_{}", self.name);
        }
        let mut oid = format!("_{}", self.ns);
        if self.encode_instance() {
            oid.push(':');
            oid.push_str(&self.instance);
        }
        oid.push('_');
        oid.push_str(&self.name);
        oid
    }

    /// rgw_obj_key::get_loc: old RGW put a locator on every object; it only
    /// differs from the name for names starting with '_'
    pub fn loc(&self) -> Option<&str> {
        (self.ns.is_empty() && self.name.starts_with('_')).then_some(self.name.as_str())
    }
}

/// A RADOS object: its name and, rarely, a locator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawName {
    pub oid: String,
    pub loc: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Obj {
    pub bucket: Bucket,
    pub key: Key,
}

fn with_marker(marker: &str, s: &str) -> String {
    if marker.is_empty() || s.is_empty() { s.to_string() } else { format!("{marker}_{s}") }
}

impl Obj {
    /// get_obj_bucket_and_oid_loc
    pub fn raw(&self) -> RawName {
        RawName {
            oid: with_marker(&self.bucket.marker, &self.key.oid()),
            loc: self.key.loc().map(|l| with_marker(&self.bucket.marker, l)),
        }
    }

    /// rgw_obj::decode, DECODE_START_LEGACY_COMPAT_LEN(6, 3, 3)
    pub fn decode(c: &mut Cursor) -> Result<Obj> {
        let h = c.start_legacy(3, 3, 0)?;
        let v = h.v;
        let mut o = Obj::default();
        if v < 6 {
            o.bucket.name = c.string()?;
            c.string()?; // loc
            o.key.ns = c.string()?;
            o.key.name = c.string()?;
            if v >= 2 {
                o.bucket = Bucket::decode(c)?;
            }
            if v >= 4 {
                o.key.instance = c.string()?;
            }
            if o.key.ns.is_empty() && o.key.instance.is_empty() {
                if o.key.name.starts_with('_') {
                    o.key.name = o.key.name[1..].to_string();
                }
            } else if v >= 5 {
                o.key.name = c.string()?;
            } else {
                let Some(p) = o.key.name[1..].find('_') else { bail!("a legacy rgw_obj name without '_'") };
                o.key.name = o.key.name[p + 2..].to_string();
            }
        } else {
            o.bucket = Bucket::decode(c)?;
            o.key.ns = c.string()?;
            o.key.name = c.string()?;
            o.key.instance = c.string()?;
        }
        c.finish(h)?;
        Ok(o)
    }
}

// ---- bucket index entries

/// One page of cls_rgw's bi_list: (type, raw index key, entry) and whether
/// more follow.  Type 1 is a plain ( listing ) entry.
pub type BiPage = (Vec<(u8, Vec<u8>, Vec<u8>)>, bool);

/// rgw_cls_bi_list_op, version 1: every release takes it.
pub fn bi_list_op(marker: &[u8], max: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(max.to_le_bytes());
    body.extend(0u32.to_le_bytes()); // name_filter
    body.extend((marker.len() as u32).to_le_bytes());
    body.extend(marker);
    let mut out = vec![1u8, 1];
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

/// rgw_cls_bi_list_ret
pub fn bi_list_ret(buf: &[u8]) -> Result<BiPage> {
    let c = &mut Cursor::new(buf);
    let h = c.start()?;
    let n = c.u32()?;
    let mut entries = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let eh = c.start()?;
        let t = c.u8()?;
        let idx = c.bytes()?;
        let data = c.bytes()?;
        c.finish(eh)?;
        entries.push((t, idx, data));
    }
    let truncated = c.bool()?;
    c.finish(h)?;
    Ok((entries, truncated))
}

pub const FLAG_DELETE_MARKER: u16 = 0x4;
pub const FLAG_VER_MARKER: u16 = 0x8;

/// The fields of rgw_bucket_dir_entry the checks read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirEntry {
    /// the index name: the object's name, escaped, with its namespace
    pub name: String,
    pub instance: String,
    pub exists: bool,
    pub size: u64,
    pub mtime: i64,
    pub etag: String,
    pub pending: usize,
    pub tag: String,
    pub flags: u16,
}

impl DirEntry {
    /// rgw_bucket_dir_entry::decode, DECODE_START_LEGACY_COMPAT_LEN(8, 3, 3)
    pub fn decode(buf: &[u8]) -> Result<DirEntry> {
        let c = &mut Cursor::new(buf);
        let h = c.start_legacy(3, 3, 0)?;
        let v = h.v;
        let mut e = DirEntry { name: c.string()?, ..Default::default() };
        c.u64()?; // ver.epoch
        e.exists = c.bool()?;
        // rgw_bucket_dir_entry_meta, DECODE_START_LEGACY_COMPAT_LEN(8, 3, 3)
        let m = c.start_legacy(3, 3, 0)?;
        c.u8()?; // category
        e.size = c.u64()?;
        e.mtime = c.time()?;
        e.etag = c.string()?;
        if m.end.is_none() {
            bail!("index entry metadata of version {} without a length", m.v);
        }
        c.finish(m)?;
        // pending_map: multimap<string, rgw_bucket_pending_info>
        let n = c.u32()? as usize;
        for _ in 0..n {
            c.string()?;
            let p = c.start_legacy(2, 2, 0)?;
            if p.end.is_none() {
                c.u8()?; // state
                c.time()?;
                c.u8()?; // op
            }
            c.finish(p)?;
        }
        e.pending = n;
        if v >= 2 {
            c.string()?; // locator
        }
        if v >= 4 {
            c.skip_struct(0, 0)?; // ver
        }
        if v >= 5 {
            c.packed()?; // index_ver
            e.tag = c.string()?;
        }
        if v >= 6 {
            e.instance = c.string()?;
        }
        if v >= 7 {
            e.flags = c.u16()?;
        }
        c.finish(h)?;
        Ok(e)
    }

    pub fn is_delete_marker(&self) -> bool {
        self.flags & FLAG_DELETE_MARKER != 0
    }

    pub fn key(&self) -> Key {
        Key::from_index(&self.name, &self.instance)
    }

    /// what radoslist calls the object: `name` or `name[instance]`
    /// The key as radoslist writes it ( rgw_obj_key's operator<< ): with
    /// its instance, without its namespace.
    pub fn display(&self) -> String {
        let name = self.key().name;
        if self.instance.is_empty() { name } else { format!("{name}[{}]", self.instance) }
    }
}

// ---- manifests

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    pub start_part_num: u32,
    pub start_ofs: u64,
    pub part_size: u64,
    pub stripe_max_size: u64,
    pub override_prefix: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Part {
    pub loc: Obj,
    pub loc_ofs: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub explicit: bool,
    pub objs: BTreeMap<u64, Part>,
    pub obj_size: u64,
    pub obj: Obj,
    pub head_size: u64,
    pub max_head_size: u64,
    pub prefix: String,
    pub rules: BTreeMap<u64, Rule>,
    pub tail_bucket: Bucket,
    pub tail_instance: String,
    pub tier_type: String,
}

impl Manifest {
    /// RGWObjManifest::decode, DECODE_START_LEGACY_COMPAT_LEN_32(8, 2, 2)
    pub fn decode(buf: &[u8]) -> Result<Manifest> {
        Manifest::decode_from(&mut Cursor::new(buf))
    }

    /// The manifest of an open upload's part, from the omap of the upload's
    /// meta object: RGWUploadPartInfo, DECODE_START_LEGACY_COMPAT_LEN(7, 2, 2)
    pub fn decode_part(buf: &[u8]) -> Result<Manifest> {
        let c = &mut Cursor::new(buf);
        let h = c.start_legacy(2, 2, 0)?;
        if h.v < 2 {
            bail!("a part record of version {} carries no manifest", h.v);
        }
        c.u32()?; // num
        c.u64()?; // size
        c.string()?; // etag
        c.time()?; // modified
        Manifest::decode_from(c)
    }

    fn decode_from(c: &mut Cursor) -> Result<Manifest> {
        let h = c.start_legacy(2, 2, 3)?;
        let v = h.v;
        let mut m = Manifest { obj_size: c.u64()?, ..Default::default() };
        for _ in 0..c.u32()? {
            let ofs = c.u64()?;
            let ph = c.start_legacy(2, 2, 3)?;
            let part = Part { loc: Obj::decode(c)?, loc_ofs: c.u64()?, size: c.u64()? };
            c.finish(ph)?;
            m.objs.insert(ofs, part);
        }
        if v >= 3 {
            m.explicit = c.bool()?;
            m.obj = Obj::decode(c)?;
            m.head_size = c.u64()?;
            m.max_head_size = c.u64()?;
            m.prefix = c.string()?;
            for _ in 0..c.u32()? {
                let ofs = c.u64()?;
                let rh = c.start()?;
                let mut r = Rule { start_part_num: c.u32()?, start_ofs: c.u64()?, part_size: c.u64()?, stripe_max_size: c.u64()?, ..Default::default() };
                if rh.v >= 2 {
                    r.override_prefix = c.string()?;
                }
                c.finish(rh)?;
                m.rules.insert(ofs, r);
            }
        } else {
            m.explicit = true;
            if let Some(first) = m.objs.values().next() {
                m.obj = first.loc.clone();
                m.head_size = first.size;
                m.max_head_size = m.head_size;
            }
        }
        // issue 16435: an old copied object's first explicit part may not be the head
        if m.explicit && m.head_size > 0 && !m.objs.is_empty() {
            let obj = m.obj.clone();
            let head_size = m.head_size;
            let p0 = m.objs.entry(0).or_default();
            if !p0.loc.key.oid().is_empty() && p0.loc.key.ns.is_empty() {
                p0.loc = obj;
                p0.size = head_size;
            }
        }
        if v >= 4 {
            m.tail_bucket = if v < 6 || c.bool()? { Bucket::decode(c)? } else { m.obj.bucket.clone() };
        }
        m.tail_instance = if v >= 5 {
            if v < 6 || c.bool()? { c.string()? } else { m.obj.key.instance.clone() }
        } else {
            m.obj.key.instance.clone()
        };
        if v >= 7 {
            c.string()?; // head placement rule
            c.string()?; // tail placement rule
        }
        if v >= 8 {
            m.tier_type = c.string()?;
        }
        c.finish(h)?;
        Ok(m)
    }

    /// RGWObjManifest::get_implicit_location
    fn implicit_location(&self, part: i64, stripe: i64, ofs: u64, override_prefix: &str) -> Obj {
        let mut name = if override_prefix.is_empty() { self.prefix.clone() } else { override_prefix.to_string() };
        let ns;
        if part == 0 {
            if ofs < self.max_head_size {
                return self.obj.clone();
            }
            name.push_str(&(stripe as i32).to_string());
            ns = "shadow";
        } else if stripe == 0 {
            name.push_str(&format!(".{}", part as i32));
            ns = "multipart";
        } else {
            name.push_str(&format!(".{}_{}", part as i32, stripe as i32));
            ns = "shadow";
        }
        let bucket = if self.tail_bucket.name.is_empty() { self.obj.bucket.clone() } else { self.tail_bucket.clone() };
        Obj { bucket, key: Key { name, instance: self.tail_instance.clone(), ns: ns.to_string() } }
    }

    /// The RADOS objects of each stripe, as RGWObjManifest::obj_iterator
    /// walks them from offset 0 to the object's size.
    pub fn locations(&self) -> Result<Vec<Obj>> {
        let mut out = Vec::new();
        if self.explicit {
            // seek(0), then ++ until the end
            if self.objs.is_empty() || self.obj_size == 0 {
                return Ok(out);
            }
            let starts: Vec<(&u64, &Part)> = self.objs.iter().collect();
            // upper_bound(0), less one
            let first = starts.iter().position(|(k, _)| **k > 0).unwrap_or(starts.len()).saturating_sub(1);
            for (_, p) in &starts[first..] {
                out.push(p.loc.clone());
            }
            return Ok(out);
        }
        let rules: Vec<(u64, &Rule)> = self.rules.iter().map(|(k, r)| (*k, r)).collect();
        let (obj_size, head_size) = (self.obj_size, self.head_size);
        if obj_size == 0 {
            return Ok(out);
        }
        // seek(0)
        let mut ofs: u64 = 0;
        let (mut part_ofs, mut stripe_ofs): (u64, u64) = (0, 0);
        let mut cur_part: i64 = 0;
        let mut cur_stripe: i64 = 0;
        let mut override_prefix = String::new();
        let mut rule_i: usize;
        let mut next_i: usize = rules.len();
        if head_size > 0 {
            rule_i = 0;
            if let Some((_, r)) = rules.first() {
                cur_part = r.start_part_num as i64;
                override_prefix = r.override_prefix.clone();
            }
            out.push(self.obj.clone());
        } else {
            // upper_bound(0), less one
            next_i = rules.iter().position(|(k, _)| *k > 0).unwrap_or(rules.len());
            rule_i = next_i.saturating_sub(1);
            let Some((_, r)) = rules.get(rule_i) else {
                return Ok(out);
            };
            cur_part = if r.part_size > 0 {
                r.start_part_num as i64 + (ofs.wrapping_sub(r.start_ofs) / r.part_size) as i64
            } else {
                r.start_part_num as i64
            };
            part_ofs = r.start_ofs.wrapping_add((cur_part - r.start_part_num as i64) as u64 * r.part_size);
            if r.stripe_max_size > 0 {
                cur_stripe = (ofs.wrapping_sub(part_ofs) / r.stripe_max_size) as i64;
                stripe_ofs = part_ofs.wrapping_add(cur_stripe as u64 * r.stripe_max_size);
                if cur_part == 0 && head_size > 0 {
                    cur_stripe += 1;
                }
            } else {
                cur_stripe = 0;
                stripe_ofs = part_ofs;
            }
            override_prefix = r.override_prefix.clone();
            out.push(self.location(ofs, cur_part, cur_stripe, &override_prefix));
        }
        // ++ until ofs reaches the object's size
        let limit = obj_size / 4096 + 1_000_000;
        for _ in 0..limit {
            if ofs == obj_size || rules.is_empty() {
                return Ok(out);
            }
            if ofs < head_size {
                rule_i = 0;
                ofs = head_size.min(obj_size);
                stripe_ofs = ofs;
                cur_stripe = 1;
                // at the end, the iterator equals obj_end(), and its location is not used
                if ofs < obj_size {
                    out.push(self.location(ofs, cur_part, cur_stripe, &override_prefix));
                }
                continue;
            }
            let mut r = rules[rule_i].1;
            if r.stripe_max_size == 0 {
                bail!("a manifest rule with no stripe size");
            }
            stripe_ofs = stripe_ofs.wrapping_add(r.stripe_max_size);
            cur_stripe += 1;
            if r.part_size > 0 && stripe_ofs >= part_ofs.wrapping_add(r.part_size) {
                cur_stripe = 0;
                part_ofs = part_ofs.wrapping_add(r.part_size);
                stripe_ofs = part_ofs;
                let last_rule = next_i >= rules.len();
                if !last_rule && stripe_ofs >= rules[next_i].1.start_ofs {
                    rule_i = next_i;
                    next_i += 1;
                    cur_part = rules[rule_i].1.start_part_num as i64;
                } else {
                    cur_part += 1;
                }
                r = rules[rule_i].1;
            }
            override_prefix = r.override_prefix.clone();
            ofs = stripe_ofs;
            if ofs > obj_size {
                ofs = obj_size;
                stripe_ofs = ofs;
            }
            if ofs < obj_size {
                out.push(self.location(ofs, cur_part, cur_stripe, &override_prefix));
            }
        }
        bail!("a manifest of {obj_size} bytes with more than {limit} stripes")
    }

    fn location(&self, ofs: u64, part: i64, stripe: i64, override_prefix: &str) -> Obj {
        if ofs < self.head_size { self.obj.clone() } else { self.implicit_location(part, stripe, ofs, override_prefix) }
    }
}

/// The RADOS objects an S3 object's head names, as radoslist lists them: the
/// head itself if it has no manifest, no data in the head, or no data; and
/// every stripe of the manifest.
pub fn object_names(head: &RawName, manifest: Option<&Manifest>) -> Result<BTreeSet<RawName>> {
    let mut names = BTreeSet::new();
    let Some(m) = manifest else {
        names.insert(head.clone());
        return Ok(names);
    };
    if m.max_head_size == 0 || m.obj_size == 0 {
        names.insert(head.clone());
    }
    for o in m.locations()? {
        names.insert(o.raw());
    }
    Ok(names)
}

#[cfg(test)]
pub mod enc {
    //! Encoders for tests, mirroring Ceph's.
    use super::*;

    pub struct Enc(pub Vec<u8>);

    impl Enc {
        pub fn new() -> Enc {
            Enc(Vec::new())
        }
        pub fn u8(&mut self, v: u8) -> &mut Self {
            self.0.push(v);
            self
        }
        pub fn u16(&mut self, v: u16) -> &mut Self {
            self.0.extend(v.to_le_bytes());
            self
        }
        pub fn u32(&mut self, v: u32) -> &mut Self {
            self.0.extend(v.to_le_bytes());
            self
        }
        pub fn u64(&mut self, v: u64) -> &mut Self {
            self.0.extend(v.to_le_bytes());
            self
        }
        pub fn s(&mut self, v: &str) -> &mut Self {
            self.u32(v.len() as u32);
            self.0.extend(v.as_bytes());
            self
        }
        pub fn raw(&mut self, v: &[u8]) -> &mut Self {
            self.0.extend(v);
            self
        }
        /// ENCODE_START .. ENCODE_FINISH around `body`
        pub fn st(&mut self, v: u8, compat: u8, body: impl FnOnce(&mut Enc)) -> &mut Self {
            let mut inner = Enc::new();
            body(&mut inner);
            self.u8(v).u8(compat).u32(inner.0.len() as u32);
            self.0.extend(inner.0);
            self
        }
    }

    pub fn bucket(e: &mut Enc, b: &Bucket) {
        e.st(10, 10, |e| {
            e.s(&b.name).s(&b.marker).s(&b.bucket_id).s(&b.tenant).u8(0);
        });
    }

    pub fn obj(e: &mut Enc, o: &Obj) {
        e.st(6, 6, |e| {
            bucket(e, &o.bucket);
            e.s(&o.key.ns).s(&o.key.name).s(&o.key.instance);
        });
    }

    pub fn manifest(m: &Manifest) -> Vec<u8> {
        let mut e = Enc::new();
        e.st(8, 6, |e| {
            e.u64(m.obj_size).u32(0).u8(0);
            obj(e, &m.obj);
            e.u64(m.head_size).u64(m.max_head_size).s(&m.prefix).u32(m.rules.len() as u32);
            for (k, r) in &m.rules {
                e.u64(*k).st(2, 1, |e| {
                    e.u32(r.start_part_num).u64(r.start_ofs).u64(r.part_size).u64(r.stripe_max_size).s(&r.override_prefix);
                });
            }
            let tail_differs = m.tail_bucket != m.obj.bucket;
            e.u8(tail_differs as u8);
            if tail_differs {
                bucket(e, &m.tail_bucket);
            }
            let inst_differs = m.tail_instance != m.obj.key.instance;
            e.u8(inst_differs as u8);
            if inst_differs {
                e.s(&m.tail_instance);
            }
            e.s("default-placement").s("default-placement").s("");
            e.st(2, 2, |e| {
                e.s("none");
            });
        });
        e.0
    }
}

#[cfg(test)]
mod tests {
    use super::enc::*;
    use super::*;

    fn b(marker: &str) -> Bucket {
        Bucket { tenant: String::new(), name: format!("bkt-{marker}"), marker: marker.into(), bucket_id: marker.into() }
    }

    fn head(name: &str, instance: &str) -> Obj {
        Obj { bucket: b("M"), key: Key { name: name.into(), instance: instance.into(), ns: String::new() } }
    }

    fn oids(m: &Manifest, head: &RawName) -> Vec<String> {
        let back = Manifest::decode(&manifest(m)).unwrap();
        assert_eq!(&back, m, "round trip");
        object_names(head, Some(&back)).unwrap().into_iter().map(|r| r.oid).collect()
    }

    const MB: u64 = 1 << 20;

    #[test]
    fn atomic() {
        // a 10 MiB PUT: a 4 MiB head, and 4 MiB stripes after it
        let mut m = Manifest { obj_size: 10 * MB, obj: head("obj", ""), head_size: 4 * MB, max_head_size: 4 * MB, prefix: ".PFX_".into(), ..Default::default() };
        m.rules.insert(0, Rule { start_ofs: 4 * MB, stripe_max_size: 4 * MB, ..Default::default() });
        m.tail_bucket = m.obj.bucket.clone();
        assert_eq!(oids(&m, &m.obj.raw()), ["M__shadow_.PFX_1", "M__shadow_.PFX_2", "M_obj"]);
        // a small object: the head alone
        let small = Manifest { obj_size: 100, head_size: 100, rules: m.rules.clone(), ..m.clone() };
        assert_eq!(oids(&small, &small.obj.raw()), ["M_obj"]);
        // an empty one
        let empty = Manifest { obj_size: 0, head_size: 0, ..small.clone() };
        assert_eq!(oids(&empty, &empty.obj.raw()), ["M_obj"]);
    }

    #[test]
    fn multipart() {
        // two 5 MiB parts and a 1 MiB one, 4 MiB stripes: no data in the head
        let mut m = Manifest { obj_size: 11 * MB, obj: head("obj", ""), prefix: "obj.2~UP".into(), ..Default::default() };
        m.rules.insert(0, Rule { start_part_num: 1, start_ofs: 0, part_size: 5 * MB, stripe_max_size: 4 * MB, ..Default::default() });
        m.rules.insert(10 * MB, Rule { start_part_num: 3, start_ofs: 10 * MB, part_size: MB, stripe_max_size: 4 * MB, ..Default::default() });
        m.tail_bucket = m.obj.bucket.clone();
        assert_eq!(
            oids(&m, &m.obj.raw()),
            ["M__multipart_obj.2~UP.1", "M__multipart_obj.2~UP.2", "M__multipart_obj.2~UP.3", "M__shadow_obj.2~UP.1_1", "M__shadow_obj.2~UP.2_1", "M_obj"]
        );
    }

    #[test]
    fn head_exactly_full() {
        // 4 MiB in a 4 MiB head: no tail, though the rule names one
        for (size, want) in [(4 * MB, vec!["M_obj"]), (4 * MB + 1, vec!["M__shadow_.P_1", "M_obj"])] {
            let mut m = Manifest { obj_size: size, obj: head("obj", ""), head_size: 4 * MB, max_head_size: 4 * MB, prefix: ".P_".into(), ..Default::default() };
            m.rules.insert(0, Rule { start_ofs: 4 * MB, stripe_max_size: 4 * MB, ..Default::default() });
            m.tail_bucket = m.obj.bucket.clone();
            assert_eq!(oids(&m, &m.obj.raw()), want, "{size} bytes");
        }
    }

    #[test]
    fn open_upload_part() {
        // part 2 of an open upload, 9 MiB in 4 MiB stripes, as the meta object's omap holds it
        let mut m = Manifest { obj_size: 9 * MB, obj: head("_multipart_obj.2~UP.2", ""), prefix: "obj.2~UP".into(), ..Default::default() };
        m.obj.key = Key { name: "obj.2~UP.2".into(), instance: String::new(), ns: "multipart".into() };
        m.rules.insert(0, Rule { start_part_num: 2, start_ofs: 0, part_size: 0, stripe_max_size: 4 * MB, ..Default::default() });
        m.tail_bucket = m.obj.bucket.clone();
        let mut e = Enc::new();
        e.st(7, 2, |e| {
            e.u32(2).u64(9 * MB).s("etag").u32(1_700_000_000).u32(0).raw(&manifest(&m));
            e.st(1, 1, |e| {
                e.s("none");
            });
            e.u64(9 * MB).u32(0).u8(0).s("");
        });
        let part = Manifest::decode_part(&e.0).unwrap();
        let names: Vec<String> = part.locations().unwrap().into_iter().map(|o| o.raw().oid).collect();
        assert_eq!(names, ["M__multipart_obj.2~UP.2", "M__shadow_obj.2~UP.2_1", "M__shadow_obj.2~UP.2_2"]);
    }

    #[test]
    fn copies_and_versions() {
        // a copy into another bucket names the source bucket's tail; a
        // versioned object's tail carries its instance
        let mut m = Manifest { obj_size: 6 * MB, obj: head("dst", "v1"), head_size: 4 * MB, max_head_size: 4 * MB, prefix: ".P_".into(), tail_instance: "v1".into(), ..Default::default() };
        m.rules.insert(0, Rule { start_ofs: 4 * MB, stripe_max_size: 4 * MB, ..Default::default() });
        m.tail_bucket = b("SRC");
        assert_eq!(oids(&m, &m.obj.raw()), ["M__:v1_dst", "SRC__shadow:v1_.P_1"]);
    }

    #[test]
    fn keys_and_locators() {
        assert_eq!(Key::from_index("obj", "").oid(), "obj");
        let k = Key::from_index("__under", "");
        assert_eq!((k.name.as_str(), k.oid().as_str(), k.loc()), ("_under", "__under", Some("_under")));
        let o = Obj { bucket: b("M"), key: k };
        assert_eq!(o.raw(), RawName { oid: "M___under".into(), loc: Some("M__under".into()) });
        let mp = Key::from_index("_multipart_a.b.2~U.meta", "");
        assert_eq!((mp.ns.as_str(), mp.name.as_str(), mp.oid().as_str(), mp.loc()), ("multipart", "a.b.2~U.meta", "_multipart_a.b.2~U.meta", None));
        assert_eq!(Key::from_index("obj", "null").oid(), "obj");
    }

    #[test]
    fn dir_entry() {
        let mut e = Enc::new();
        e.st(8, 3, |e| {
            e.s("obj").u64(7).u8(1);
            e.st(7, 3, |e| {
                e.u8(1).u64(1234).u32(1_700_000_000).u32(0).s("\"etag\"").s("owner").s("Owner").s("text/plain").u64(1234).s("").s("").u8(0);
            });
            e.u32(1).s("tag1").st(2, 2, |e| {
                e.u8(1).u32(0).u32(0).u8(1);
            });
            e.s("").st(1, 1, |e| {
                e.u8(0x81).u8(200).u8(7);
            });
            e.u8(0x82).u16(1000).s("TAG").s("inst").u16(FLAG_DELETE_MARKER).u64(3);
        });
        let d = DirEntry::decode(&e.0).unwrap();
        assert_eq!((d.name.as_str(), d.exists, d.size, d.mtime, d.etag.as_str()), ("obj", true, 1234, 1_700_000_000, "\"etag\""));
        assert_eq!((d.pending, d.tag.as_str(), d.instance.as_str(), d.is_delete_marker()), (1, "TAG", "inst", true));
        assert_eq!(d.display(), "obj[inst]");
        assert!(DirEntry::decode(&e.0[..20]).is_err());
    }
}
