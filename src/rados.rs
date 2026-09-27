//! librados, through its C API: the calls the checks make, with the
//! asynchronous ones as futures.

#![allow(non_camel_case_types)]

use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use tokio::sync::oneshot;

use crate::store::{PoolId, Pools, Stat, Store};

type rados_t = *mut c_void;
type rados_ioctx_t = *mut c_void;
type rados_completion_t = *mut c_void;
type rados_read_op_t = *mut c_void;
type rados_omap_iter_t = *mut c_void;
type rados_callback_t = Option<unsafe extern "C" fn(rados_completion_t, *mut c_void)>;

unsafe extern "C" {
    fn rados_create(cluster: *mut rados_t, id: *const c_char) -> c_int;
    fn rados_conf_read_file(cluster: rados_t, path: *const c_char) -> c_int;
    fn rados_conf_parse_env(cluster: rados_t, var: *const c_char) -> c_int;
    fn rados_conf_get(cluster: rados_t, option: *const c_char, buf: *mut c_char, len: usize) -> c_int;
    fn rados_connect(cluster: rados_t) -> c_int;
    fn rados_shutdown(cluster: rados_t);
    fn rados_ioctx_create(cluster: rados_t, pool: *const c_char, io: *mut rados_ioctx_t) -> c_int;
    fn rados_ioctx_destroy(io: rados_ioctx_t);
    fn rados_ioctx_set_namespace(io: rados_ioctx_t, ns: *const c_char);
    fn rados_aio_create_completion2(arg: *mut c_void, cb: rados_callback_t, pc: *mut rados_completion_t) -> c_int;
    fn rados_aio_release(c: rados_completion_t);
    fn rados_aio_get_return_value(c: rados_completion_t) -> c_int;
    fn rados_aio_stat(io: rados_ioctx_t, oid: *const c_char, c: rados_completion_t, psize: *mut u64, pmtime: *mut libc::time_t) -> c_int;
    fn rados_aio_getxattr(io: rados_ioctx_t, oid: *const c_char, c: rados_completion_t, name: *const c_char, buf: *mut c_char, len: usize) -> c_int;
    fn rados_create_read_op() -> rados_read_op_t;
    fn rados_release_read_op(op: rados_read_op_t);
    fn rados_read_op_omap_get_vals2(
        op: rados_read_op_t,
        start_after: *const c_char,
        filter_prefix: *const c_char,
        max_return: u64,
        iter: *mut rados_omap_iter_t,
        pmore: *mut u8,
        prval: *mut c_int,
    );
    fn rados_read_op_operate(op: rados_read_op_t, io: rados_ioctx_t, oid: *const c_char, flags: c_int) -> c_int;
    fn rados_omap_get_next2(
        iter: rados_omap_iter_t,
        key: *mut *mut c_char,
        val: *mut *mut c_char,
        key_len: *mut usize,
        val_len: *mut usize,
    ) -> c_int;
    fn rados_omap_get_end(iter: rados_omap_iter_t);
    fn rados_mon_command(
        cluster: rados_t,
        cmd: *mut *const c_char,
        cmdlen: usize,
        inbuf: *const c_char,
        inbuflen: usize,
        outbuf: *mut *mut c_char,
        outbuflen: *mut usize,
        outs: *mut *mut c_char,
        outslen: *mut usize,
    ) -> c_int;
    fn rados_buffer_free(buf: *mut c_char);
}

fn check(r: c_int, what: impl FnOnce() -> String) -> Result<c_int> {
    if r < 0 {
        bail!("{}: {}", what(), std::io::Error::from_raw_os_error(-r));
    }
    Ok(r)
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| anyhow!("{s:?} holds a NUL"))
}

pub struct Cluster {
    handle: rados_t,
}

// librados handles are thread safe
unsafe impl Send for Cluster {}
unsafe impl Sync for Cluster {}

impl Cluster {
    /// Connect as `id` ( client.admin by default ), with the config file and
    /// CEPH_ARGS.
    pub fn connect(conf: Option<&Path>, id: Option<&str>) -> Result<Arc<Cluster>> {
        let mut handle = null_mut();
        let id = id.map(cstr).transpose()?;
        unsafe {
            check(rados_create(&mut handle, id.as_ref().map_or(std::ptr::null(), |i| i.as_ptr())), || "rados_create".into())?;
            let cluster = Cluster { handle };
            let path = conf.map(|p| cstr(&p.to_string_lossy())).transpose()?;
            check(rados_conf_read_file(handle, path.as_ref().map_or(std::ptr::null(), |p| p.as_ptr())), || {
                format!("reading the ceph config {}", conf.map(|p| p.display().to_string()).unwrap_or_default())
            })?;
            check(rados_conf_parse_env(handle, std::ptr::null()), || "parsing CEPH_ARGS".into())?;
            check(rados_connect(handle), || "connecting to the cluster".into())?;
            Ok(Arc::new(cluster))
        }
    }

    /// Open a pool given as `pool` or `pool:namespace`.
    pub fn ioctx(self: &Arc<Self>, spec: &str) -> Result<Arc<IoCtx>> {
        let (pool, ns) = spec.split_once(':').unwrap_or((spec, ""));
        self.ioctx_ns(pool, ns)
    }

    pub fn ioctx_ns(self: &Arc<Self>, pool: &str, ns: &str) -> Result<Arc<IoCtx>> {
        let mut io = null_mut();
        let name = cstr(pool)?;
        unsafe {
            check(rados_ioctx_create(self.handle, name.as_ptr(), &mut io), || format!("opening pool {pool}"))?;
            if !ns.is_empty() {
                let n = cstr(ns)?;
                rados_ioctx_set_namespace(io, n.as_ptr());
            }
        }
        Ok(Arc::new(IoCtx { io, name: if ns.is_empty() { pool.to_string() } else { format!("{pool}:{ns}") }, _cluster: self.clone() }))
    }

    pub fn conf_get(&self, name: &str) -> Option<String> {
        let opt = cstr(name).ok()?;
        let mut buf = vec![0u8; 4096];
        let r = unsafe { rados_conf_get(self.handle, opt.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
        (r == 0).then(|| unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }.to_string_lossy().into_owned())
    }

    pub fn mon_command(&self, json: &str) -> Result<String> {
        let cmd = cstr(json)?;
        let mut cmds = [cmd.as_ptr()];
        let (mut out, mut outlen, mut outs, mut outslen) = (null_mut(), 0usize, null_mut(), 0usize);
        let r = unsafe {
            rados_mon_command(self.handle, cmds.as_mut_ptr(), 1, std::ptr::null(), 0, &mut out, &mut outlen, &mut outs, &mut outslen)
        };
        let take = |p: *mut c_char, n: usize| {
            if p.is_null() {
                return String::new();
            }
            let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p as *const u8, n) }).into_owned();
            unsafe { rados_buffer_free(p) };
            s
        };
        let (out, outs) = (take(out, outlen), take(outs, outslen));
        check(r, || format!("mon command {json}: {outs}"))?;
        Ok(out)
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        unsafe { rados_shutdown(self.handle) }
    }
}

pub struct IoCtx {
    io: rados_ioctx_t,
    pub name: String,
    _cluster: Arc<Cluster>,
}

unsafe impl Send for IoCtx {}
unsafe impl Sync for IoCtx {}

impl Drop for IoCtx {
    fn drop(&mut self) {
        unsafe { rados_ioctx_destroy(self.io) }
    }
}

/// An operation's buffers and its waiter, owned by the completion callback
/// until the operation completes, so dropping the future cannot free them
/// under librados.
struct Op<B> {
    buf: B,
    tx: Option<oneshot::Sender<(c_int, B)>>,
}

unsafe extern "C" fn complete<B>(c: rados_completion_t, arg: *mut c_void) {
    unsafe {
        let op = Box::from_raw(arg as *mut Op<B>);
        let rv = rados_aio_get_return_value(c);
        rados_aio_release(c);
        let Op { buf, tx } = *op;
        if let Some(tx) = tx {
            let _ = tx.send((rv, buf));
        }
    }
}

/// A librados handle that may cross threads: librados handles are thread safe.
#[derive(Clone, Copy)]
struct Handle(*mut c_void);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    // a method, so closures capture the Handle, not its pointer field
    fn ptr(self) -> *mut c_void {
        self.0
    }
}

/// Create a completion and start the operation; the receiver yields its
/// result and the buffers.
fn begin<B: Send + 'static>(buf: B, start: impl FnOnce(rados_completion_t, *mut B) -> c_int) -> Result<oneshot::Receiver<(c_int, B)>, (c_int, B)> {
    let (tx, rx) = oneshot::channel();
    let op = Box::into_raw(Box::new(Op { buf, tx: Some(tx) }));
    let mut c = null_mut();
    unsafe {
        let r = rados_aio_create_completion2(op as *mut c_void, Some(complete::<B>), &mut c);
        if r < 0 {
            return Err((r, Box::from_raw(op).buf));
        }
        let r = start(c, &mut (*op).buf);
        if r < 0 {
            // never started, so the callback will not run
            rados_aio_release(c);
            return Err((r, Box::from_raw(op).buf));
        }
    }
    Ok(rx)
}

/// Start an asynchronous operation with `start`, which gets the completion
/// and the buffers, and wait for it.
async fn aio<B: Send + 'static>(buf: B, start: impl FnOnce(rados_completion_t, *mut B) -> c_int) -> (c_int, B) {
    match begin(buf, start) {
        Ok(rx) => rx.await.expect("librados completes every operation it starts"),
        Err(failed) => failed,
    }
}

impl IoCtx {
    pub async fn stat(&self, oid: &str) -> Result<(u64, i64), c_int> {
        let Ok(o) = CString::new(oid) else { return Err(-libc::EINVAL) };
        let io = Handle(self.io);
        let (r, (_o, size, mtime)) = aio((o, 0u64, 0 as libc::time_t), move |c, b| unsafe {
            let b = &mut *b;
            rados_aio_stat(io.ptr(), b.0.as_ptr(), c, &mut b.1, &mut b.2)
        })
        .await;
        if r < 0 { Err(r) } else { Ok((size, mtime as i64)) }
    }

    pub async fn getxattr(&self, oid: &str, name: &str) -> Result<Option<Vec<u8>>> {
        let (o, n) = (cstr(oid)?, cstr(name)?);
        let mut len = 4096;
        loop {
            let io = Handle(self.io);
            let (r, (_o, _n, mut buf)) = aio((o.clone(), n.clone(), vec![0u8; len]), move |c, b| unsafe {
                let b = &mut *b;
                rados_aio_getxattr(io.ptr(), b.0.as_ptr(), c, b.1.as_ptr(), b.2.as_mut_ptr() as *mut c_char, b.2.len())
            })
            .await;
            match r {
                r if r >= 0 => {
                    buf.truncate(r as usize);
                    return Ok(Some(buf));
                }
                r if r == -libc::ENOENT || r == -libc::ENODATA => return Ok(None),
                r if r == -libc::ERANGE && len < 64 << 20 => len *= 16,
                r => bail!("getxattr {name} of {oid} in {}: {}", self.name, std::io::Error::from_raw_os_error(-r)),
            }
        }
    }

    /// The omap keys with a prefix, all pages; None if the object is missing.
    /// Blocking.
    pub fn omap_keys_blocking(&self, oid: &str, prefix: &str) -> Result<Option<Vec<String>>> {
        let (o, p) = (cstr(oid)?, cstr(prefix)?);
        let mut keys = Vec::new();
        let mut start = CString::default();
        loop {
            let mut page = Vec::new();
            let mut more = 0u8;
            unsafe {
                let op = rados_create_read_op();
                let mut iter = null_mut();
                let mut prval: c_int = 0;
                rados_read_op_omap_get_vals2(op, start.as_ptr(), p.as_ptr(), 1000, &mut iter, &mut more, &mut prval);
                let r = rados_read_op_operate(op, self.io, o.as_ptr(), 0);
                if r == -libc::ENOENT {
                    rados_release_read_op(op);
                    return Ok(None);
                }
                if r < 0 || prval < 0 {
                    rados_release_read_op(op);
                    bail!("omap of {oid} in {}: {}", self.name, std::io::Error::from_raw_os_error(-(if r < 0 { r } else { prval })));
                }
                loop {
                    let (mut k, mut v, mut klen, mut vlen) = (null_mut(), null_mut(), 0usize, 0usize);
                    if rados_omap_get_next2(iter, &mut k, &mut v, &mut klen, &mut vlen) < 0 || k.is_null() {
                        break;
                    }
                    page.push(std::slice::from_raw_parts(k as *const u8, klen).to_vec());
                }
                rados_omap_get_end(iter);
                rados_release_read_op(op);
            }
            let last = page.last().cloned();
            keys.extend(page.into_iter().map(|k| String::from_utf8_lossy(&k).into_owned()));
            match (more != 0, last) {
                (true, Some(last)) if !last.contains(&0) => start = CString::new(last).expect("checked for NUL"),
                _ => break,
            }
        }
        Ok(Some(keys))
    }
}

/// The Store on a cluster: the zone's data pools, extra pools and index pools.
pub struct RadosStore {
    pub cluster: Arc<Cluster>,
    pools: Vec<Arc<IoCtx>>,
    data: Vec<usize>,
    extra: Vec<usize>,
    index_pools: HashMap<String, String>,
    index: Mutex<HashMap<String, Option<Arc<IoCtx>>>>,
}

impl RadosStore {
    /// `data` and `extra` as `pool` or `pool:namespace`.  As rgw-gap-list.py
    /// does, a `.non-ec` pool is also searched in its `multipart` namespace.
    pub fn new(cluster: Arc<Cluster>, data: &[String], extra: &[String], index_pools: HashMap<String, String>) -> Result<RadosStore> {
        let mut store = RadosStore { cluster, pools: Vec::new(), data: Vec::new(), extra: Vec::new(), index_pools, index: Mutex::default() };
        for (specs, is_extra) in [(data, false), (extra, true)] {
            for spec in specs {
                let io = match store.cluster.ioctx(spec) {
                    Ok(io) => io,
                    Err(e) => {
                        tracing::error!("{e:#}, skipping it");
                        continue;
                    }
                };
                let mut ios = vec![io];
                if spec.ends_with(".non-ec") {
                    ios.push(store.cluster.ioctx_ns(spec, "multipart")?);
                }
                for io in ios {
                    store.pools.push(io);
                    let id = store.pools.len() - 1;
                    if is_extra { store.extra.push(id) } else { store.data.push(id) }
                }
            }
        }
        if store.data.is_empty() {
            bail!("none of the data pools {data:?} could be opened");
        }
        Ok(store)
    }

    fn order(&self, pools: Pools) -> Vec<usize> {
        match pools {
            Pools::Data => self.data.clone(),
            Pools::ExtraFirst => self.extra.iter().chain(&self.data).copied().collect(),
            Pools::DataFirst => self.data.iter().chain(&self.extra).copied().collect(),
        }
    }

    fn index_ioctx(&self, placement: &str) -> Option<Arc<IoCtx>> {
        let mut index = self.index.lock().unwrap();
        index
            .entry(placement.to_string())
            .or_insert_with(|| {
                let spec = self.index_pools.get(placement).or_else(|| self.index_pools.get("default-placement"))?;
                self.cluster.ioctx(spec).map_err(|e| tracing::error!("index pool of {placement}: {e:#}")).ok()
            })
            .clone()
    }
}

#[async_trait]
impl Store for RadosStore {
    async fn stat(&self, oid: &str) -> Stat {
        // the first data pool holds most objects; look in the others only
        // when it lacks this one
        let first = self.data[0];
        match self.pools[first].stat(oid).await {
            Ok((size, mtime)) => return Stat::Found { pool: PoolId(first), size, mtime },
            Err(r) if r != -libc::ENOENT => return Stat::Error(r),
            Err(_) => {}
        }
        let rest = self.data[1..].iter().map(|&p| async move { (p, self.pools[p].stat(oid).await) });
        let mut error = None;
        for (p, r) in futures::future::join_all(rest).await {
            match r {
                Ok((size, mtime)) => return Stat::Found { pool: PoolId(p), size, mtime },
                Err(r) if r != -libc::ENOENT => error = Some(r),
                Err(_) => {}
            }
        }
        error.map_or(Stat::Missing, Stat::Error)
    }

    async fn find(&self, oid: &str, pools: Pools) -> Option<(PoolId, u64, i64)> {
        for p in self.order(pools) {
            match self.pools[p].stat(oid).await {
                Ok((size, mtime)) => return Some((PoolId(p), size, mtime)),
                Err(r) if r != -libc::ENOENT => {
                    tracing::warn!("stat of {oid} in {}: {}", self.pools[p].name, std::io::Error::from_raw_os_error(-r))
                }
                Err(_) => {}
            }
        }
        None
    }

    async fn getxattr(&self, pool: PoolId, oid: &str, name: &str) -> Result<Option<Vec<u8>>> {
        self.pools[pool.0].getxattr(oid, name).await
    }

    async fn omap_keys(&self, pool: PoolId, oid: &str, prefix: &str) -> Result<Option<Vec<String>>> {
        let io = self.pools[pool.0].clone();
        let (oid, prefix) = (oid.to_string(), prefix.to_string());
        tokio::task::spawn_blocking(move || io.omap_keys_blocking(&oid, &prefix)).await?
    }

    async fn index_keys(&self, placement: &str, oid: &str, prefix: &str) -> Result<Option<Vec<String>>> {
        let io = self.index_ioctx(placement).with_context(|| format!("no index pool for placement {placement}"))?;
        let (oid, prefix) = (oid.to_string(), prefix.to_string());
        tokio::task::spawn_blocking(move || io.omap_keys_blocking(&oid, &prefix)).await?
    }

    async fn majors(&self) -> Result<BTreeSet<u32>> {
        let cluster = self.cluster.clone();
        let out = tokio::task::spawn_blocking(move || cluster.mon_command(r#"{"prefix": "versions", "format": "json"}"#)).await??;
        let versions: serde_json::Value = serde_json::from_str(&out)?;
        Ok(majors_of(&versions))
    }

    fn conf_get(&self, name: &str) -> Option<String> {
        self.cluster.conf_get(name)
    }
}

/// The major versions in `ceph versions` output, of the RGWs and OSDs.
pub fn majors_of(versions: &serde_json::Value) -> BTreeSet<u32> {
    let mut majors = BTreeSet::new();
    for daemon in ["rgw", "osd"] {
        if let Some(map) = versions.get(daemon).and_then(|v| v.as_object()) {
            for vstr in map.keys() {
                if let Some(m) = vstr.strip_prefix("ceph version ").and_then(|r| r.split('.').next()).and_then(|m| m.parse().ok()) {
                    majors.insert(m);
                }
            }
        }
    }
    majors
}
