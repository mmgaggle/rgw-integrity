# rgw-integrity

Finds, and classifies, what known Ceph RGW races leave behind: data that is
gone or about to be, completed multipart uploads that an abort would destroy,
bucket index entries that disagree with the objects, and leaked RADOS
objects.  Each finding names the upstream issues that can leave that
artifact, ranked by the evidence and filtered by the cluster's release.

It grew out of `rgw-gap-list.py` in
[linuxkidd/ceph-misc](https://github.com/linuxkidd/ceph-misc), and writes
findings in the same JSON format.

## Status

- `scan`: a standalone scan from one host, the equivalent of
  `rgw-gap-list.py` with its classification.  Verified against the same
  seeded vstart cluster.
- `server` and `client`: in progress.  Clients check buckets in parallel and
  report to a server that keeps state in Ceph ( libcephsqlite ) and serves a
  dashboard.

## Build

Needs librados ( `librados-devel`, or a ceph build's `lib` directory ):

```
LIBRADOS_DIR=~/ceph/build/lib cargo build --release
```

`cargo test --no-default-features` runs the tests without librados.

## Scan

```
rgw-integrity scan -v                     # every bucket
rgw-integrity scan -v -b bucket1 -I -R    # one bucket, with the per-object checks
rgw-integrity scan -v -O orphan-list-*.out  # classify rgw-orphan-list output
```

Runs where `radosgw-admin` works, as client.admin by default ( `--id` ).
Supports Reef and later.  See `rgw-integrity scan --help`.
