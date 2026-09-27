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
  `rgw-gap-list.py` with its classification.
- `server` and `client`: clients lease buckets from the server and scan them
  in parallel; the server keeps state in RADOS through libcephsqlite, sets
  each client's share of a global concurrency, and can pause them.  Leases
  lapse to other clients when a client stops.
- `import`: findings from `scan` or `rgw-gap-list.py`, into a server.
- The dashboard, in the IBM Carbon Design System: in progress.

Both are tested against a vstart cluster seeded with each known race's
artifact; see `tests/`.

## Build

Needs librados ( `librados-devel`, or a ceph build's `lib` directory ):

```
LIBRADOS_DIR=~/ceph/build/lib cargo build --release
```

`cargo test --no-default-features` runs the tests without librados.

## Server and clients

```
rgw-integrity server --db ceph:rgw-integrity/state.db --tls-cert server.pem --tls-key server.key
rgw-integrity client --server https://server:8443 --ca-cert ca.pem
```

The server writes a client token and an admin token to
`/etc/rgw-integrity/{client,admin}.token` on first start; clients read the
client token.  Start a scan with the admin token:

```
curl --cacert ca.pem -H "Authorization: Bearer $(cat admin.token)" -H 'Content-Type: application/json' \
  -d '{"options": {"grace": 3600, "check_index": false, "refcount": false, "uploads": true, "match_prefix": null, "threads": 32}}' \
  https://server:8443/api/v1/scans
```

## Scan

```
rgw-integrity scan -v                     # every bucket
rgw-integrity scan -v -b bucket1 -I -R    # one bucket, with the per-object checks
rgw-integrity scan -v -O orphan-list-*.out  # classify rgw-orphan-list output
```

Runs where `radosgw-admin` works, as client.admin by default ( `--id` ).
Supports Reef and later.  See `rgw-integrity scan --help`.

## License

LGPL-3.0: see `COPYING.LESSER`, and `COPYING` for the GPL-3.0 it extends.
