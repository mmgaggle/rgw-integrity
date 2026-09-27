# Tests

`cargo test --no-default-features` runs the unit tests, without a cluster:
the listing, the checks and the gap-list reading against an in-memory store
( `store::MockStore`, with an emulation of cls_rgw's `bi_list` ), and the
server's database.

The rest need a vstart cluster whose radosgw has the test injection points
of ceph/ceph#72096 ( build the `vstart` and `ceph-diff-sorted` targets ):

- `seed_gap_artifacts.py` leaves the artifact of each known RGW race in a
  bucket of its own ( through the radosgw's injection points ), and writes
  what rgw-integrity should find there to a JSON file: each finding's
  class, check, key and likely causes, or that the bucket is clean.
  `check_findings.py` compares rgw-integrity's findings, as JSON lines,
  with it: scan's `-J`, or a server's, which `/api/v1/findings` answers as
  one paged object ( take `?per_page=1000` through
  `jq -c '.findings[].finding'`, as `e2e.sh` does ).  They are
  rgw-integrity's own tests, written for its findings: nothing published
  in linuxkidd/ceph-misc ( main, and its `wip-gap-list-results-to-rados`
  branch ) writes that format, and rgw-gap-list.py's results cannot be
  checked with them.  `seed_gap_artifacts.py OUT.json fixed`
  seeds a radosgw that has the fixes too, where the races leave ( nearly )
  nothing.
- `e2e.sh` runs a server and two clients on that seeded cluster: a scan over
  TLS, orphans included, that must find what was seeded ( `check_findings.py`
  on the server's findings ), a lease that lapses and goes to another
  client, the server's concurrency and pause reaching the clients, and a
  killed server coming back with its state in RADOS.

```
CEPH_BUILD=~/ceph/build EXPECTED=gap-run/expected.json PYTHON=~/venv/bin/python tests/e2e.sh
```

  `SHARD_UNITS_ABOVE=0` makes every bucket of several shards a unit per shard.
- `seed_listing_corpus.py` fills buckets whose objects exercise the native
  listing ( any vstart cluster: it needs no injection points ), and
  `compare_listing.sh` lists every bucket natively, with radoslist, and a
  shard at a time, and compares them object for object:

  ```
  CEPH_BUILD=~/ceph/build python tests/seed_listing_corpus.py
  CEPH_BUILD=~/ceph/build tests/compare_listing.sh
  ```

- `oidc/`: single sign-on through Keycloak.  `keycloak.sh` runs one in
  podman with realm `rgwi` ( `realm.json` ): alice is in `rgw-admins`, bob is
  not.  Start a server on https://localhost:18443 with
  `--public-url https://localhost:18443 --oidc-issuer http://localhost:8080/realms/rgwi --oidc-client-id rgw-integrity`
  `--oidc-client-secret-file <( echo rgwi-test-secret ) --oidc-allowed-groups rgw-admins --oidc-name Keycloak`,
  and run `test_oidc.py` where a browser reaches both ports:

  ```
  uv run --with playwright python tests/oidc/test_oidc.py chrome
  ```
