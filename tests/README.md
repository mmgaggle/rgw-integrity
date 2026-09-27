# Tests

`cargo test --no-default-features` runs the unit tests, without a cluster.

The rest need a vstart cluster whose radosgw has the test injection points
of ceph/ceph#72096 ( build the `vstart` and `ceph-diff-sorted` targets ):

- `seed_gap_artifacts.py` leaves the artifact of each known RGW race in a
  bucket of its own, and writes what should be found to a JSON file.
  `check_findings.py` compares findings with it.  Both come from
  `rgw-gap-list-tests` in linuxkidd/ceph-misc, where `run-gap.sh` seeds a
  fresh cluster and runs rgw-orphan-list.
- `e2e.sh` runs a server and two clients on that seeded cluster: a scan over
  TLS that must find what was seeded, a lease that lapses and goes to
  another client, the server's concurrency and pause reaching the clients,
  and a killed server coming back with its state in RADOS.

```
CEPH_BUILD=~/ceph/build EXPECTED=gap-run/expected.json ORPHANS=gap-run/orphans.txt PYTHON=~/venv/bin/python tests/e2e.sh
```
