# rgw-integrity

Finds, and classifies, what known Ceph RGW races leave behind: data that is
gone or about to be, completed multipart uploads that an abort would destroy,
bucket index entries that disagree with the objects, and leaked RADOS
objects.  Each finding names the upstream issues that can leave that
artifact, ranked by the evidence and filtered by the cluster's release.

It grew out of `rgw-gap-list.py` in
[linuxkidd/ceph-misc](https://github.com/linuxkidd/ceph-misc), whose gap
check it keeps, and whose gap lists it reads and writes.  The published
versions of rgw-gap-list.py ( v2.2 on main, v3.0 on its
`wip-gap-list-results-to-rados` branch ) write `s3://bucket/key MISSING
oid` text lines, and classify nothing: rgw-integrity's findings, their JSON
format and their classification are its own.  This README as first
written, and the commit that began rgw-integrity ( c83e865 ), called them a
port of rgw-gap-list.py's classification, in its JSON format; no published
version of rgw-gap-list.py has either.  See [rgw-gap-list](#rgw-gap-list)
for what it follows, and where it differs.

## Status

- `scan`: a standalone scan from one host: rgw-gap-list.py's gap check,
  with rgw-integrity's other checks and its classification, in one process.
  Copies on several hosts do not share the work ( each scans every bucket );
  for that, run `server` and `client`s.
- `server` and `client`: clients lease buckets, or the index shards of big
  ones, from the server and scan them in parallel; the server keeps state in RADOS through libcephsqlite, sets
  each client's share of a global concurrency, and can pause them.  Leases
  lapse to other clients when a client stops.
- Orphan detection: RADOS objects in the pools a scan stats in that no
  bucket references, classified as leaks ( with their likely cause ), or as heads no listing
  shows.  See below.
- `import`: findings from `scan`, or the gap lists of `rgw-gap-list.py` and
  the tools around it, into a server.  See [Import](#import).
- `verify`: gap lists statted again, as `rgw-gap-list.py -x` does, with the
  delete markers' lines dropped, as `rgw-gap-verify-versioned.sh` means to.
  See [Verify](#verify).
- `list`: a bucket's RADOS objects, or one index shard's, in the columns of
  `radosgw-admin bucket radoslist --rgw-obj-fs`, read natively.  See
  [Listing](#listing).
- A dashboard, in the IBM Carbon Design System, served by the server: what
  was found, filtered by class, cause, bucket and status, with each
  finding's evidence and triage; the clients, with the global concurrency
  and pause; and the scans.  It follows the system's light or dark theme,
  and needs no Internet access.

The server and clients are tested against a vstart cluster seeded with
each known race's artifact, and the native listing against radoslist; see
`tests/`.

## rgw-gap-list

What rgw-integrity takes from `rgw-gap-list.py` ( v2.2 on main, and v3.0 on
its `wip-gap-list-results-to-rados` branch ), and where it differs on
purpose.  rgw-gap-list.py stats each RADOS object `bucket radoslist` names,
and writes those missing from every pool as `s3://bucket/key MISSING oid`
lines; that is all it checks.  v3.0 also starts to keep them in RADOS, as
JSON records `{epoch, bucket, user_object, rados_object}`, but that is
unfinished: the write names an attribute the class never sets
( `self.results_object_name` ), so it raises once a synced scan finishes a
bucket with gaps ( or any scan's gaps pass 4 MiB ), would write the sync
object rather than a results object, and `-g` and the deletion of results
are stubs.  Of what rgw-integrity does, those published versions, and the
tools beside them, hold only the gap check, and the dropping of delete
markers' lines ( which `rgw-gap-verify-versioned.sh` means to do ): its
other checks, its catalog of issues, its classification and its JSON
findings are in none of them.  Its orphan detection does what Ceph's own
`rgw-orphan-list` does ( list the pools, and take away what the buckets'
listings name ), whose output `scan -O` classifies; the way it splits the
work, and the classification, are its own.

It follows rgw-gap-list.py in:

- the gap check, per bucket: each RADOS object a bucket's listing names is
  statted in the first data pool, then in the others, and one that is ENOENT
  in all of them is missing;
- the pools: the data pools, the first ( default ) one first, then the
  extra ( non-ec ) pools, a `.non-ec` pool in its `multipart` namespace too;
  `-p` names them instead, as a space-separated list;
- the gap list ( `-o` ): its lines, which `rgw-gap-list.py -x` can verify;
- `-b` ( a space-separated list ), `-l` ( a name per line, trimmed ), `-m`
  ( trimmed, and every key when blank ), `-a`, `-i`, and `-x` as `verify`,
  with the differences below and in [Verify](#verify).

It differs in:

- `-m` is a true prefix of the key ( `name`, or `name[instance]` for a
  version ), as S3 listings take one.  rgw-gap-list's `-m` is the regex
  `^\b<prefix>\b`: it skips `foobar` under `-m foo`, `logs/-x` under
  `-m logs/`, and every key under `-m /x`.
- Pools are not guessed: without `-p` the zone must be readable, and list
  data pools, or the scan stops ( rgw-gap-list defaults to
  `default.rgw.buckets.*`, and so reports every object of a bucket in another
  placement missing ).
- A stat that fails otherwise than with ENOENT is an error, reported, and
  never taken for a find, as rgw-gap-list takes it.
- A tenant's bucket is written `tenant/bucket`, as radosgw-admin names it:
  `s3://tenant/bucket/key MISSING oid`, and a Swift large object's segment
  under the bucket that holds it.  v2.2 writes radoslist's bucket column,
  the bucket alone ( radoslist names no tenant ), which cannot tell `t/b`
  from `b`; v3.0 writes the bucket it scans, as `bucket list`, `-b` or `-l`
  names it, so `t/b` too, but a segment under the large object's bucket.
- The gap list leaves out what is no gap at all: delete markers' heads,
  which radoslist lists and do not exist, and radoslist's misnamed OLH ( see
  [Listing](#listing) ).  It keeps, like rgw-gap-list's, what is too young
  or in flight to judge.
- `-b` and `-p` can be repeated, and are split at any whitespace ( upstream
  takes the last of each, split at single spaces ); `-b` and `-l` add up,
  where upstream reads `-l` only without `-b`; a bucket named twice is
  scanned once.
- Several hosts share the work as a server and clients, not as copies
  sharing a sync pool ( rgw-gap-list's `-s` ).  `-a` resumes from a local
  `--state` file, and only when given ( upstream's is 7 days, for a scan of
  every bucket ); the server's `/api/v1/scans/{id}/units` stands for `-r -j`.
- `-i` ( 1024 by default ) is shared by a scan's `--parallel` units, and
  counts the reads of heads, manifests, upload records, refcounts and single
  index entries too; rgw-gap-list's ( 10000 ) bounds its process's stats,
  of one bucket at a time.
- Buckets are listed natively by default, not with radoslist ( see
  [Listing](#listing) ): `--radoslist` lists as rgw-gap-list does.

## Dashboard

From a vstart cluster seeded with each known race's artifact ( see `tests/` ).

![Overview](docs/screenshots/overview.png)

![Findings, in the dark theme](docs/screenshots/findings-dark.png)

![A finding's causes and evidence](docs/screenshots/finding-dark.png)

![Clients and their concurrency](docs/screenshots/clients.png)

![Scans](docs/screenshots/scans-dark.png)

## Single sign-on

The dashboard and the admin API can take logins from an OpenID Connect
provider ( Keycloak, IBM Security Verify, Okta, Entra ID, ... ):

```
rgw-integrity server ... --public-url https://rgwi.example.com:8443 \
  --oidc-issuer https://sso.example.com/realms/storage --oidc-client-id rgw-integrity \
  --oidc-client-secret-file /etc/rgw-integrity/oidc.secret \
  --oidc-allowed-groups storage-admins --oidc-name "IBM Security Verify"
```

- The login is the authorization code flow with PKCE; the server checks the
  ID token's signature against the provider's keys, and its issuer,
  audience, expiry and nonce.  Register `<public url>/oidc/callback` as the
  client's redirect URI, and `<public url>/login` as its post-logout one.
- Only `--oidc-allowed-users` and members of `--oidc-allowed-groups` ( the
  `--oidc-groups-claim`, `groups` by default ) get in, unless
  `--oidc-allow-any-user`.  Others are refused, and the refusal is logged.
- The admin API takes the provider's access tokens as bearer tokens, with
  the audience `--oidc-api-audience` ( the client id by default ) and the
  same rules, for automation.
- Logins are server-side sessions of 12 hours; logout ends the provider's
  session too.  Events name who changed what.
- `--oidc-only` removes the admin token's login from the dashboard; the
  token still works as the API's bearer token, and clients keep theirs.

![Logging in](docs/screenshots/login-dark.png)

## Listing

A bucket's RADOS objects come from its own index and heads, not from
`radosgw-admin bucket radoslist`: each index shard is paged through cls_rgw's
`bi_list`, each entry's head is read for its manifest ( `user.rgw.manifest` ),
and the manifest is walked as RGW's `obj_iterator` walks it; an open upload's
parts come from the part records in its meta object.  This is several times
faster than radoslist, reads nothing through RGW, and works a shard at a
time: every entry of a key ( its versions, its OLH, its uploads' meta and
part entries ) is in the shard its name hashes to, so each shard is listed
on its own.

A bucket with more than `--shard-units-above` S3 objects ( 100,000 ) over
several shards becomes a unit per shard, which a server spreads over its
clients, and a standalone scan over its `--parallel` tasks ( the buckets
`-b` and `-l` name too: their stats are read first, `--parallel` at a
time, and one whose stats cannot be read then is a unit whole ).  With
`--radoslist` a bucket is always one unit.  A copy shares
its source's tail, and names its upload, from another shard: a shard unit
reads such an upload's meta object
( `<marker>__multipart_<key>.<upload>.meta`, the extra pools first ), and
reads the uploads every head of the bucket names before it reports one of
its own that no head of it names ( below ).  The findings of a sharded
bucket are marked gone only once every shard is scanned without errors.

With `-m` ( `--prefix` ), the native listing reads only the index entries
under the prefix, in every shard: a range of the plain entries ( from the
prefix as the index writes it, a leading `_` escaped ), one of the
multipart namespace ( `_multipart_<prefix>` ), and, for a prefix that runs
into a `[`, one of that name's versions.  A scan of a prefix costs what the
keys under it do, not what the bucket does, and its checks ( the index
check, open uploads and their parts ) keep to those keys.  It lists whole
buckets, and drops the keys not under the prefix, where it needs every
head:

- `--radoslist`: bucket radoslist takes no prefix.
- `--refcount`: a tail's references are carried by the heads of its copies,
  wherever their keys are.
- Orphan detection, which refuses a prefix anyway.
- Once per unit at most, the heads only: before it reports an open
  upload's parts missing from the index ( `part_entries_missing` ) when no
  head it listed names the upload, as a copy outside the prefix may.  A
  shard unit does the same, and so does a listing cut short, or one that
  could not read what a head names.  If that read fails, or cannot read a
  head's manifest ( an error of the unit ), or a `--radoslist` listing was
  cut short, the upload is tallied ( `an upload with unindexed parts, not
  every head that may name it read` ), not reported.

The open uploads' entries are read in full ( one per upload or part ), and
errors of objects outside the prefix ( a manifest that does not decode ) are
not reported, as those objects are not read.

Swift large objects keep their segments in other containers of the head's
tenant: a DLO's head names a `container/prefix` ( `user.rgw.user_manifest`,
url-decoded as RGW does ), an SLO's a list of `/container/object` paths
( `user.rgw.slo_manifest`, read as a GET reads them ).  As radoslist does,
the native listing follows them, and lists the segments' RADOS objects under
their own bucket, nesting included ( 8 deep ).  It does not follow them into
a bucket the scan lists itself ( the unit's own, one it names, or any, for a
scan that names none ) under its prefix: that bucket's scan checks them.  A
followed segment is checked as its own bucket's scan would check it, its
open uploads ( a meta object read each ) and that bucket's lifecycle included,
and its gap lines and findings are reported once a scan ( a server keeps a
gap line once a scan, and a finding once ).  A container that does not
exist ( `bucket stats` and `metadata get bucket:<name>` both ENOENT ) is a
warning and a tally, as for radoslist; one whose entrypoint is there but
whose stats are ENOENT ( its instance missing, or before Ceph 20 an index
shard ) is an error of the unit, as is one whose stats cannot be read,
which each unit asks for again, once.  An SLO manifest that does not decode
is an error, unless the scan covers every bucket and key; a path that names
no object is a tally.

The RADOS objects a scan counts are the ones it checks: heads, tails and
open uploads' parts, but not delete markers' heads, which do not exist.  So
the count is not rgw-gap-list's `rados_obj_count`, which counts radoslist's
lines.  As radoslist does, it lists a null version's head twice when newer
versions exist, as the key's OLH object and as the null version: its
objects count twice, as rgw-gap-list's do, but its gaps and `-o` lines once
each ( rgw-gap-list writes each line twice ), as a server's gap list keeps
them, and its finding once.

`tests/compare_listing.sh` checks the native listing against radoslist,
object for object, and each shard's listing against the whole, on buckets
`tests/seed_listing_corpus.py` fills with sizes around the head and stripe
boundaries, multipart uploads open and completed, copies within and across
buckets, versions and delete markers, keys starting with `_`, a tenant's
bucket, and an index resharded to 13 shards.  They agree but where
radoslist is wrong:

- radoslist lists the heads of delete markers, which do not exist.
- With `--rgw-obj-fs`, radoslist leaves out open uploads' parts
  ( `RGWRadosList::run` returns before `do_incomplete_multipart` ).
- For a versioned key starting with `_`, radoslist names the key's OLH
  from its escaped index name: an object that does not exist, instead of the
  one that does.  rgw-gap-list reports a missing object for it
  ( rgw-orphan-list sets objects with locators aside, so it does not call
  the OLH an orphan ).

`--radoslist` ( or the dashboard's radoslist box ) lists with radosgw-admin
instead, a unit per bucket.  A tenant's bucket `t/b` is listed with
`--tenant=t --uid=rgw-integrity --bucket=b` ( radosgw-admin refuses `--tenant`
without a user, which need not exist ), so its Swift segments resolve in
the tenant too, and every line names `t/<bucket>`, as the native listing
does.  A radosgw-admin listing the scan stops reading, or whose output does
not parse, is killed and reaped, not left to run on.

`list` writes radoslist's columns, `oid<sep>bucket<sep>key` ( `--separator`,
a tab by default ), a tenant's bucket as `tenant/bucket` ( `list --radoslist`
too ), and an open upload's parts, which radoslist leaves out, as bare oid
lines.  Otherwise it differs from radoslist only where radoslist is wrong,
above.  It lists whole buckets: it takes no prefix.

## Orphans

A scan with orphans ( `"orphans": true`, the dashboard's Orphans box, or
`scan --find-orphans` ) lists every object in the pools the scan stats in
( `--pool`'s, or the zone's data and extra pools, a `.non-ec` pool's
`multipart` namespace too ), and keeps those no bucket's listing
references.  It needs every bucket and every key ( no `-b`, `-l` or `-m` ),
and is refused when `radosgw-admin bucket stats` cannot read a bucket, whose
objects would be taken for orphans.  Nothing holds the whole
cluster's names: both sides are split into partitions by a hash of the
object's name, about a million names each.

- Clients list the pools in slices ( librados's `rados_object_list_slice` ),
  and file the names by partition; bucket scans file a 16-byte hash of each
  name they list.  With a server, the partitions are objects in the
  `rgw-integrity-work` namespace of the database's pool, or of
  `--work-pool` ( a pool spec, as `--pool` takes it ), and the pools listed
  are the server's ( its `--pool`, or the zone's ): start the clients with
  the same `--pool`.  A standalone scan keeps them in a directory of its
  own, `rgw-integrity-<pid>-<started>` under `--work-dir` ( the system's
  temporary directory by default ), made new and removed however the scan
  ends, a second signal included; nothing else there is touched.
- Once every bucket and pool slice is in, a join per partition keeps the
  names nothing references, and removes the partition.  If a bucket or a
  slice failed, the references are incomplete: a server skips the joins
  ( event `orphan detection skipped` ), and a standalone scan stops, rather
  than report false orphans.  With radoslist listings ( `--radoslist`, the
  radoslist box ), a bucket whose open uploads, or whose stats, cannot be
  read fails its unit, standalone and on a server alike: radoslist leaves
  out open uploads' parts, which only the bucket's upload listing names.  A
  server also skips the joins when such a bucket unit, with the uploads
  check, is done with errors of any kind, as a client from before that
  rule reports a failed upload listing; a standalone scan goes on then,
  its references whole.  A native listing's errors leave its references
  whole.
  Once the joins are in, what they kept is classified before the scan
  closes, always: judging it complete and closing it are one transaction.
- What the joins keep is classified together, by bucket marker, so that an
  unlisted head and its tail, or an upload's parts, make one finding.
  Objects newer than the scan's start, less the grace period, are skipped,
  as writes in flight; so are parts of open uploads, parts of uploads
  completed since their bucket was listed, and objects queued for GC.  An
  object whose stat fails, or a head whose tag cannot be read, is tallied,
  not called an orphan, and a meta object that cannot be read counts as an
  open upload's.

It reads every object's name once, and holds about 90 bytes per name of a
partition while joining it.

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
client token.  Start a scan with the admin token ( `"buckets": [...]` for
only some ):

```
curl --cacert ca.pem -H "Authorization: Bearer $(cat admin.token)" -H 'Content-Type: application/json' \
  -d '{"options": {"grace": 3600, "check_index": false, "refcount": false, "uploads": true, "match_prefix": null, "threads": 32}}' \
  https://server:8443/api/v1/scans
```

- The findings: `GET /api/v1/findings`, one JSON object, `{total,
  findings: [{id, status, first_seen, last_seen, first_scan, last_scan,
  note, finding}]}`, of every scan, worst class first, 50 a page
  ( `?page=` from 0, `?per_page=` up to 1000 ); `?scan=N` keeps those scan
  N saw last, and `class`, `check`, `bucket`, `cause`, `confidence`,
  `status`, `after_fix` and `key` ( a substring ) narrow them.  Each
  `finding` is a line of scan's `-J`, and lists at most 100 of its RADOS
  objects ( `oid_count` holds how many there are ): `jq -c
  '.findings[].finding'` makes JSON lines of them.
- A scan's gap list: `GET /api/v1/scans/{id}/missing`, the `s3://bucket/key
  MISSING oid` lines its units reported, each once, as scan's `-o` ( the scan
  page's "Download the gap list" ).  Gaps too young or in flight to judge are
  in it, and have no finding yet.
- A scan's units: `GET /api/v1/scans/{id}/units[?state=]`, each one's state,
  client, attempts, times, RADOS objects, gaps, findings, error and what it
  skipped, as rgw-gap-list's `-r -j` gives its buckets.  The dashboard shows
  them per scan ( Missing, Skipped ), and counts the units with errors.
- The global concurrency ( the dashboard's RADOS operations in flight ) is
  for the whole cluster, divided among the clients seen in the last 30 s,
  not per process as rgw-gap-list's `-i`.  `--admin-concurrency` is each
  process's, the server's and each client's: the radosgw-admin commands it
  runs at once, but for the streamed listings.
- A client posts a unit's report whole, or, past 64 MiB, in parts
  ( `/api/v1/report/part` ) and then the rest; the server counts the parts
  of the attempt that holds the lease, once its report is in.  A report that
  cannot be delivered ( to a server too old for parts, say ) fails the
  unit, which is retried.

A scan, as it closes, marks gone the open and confirmed findings it
checked again and did not find: those of the checks it ran ( the index
check's only with `check_index`, the uploads' with `uploads`, the GC's with
a GC snapshot, `unheld_reference` only with `refcount` ), with keys under
its prefix, and older than its grace, in buckets it has units of whose
every unit is done without errors.  An unheld reference has no key, and
its tail's references are merged across the scan's buckets ( filed under
the first bucket to report a head that needs one, when a copy in another
may need it too ): only a scan of every bucket ( no `"buckets"`, or with
orphans ) with no prefix retires it, and not while the scan finds its tail
unheld under another bucket.  A tail whose refcount cannot be read or
decoded is an error of its unit.  A bucket whose units failed or
had errors ( a stat that failed, a listing cut short ) keeps its findings,
and the scan's event names it ( `scan N kept X finding(s) ...` ).  Orphans
go only with a complete orphan detection, whoever found them.  A finding a
scan marked gone that is found again gets back its status, so triage is
kept; one a person marked gone is reopened by any new evidence.

A late report, of a cancelled scan or of a unit of a closed one, records
its findings as its scan's, but reopens none that a newer scan marked gone:
a finding keeps the last scan that checked it and marked it gone, and only
evidence of a newer scan, or of none ( an import, the parts of an attempt
that never reported ), reopens it.  Nor does it move a finding's last scan
back.  A finding marked gone by a server from before it kept that scan is
taken, as the server upgrades, as marked gone by the last scan done then
( the scan that did is not recorded, and can be no later ); from before it
kept a scan's gone apart from a person's, a person's is taken the same.
The grace is judged on the server's clock here, and on each client's as it
scans: skew between them can let a finding a client skipped as young go.

## Scan

```
rgw-integrity scan -v                     # every bucket
rgw-integrity scan -v -b bucket1 -I -R    # one bucket, with the per-object checks
rgw-integrity scan -v -b "b1 b2" -m logs/ # two buckets, the keys under logs/
rgw-integrity scan -v -O orphan-list-*.out  # classify rgw-orphan-list output
rgw-integrity list -b bucket1 --shard 3     # one index shard's RADOS objects
rgw-integrity verify rgw-integrity-missing.txt gap-list-results.1234
```

Runs where `radosgw-admin` works, as client.admin by default ( `--id` ).
Supports Reef and later.  See `rgw-integrity scan --help`.

- Pools: without `-p`, the zone's ( `radosgw-admin zone get`, tried three
  times ): every placement's data pools ( a legacy placement's `data_pool`
  too ), then its extra pools.  A zone that cannot be read, or lists no data
  pools, is an error, not a guess.  `-p` names the data pools instead:
  repeated, or one space-separated list; each `pool` or `pool:namespace`,
  with a `:` or `\` in either escaped by a `\`, as the zone writes them
  ( `rgw\:data` is the pool `rgw:data` ), and a space too.  The zone's extra
  pools are still searched for upload meta objects.
- Buckets: every one `radosgw-admin bucket list` names; one whose `bucket
  stats` still cannot be read when its unit starts is listed with
  radoslist, without the upload and index checks, and is an error of its
  unit.  `-b` is split at whitespace ( no S3 bucket name holds any ); `-l`
  lines are only trimmed, for a Swift container with a space in its name.
  `-b` and `-l` add up, and a bucket named more than once is scanned once,
  in the order first named.  An empty name is refused: radosgw-admin takes
  it for every bucket.
- Output: `-J` ( `rgw-integrity-findings.jsonl` ), the findings, checked and
  classified, a JSON object per line; `-o` ( `rgw-integrity-missing.txt` ),
  the gap list, as above.  The gap list holds every gap but what is none at
  all ( a delete marker's head, radoslist's misnamed OLH, a key deleted
  during the scan ); gaps too young ( `--grace` ) or in flight to judge are
  in it with no finding yet, and counted under `Skipped:` in the summary.
  `--grace 0` reports them at once, as rgw-gap-list does.  Both files are
  locked while the scan runs: a second scan with the same files stops before
  it connects, and needs its own.  They are emptied only as the scan starts
  writing, once what it reads first is read ( the zone, the buckets and,
  but for named buckets with `--radoslist`, their stats; a `-O` file ): one
  that stops before leaves an earlier scan's
  as they were.  They are written as each unit finishes, and removed if they
  hold nothing, however the scan ends.
- Errors: a stat that fails otherwise than with ENOENT, a head, meta
  object or tail's refcount that cannot be read ( or a refcount decoded ),
  a listing cut short are errors of their unit,
  logged, and never taken for a find: what they would have told is not
  judged, and the unit counts as not fully checked.
- Resuming: `--state FILE` records each unit as it finishes, with its
  findings and gap lines, and the buckets it relied on for Swift segments;
  `-a SECS` ( `--maxage` ) then skips the units recorded as finished without
  errors that recently, with the same checks and shard count.  It rescans a
  unit that followed segments into a bucket its scan did not list, or left
  them to a bucket this scan does not name: its record may not hold their
  lines, or this scan may write them again.  `-J` and `-o` still start
  empty: the skipped units' recorded lines are written to them first, so
  they hold the whole result, as a scan of every unit would.  A record of
  an older rgw-integrity, without those fields, is passed over with a
  warning, and its unit rescanned.  With units skipped, the refcount
  check's references are not resolved.
- Progress: every 30 s ( with `-v` ), a `[status]` line per running unit and
  one for the whole; a line per unit as it finishes.
- Signals: the first SIGINT or SIGTERM finishes the running units, starts
  no more, and skips orphan detection; the second exits at once, removing
  the scan's work directory, and `-J` and `-o` if they hold nothing.  What
  is done is in the files either way.
- Exit status: 0 when every unit was scanned in full, findings or not; 1
  when the scan could not run, or stopped on an error; 2 when the command
  line is refused, and nothing ran; 3 when some units failed or had errors,
  so what they found is partial; 4 when a signal stopped it before it was
  done ( units left, or orphan detection ).

A versioned key whose OLH object is missing, while a live version is
current, is an inconsistency ( `olh_missing` ): GET without a versionId
answers 404, though each version is still read by its versionId.  One with
an index op pending, a delete marker current, or younger than the grace, is
skipped; an older null delete marker that a later version replaced excuses
nothing, and `verify` keeps that line.

## Verify

`verify` stats each line's RADOS object again, in the pools a scan stats in
( `-p` too ), as `rgw-gap-list.py -x` does, and writes the lines of what is
still missing, `... STILL MISSING <oid>`, to `-o`
( `rgw-integrity-still-missing.txt` ).  It reads any mix of: scan's `-o`
file and a server's gap list; rgw-gap-list.py's results ( v2.2's and v3.0's
lines, and v3.0's JSON records, as its unfinished results objects would
hold them ) and its `-x` output; rgw-gap-list-by-bucket's
`bucket/key MISSING oid`; rgw-gap-verify-versioned.sh's output; and its own.
A head's line whose key ends in blanks, which upstream strips from the key
but not from the oid, is read as that key ( not a `-x` line's, stripped
again ).  Unlike `-x`:

- A stat that fails otherwise than with ENOENT is an error, and its line
  is kept as it was ( `MISSING` ), to verify again; `-x` counts it found.
- A line is split where its oid names the key, not at its last ` MISSING `,
  and only the separator becomes ` STILL MISSING `: `-x` rewrites every
  ` MISSING `, the key's and the oid's too, and a line verified twice
  becomes `STILL STILL MISSING`.
- The inputs are read in full before anything is written, through a
  rename: `verify -o F F` keeps F whole, where `-x F -o F` truncates it.
  Nothing is written when nothing is left, and an earlier output is
  removed ( unless it is an input ).  Lines read twice are statted once.
- It exits 1 when anything is still missing, a stat failed, or an index
  lookup failed.

A delete marker has no RADOS object, yet radoslist lists its head, so a gap
list of a versioned bucket names every delete marker as missing.
`rgw-gap-verify-versioned.sh` was written to drop those lines, but its jq
filter never matches as written: it looks for the key in literal braces
( `--arg O "{$object}"` ), and cuts the instance off the key only if it is
alphanumeric, where RGW's hold `-` and `.` too.  So it drops no line, and
prefixes every one with `Not Versioned Instance: `; nor can it read a
tenant's bucket.  `verify` does what it meant: for each head still missing,
it reads the key's index entry ( `radosgw-admin bi list --object`, a leading
`_` escaped, the null version as no instance, a tenant's bucket as
`tenant/bucket` ), and drops the line of a delete marker; a null delete
marker that a later version replaced is no excuse, as the head is then the
key's OLH, which a GET reads.  A head the index holds no entry for is kept,
and counted: a lookup that misses must not hide a gap.
`--keep-delete-markers` looks nothing up.

## Import

`rgw-integrity import -s https://server:8443 --ca-cert ca.pem FILE` sends
findings to a server: scan's `-J` file ( JSON lines, or one JSON document ),
or a gap list of any form `verify` reads.  A finding is recorded as it is,
as evidence of no scan: it replaces the record of one with its fingerprint,
and reopens it if it was marked gone.

Gap lines become unverified findings, grouped per bucket and key:
`listed_without_head` when the key's head is among the missing,
`missing_data` otherwise, with no causes, and evidence that says they come
from rgw-gap-list, unverified.  A scan of their bucket replaces them, or
marks them gone, under the rules of [Server and clients](#server-and-clients).
A gap the server has recorded already, open or gone, is left as it is: a
gap list has no time, so a stale one cannot be told from a loss that came
back ( which stays gone until a scan finds it again ).

A line's bucket and key are split where its oid names the key: a head's,
a part's, a multipart or appendable object's tail's.  An atomic object's
tail names no key, and is split at the first `/`, as upstream splits it,
unless an exact line of the same object in the file ( the same text, its
oid of the same bucket marker ) settles it.  Only a head's oid splits a
tenant off, as a copy's parts and tails are named by its source's key.  So
the `s3://t/b/k` lines of a tenant's bucket ( scan's, a server's, v3.0's )
import under `t/b` when the file holds the head's line, its parts' and
tails' lines with it.  Without it ( the usual `missing_data`: the head is
there, its tails are gone ), the server settles them by its cluster's
bucket names ( `radosgw-admin bucket list`, read once an import, and only
when a line needs them ): under the tenant's bucket `t/b` if there is one,
else under a global bucket `t`, key `b/k`, as upstream splits them.  When
the names cannot be read, they import as upstream splits them, and the
import's event says so: under a bucket `t` that does not exist, no scan
replaces or retires them; under a global `t` that does, a clean scan of
`t` retires them, as it finds no `b/k`.  `verify` settles its lines the
same way, for its index lookups.  v3.0's JSON records name the bucket
apart, and import under `t/b`.  v2.2's lines of `t/b` name it `b`,
and import as `b`: a scan of `t/b` does not clear them, and one of a global
`b` can.

## License

LGPL-3.0: see `COPYING.LESSER`, and `COPYING` for the GPL-3.0 it extends.
