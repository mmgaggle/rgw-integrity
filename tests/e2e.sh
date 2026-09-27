#!/bin/bash
# e2e.sh: rgw-integrity's server and clients on a vstart cluster that
# seed_gap_artifacts.py seeded ( see tests/README.md ).
#
#   CEPH_BUILD=~/ceph/build EXPECTED=gap-run/expected.json ./e2e.sh
#
# Checks, in order: a scan by two clients over TLS, orphans included, finds
# what the seeding left; a lapsed lease goes to another client; the server's concurrency and
# pause reach the clients; and a killed server comes back with its state.
set -u
B=${CEPH_BUILD:?set CEPH_BUILD to a ceph build directory}
T=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-$T/../target/release/rgw-integrity}
PY=${PYTHON:-python3}
W=$PWD/e2e-run
rm -rf "$W"; mkdir -p "$W"
export PATH=$B/bin:$PATH LD_LIBRARY_PATH=$B/lib CEPH_CONF=$B/ceph.conf
PORT=${PORT:-18443}
URL=https://localhost:$PORT
fails=0
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=$((fails+1)); fi; }
api() { curl -sf --cacert "$W/ca.pem" -H "Authorization: Bearer $(cat "$W/admin.token")" "$@"; }

# a CA, and a server certificate it signs
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 -subj "/CN=rgw-integrity test CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$W/server.key" -out "$W/server.csr" -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > "$W/san.ext"
openssl x509 -req -in "$W/server.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -out "$W/server.pem" -days 2 -extfile "$W/san.ext" 2>/dev/null

ceph osd pool create rgw-integrity 8 >/dev/null 2>&1
ceph osd pool application enable rgw-integrity mgr >/dev/null 2>&1
pkill -f "rgw-integrity (server|client)" 2>/dev/null
# a database of its own, and nothing left from earlier runs
DB=e2e-$(date +%s).db
rados -p rgw-integrity ls 2>/dev/null | grep '^e2e-' | xargs -r -n1 rados -p rgw-integrity rm 2>/dev/null
rados -p rgw-integrity -N rgw-integrity-work ls 2>/dev/null | xargs -r -n1 rados -p rgw-integrity -N rgw-integrity-work rm 2>/dev/null

start_server() {
  "$BIN" server -v --listen 127.0.0.1:$PORT --tls-cert "$W/server.pem" --tls-key "$W/server.key" \
    --db ceph:rgw-integrity/$DB --cephsqlite "$B/lib/libcephsqlite.so" \
    --client-token-file "$W/client.token" --admin-token-file "$W/admin.token" \
    --orphan-partitions "${PARTITIONS:-5}" --orphan-slices "${SLICES:-4}" >> "$W/server.log" 2>&1 &
  SERVER=$!
  for i in $(seq 60); do curl -s --cacert "$W/ca.pem" -o /dev/null "$URL/api/v1/status" && break; sleep 1; done
}
start_client() {
  "$BIN" client -v --server "$URL" --ca-cert "$W/ca.pem" --token-file "$W/client.token" --name "$1" >> "$W/client-$1.log" 2>&1 &
  eval "CLIENT_$1=$!"
}
wait_scan() {  # wait_scan <id> <seconds>
  for i in $(seq "$2"); do
    [ "$(api "$URL/api/v1/status" | jq -r ".scans[] | select(.id == $1) | .state")" = done ] && return 0
    sleep 1
  done
  return 1
}
settings() {  # settings <jq update>
  api "$URL/api/v1/status" | jq ".settings | $1" > "$W/settings.json"
  api -X POST -H 'Content-Type: application/json' --data @"$W/settings.json" "$URL/api/v1/settings"
}

start_server
check "server answers over TLS with the test CA" 'api "$URL/api/v1/status" >/dev/null'
check "the API refuses a request without a token" '[ "$(curl -s --cacert "$W/ca.pem" -o /dev/null -w "%{http_code}" "$URL/api/v1/status")" = 401 ]'
start_client a
start_client b

# 1. a full scan, by both clients, finding orphans too
SCAN=$(api -X POST -H 'Content-Type: application/json' \
  --data '{"options": {"grace": 0, "check_index": true, "refcount": true, "uploads": true, "match_prefix": null, "threads": 16, "orphans": true}}' \
  "$URL/api/v1/scans")
check "scan $SCAN finishes" 'wait_scan "$SCAN" 180'
api "$URL/api/v1/findings?per_page=1000" | jq -c '.findings[].finding' > "$W/scan.jsonl"
$PY "$T/check_findings.py" "${EXPECTED:?}" "$W/scan.jsonl" "$W/scan.jsonl" > "$W/check.txt"
check "the clients' findings, orphans included, match the seeded artifacts" 'tail -1 "$W/check.txt" | grep -q "^0 problem"'
check "both clients listed pool slices or joined partitions" '[ "$(grep -hcE "\( unit [0-9]+, (list|join) \)" "$W"/client-*.log | grep -vc "^0$")" -ge 1 ]'
check "the joins removed the partitions from the work pool" '[ -z "$(rados -p rgw-integrity -N rgw-integrity-work ls 2>/dev/null)" ]'
sleep 6  # a heartbeat with the final counts
check "both clients scanned buckets" '[ "$(api "$URL/api/v1/status" | jq "[.clients[] | select(.status.checked > 0)] | length")" -ge 2 ]'

# 2. a lease that lapses: a client leases a unit and never reports
settings '.lease_secs = 12' >/dev/null
kill -STOP $CLIENT_a $CLIENT_b
SCAN=$(api -X POST -H 'Content-Type: application/json' --data '{"options": {"grace": 0, "check_index": false, "refcount": false, "uploads": true, "match_prefix": null, "threads": 16}, "buckets": ["gap-clean"]}' "$URL/api/v1/scans?gc=false")
UNIT=$(api -X POST -H 'Content-Type: application/json' --data '{"client": "ghost:1", "max": 1}' "$URL/api/v1/lease" | jq '.units[0].id')
check "a ghost client leased unit $UNIT" '[ "$UNIT" != null ]'
kill -CONT $CLIENT_a $CLIENT_b
check "the lapsed lease went to a real client, and the scan finished" 'wait_scan "$SCAN" 90'
check "the server logged the lapsed lease" 'api "$URL/api/v1/status" >/dev/null && grep -q "ghost:1 stopped renewing" "$W/server.log"'
settings '.lease_secs = 120' >/dev/null

# 3. concurrency and pause reach the clients
settings '.global_inflight = 10' >/dev/null
sleep 12
check "each of two clients gets half of 10 in flight" '[ "$(api "$URL/api/v1/status" | jq "[.clients[] | select(.last_seen > (now - 30)) | .status.inflight_size] | unique" -c)" = "[5]" ]'
settings '.paused = true' >/dev/null
SCAN=$(api -X POST -H 'Content-Type: application/json' --data '{"options": {"grace": 0, "check_index": false, "refcount": false, "uploads": true, "match_prefix": null, "threads": 16}, "buckets": ["gap-clean", "gap-atrisk"]}' "$URL/api/v1/scans?gc=false")
sleep 12
check "paused clients lease nothing" '[ "$(api "$URL/api/v1/status" | jq ".scans[] | select(.id == $SCAN) | .pending")" = 2 ]'
settings '.paused = false | .global_inflight = 1024' >/dev/null
check "resumed, the scan finishes" 'wait_scan "$SCAN" 60'

# 4. the server dies; its state in RADOS survives it
BEFORE=$(api "$URL/api/v1/findings?per_page=1" | jq .total)
kill -9 $SERVER; wait $SERVER 2>/dev/null
start_server
check "a restarted server has the $BEFORE findings" '[ "$(api "$URL/api/v1/findings?per_page=1" | jq .total)" = "$BEFORE" ]'
sleep 12
check "the clients reconnected" '[ "$(api "$URL/api/v1/status" | jq "[.clients[] | select(.last_seen > (now - 15))] | length")" -ge 2 ]'

kill $CLIENT_a $CLIENT_b $SERVER 2>/dev/null
sleep 1; kill -9 $CLIENT_a $CLIENT_b $SERVER 2>/dev/null
echo "$fails failed"
exit $((fails > 0))
