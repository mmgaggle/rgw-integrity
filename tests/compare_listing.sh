#!/usr/bin/env bash
# compare_listing.sh: the native listing against radosgw-admin bucket
# radoslist, bucket by bucket, object for object.
#
#     CEPH_BUILD=~/ceph/build tests/compare_listing.sh [bucket ...]
#
# Every bucket by default.  Two comparisons:
#   keyed: RADOS object and key, against radoslist --rgw-obj-fs ( which
#          writes a tenant's bucket without its tenant ),
#          which leaves out open uploads' parts ( RGWRadosList::run returns
#          before do_incomplete_multipart when it writes keys )
#   oids:  every RADOS object, against plain radoslist, which lists them
#   shards: the listings of each index shard, together, against the whole
# They must match but for radoslist's mistakes, which the native listing
# does not make:
#   - it lists the heads of delete markers, which do not exist
#   - it names the shared head ( OLH ) of a versioned key starting with '_'
#     from the key's escaped index name: an object that does not exist, in
#     place of the one that does ( so rgw-gap-list reports a missing object )
set -euo pipefail
B=${CEPH_BUILD:?set CEPH_BUILD to a vstart build directory}
T=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-$T/../target/release/rgw-integrity}
DATA_POOL=${DATA_POOL:-default.rgw.buckets.data}
export PATH=$B/bin:$PATH LD_LIBRARY_PATH=$B/lib CEPH_CONF=$B/ceph.conf
cd "$B"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
if [ $# -eq 0 ]; then
    mapfile -t buckets < <(radosgw-admin bucket list 2>/dev/null | jq -r '.[]')
else
    buckets=("$@")
fi
srt() { LC_ALL=C sort -u "$@"; }
# the objects of stdin that exist
existing() { while IFS= read -r o; do rados -p "$DATA_POOL" stat "$o" >/dev/null 2>&1 && echo "$o"; done; true; }
# drop the OLHs radoslist misnames: object o of key k ( k starting with '_' )
# is M_<rest>; radoslist lists M__<rest> for key _k.  $1: radoslist's lines,
# $2: 1 for oid and key, 2 for oids alone
misnamed() {
    awk -F'\t' -v cols="$2" '
        NR == FNR { r[$0] = 1; next }
        { i = index($1, "_"); m = substr($1, 1, i) "_" substr($1, i + 1) }
        cols == 1 && substr($2, 1, 1) == "_" && ((m "\t_" $2) in r) { next }
        cols == 2 && (m in r) { next }
        { print }' "$1" -
}
fails=0
for b in "${buckets[@]}"; do
    "$BIN" list -b "$b" 2>"$out/n.err" | srt >"$out/n" || { echo "FAIL  $b: native listing failed"; cat "$out/n.err"; fails=$((fails + 1)); continue; }
    "$BIN" list -b "$b" --radoslist 2>/dev/null | cut -f1,3 | srt >"$out/rk"
    radosgw-admin bucket radoslist --bucket="$b" 2>/dev/null | srt >"$out/ro"
    { grep -F "$(printf '\t')" "$out/n" || true; } | cut -f1,3 | srt >"$out/nk"
    cut -f1 "$out/n" | srt >"$out/no"
    rk_only=$(LC_ALL=C comm -23 "$out/rk" "$out/nk" | cut -f1 | existing)
    nk_only=$(LC_ALL=C comm -13 "$out/rk" "$out/nk" | misnamed "$out/rk" 1)
    ro_only=$(LC_ALL=C comm -23 "$out/ro" "$out/no" | existing)
    no_only=$(LC_ALL=C comm -13 "$out/ro" "$out/no" | misnamed "$out/ro" 2)
    gone=$(LC_ALL=C comm -23 "$out/ro" "$out/no" | wc -l)
    shards=$(radosgw-admin bucket stats --bucket="$b" 2>/dev/null | jq -r '.num_shards // 1')
    [ "$shards" -gt 0 ] || shards=1
    for ((i = 0; i < shards; i++)); do "$BIN" list -b "$b" --shard "$i" 2>/dev/null; done | srt >"$out/s"
    shard_diff=$(LC_ALL=C comm -3 "$out/n" "$out/s")
    if [ -z "$rk_only$nk_only$ro_only$no_only$shard_diff" ]; then
        printf 'PASS  %-24s %5d objects, %d keyed, %d shard(s)' "$b" "$(wc -l <"$out/no")" "$(wc -l <"$out/nk")" "$shards"
        [ "$gone" -gt 0 ] && printf ', %d objects radoslist names that do not exist' "$gone"
        echo
    else
        fails=$((fails + 1))
        echo "FAIL  $b"
        for v in rk_only nk_only ro_only no_only shard_diff; do
            [ -n "${!v}" ] && printf '%s\n' "${!v}" | head -5 | sed "s/^/    $v: /"
        done
    fi
    grep -v '^\*\*\*\|WARNING: all dangerous\|cannot read the zone' "$out/n.err" | head -3 | sed 's/^/    native stderr: /' || true
done
echo "$fails failed"
[ "$fails" -eq 0 ]
