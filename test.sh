#!/bin/bash
set -eEo pipefail
# set -x

# Setting NBRPC_TEST_RUN will make script fake checks as instructed.
# Running such fake-checks multiple times with different NBRPC_TEST_TS
#  is used to test how logic of combining these results work in the script/db.
#
# env vars for testing:
#  NBRPC_TEST_RUN=<run.txt-file>
#  NBRPC_TEST_TS=<unix-timestamp>
#  NBRPC_TEST_TZ=<tz-name-for-ZoneInfo> (UTC in tests)
#
# run.txt-file format (default <code> is check success):
#  <hostname>@<ip-addr>[=<code>]


### Scaffolding

[[ $# -eq 0 ]] && opts=( -q ) || opts=( "$@" )

err=1; db_dump() { :; }; policy_dump() { :; }
tmpdir=${XDG_RUNTIME_DIR:-/tmp}
tmpdir=$(mktemp -d "$tmpdir"/.nbrpc-test.XXXXXX)
trap 'db_dump; policy_dump; rm -rf "$tmpdir"; trap "" TERM; kill 0; wait; exit $err' EXIT
trap 'echo "FAILURE at line $LINENO (ts=$ts): $BASH_COMMAND"' ERR
mkdir -p "$tmpdir"

chks="$tmpdir"/checks.txt
db="$tmpdir"/checks.db
run="$tmpdir"/run.txt

# ## Online check to see URL parsing/outputs, uncomment for one-off manual test
# echo >"$chks" httpbin.org:https/status/473=473
# ./nbrpc.py -f "$chks" -d "$db" -SUn9999 -x- --debug
# ./nbrpc.py -f "$chks" -d "$db" -P
# exit

echo >"$chks" test

export NBRPC_TEST_TZ=UTC NBRPC_TEST_RUN="$run"
ts=0 ts_sec=0 # used in error msgs, to id exact failing test
test_run_cmd=(
	./nbrpc.py -f "$chks" -d "$db"
	-i host-na-state=500 # <10min, grace period for na->ok transition
	-i host-ok-state=1000 # <20min, same for ok->na
	-t host-addr=5000 # <100min, to forget not-seen dns addr
	-SUn9999 -x- "${opts[@]}" ) # -n disables other intervals
test_run_opts=()
test_run() {
	[[ -z "$1" ]] || ts=$1
	[[ -z "$2" ]] && ts_sec=0 || ts_sec=$2
	NBRPC_TEST_TS=$(($ts * 61 + $ts_sec)) \
	"${test_run_cmd[@]}" "${test_run_opts[@]}" >"$tmpdir"/out.txt
	test_run_opts=(); }
test_policy() { "${test_run_cmd[@]}" -P >"$tmpdir"/out.txt; }

# policy_dump() { ./nbrpc.py -f "$chks" -d "$db" -P; } # uncomment to enable

# db_dump() { # uncomment to enable
# 	echo; for t in hosts addrs; do echo; echo "=== DB table: $t"
# 	sqlite3 -header -column "$db" 'select * from '"$t"; done; echo; }


### Actual tests
# Unrelated blocks of tests should run "rm -f $db" at the start to flush old host/addr info
# ts= value is used to track progress and report fail position, so increasing throughout these


## Initial states

test_block_init() {

rm -f "$db"; echo >"$chks" test

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0'
test_run 0
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2'
rm "$db"; test_run
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" '0.0.0.5'
rm "$db"; test_run
cat >"$tmpdir"/out.expected.txt <<EOF
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_policy
diff -uB "$tmpdir"/out{.expected,}.txt

}


## Basic ok <-> failure transitions

test_block_basic() {

rm -f "$db"; echo >"$chks" test

# Flapping ok->na->ok addr, with ok->failing->ok host-state

echo >"$run" 'test@0.0.0.1 test@0.0.0.2'
test_run 0
echo >"$run" 'test@0.0.0.1=0 0.0.0.2'
test_run 1
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

test_run 2
test_run 2 10
test_run 2 20

test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https -failing- @ 2001-09-09.01:47]:
  0.0.0.1 :: [2001-09-09.01:47] na
  0.0.0.2 :: [2001-09-09.01:46] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" '0.0.0.1 test@0.0.0.2'
test_run 3
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.01:49]:
  0.0.0.1 :: [2001-09-09.01:49] ok
  0.0.0.2 :: [2001-09-09.01:46] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# Normal ok/na stuff

echo >"$run" 'test@0.0.0.1 0.0.0.2=0'
test_run 10
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 0.0.0.2=0'
test_run 20
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" '0.0.0.1 0.0.0.2 test@0.0.0.3'
test_run 40
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

# Transitions normally despite specific IPs changing state
echo >"$run" 'test@0.0.0.1 0.0.0.2=0 0.0.0.3'
test_run 41
echo >"$run" 'test@0.0.0.1=0 0.0.0.2 0.0.0.3'
test_run 42
echo >"$run" 'test@0.0.0.1 0.0.0.2=0 0.0.0.3'
test_run 43

echo >"$run" 'test@0.0.0.1=0 0.0.0.2 0.0.0.3'
test_run 50
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

# Addr-fail gets forgotten along with addr, but host=blocked sticks until then
echo >"$run" 'test@0.0.0.1 0.0.0.2=0 0.0.0.3'
test_run 51
echo >"$run" 'test@0.0.0.1 0.0.0.2=0 0.0.0.3'
test_run 58
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
echo >"$run" 'test@0.0.0.1 0.0.0.2=0 0.0.0.3'
test_run 80
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
echo >"$run" 'test@0.0.0.1 0.0.0.2=0 0.0.0.3'
test_run 100
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.3 https
EOF
echo >"$run" 'test@0.0.0.1=0 0.0.0.3'
test_run 101
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
echo >"$run" 'test@0.0.0.1 0.0.0.3=0'
test_run 120
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.03:48]:
  0.0.0.1 :: [2001-09-09.03:48] ok
  0.0.0.3 :: [2001-09-09.03:48] na
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_run 140
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.04:09]:
  0.0.0.1 :: [2001-09-09.03:48] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# ok->na transition delay
echo >"$run" 'test@0.0.0.1=0'
test_run 150
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
EOF
test_run 160
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
EOF

}


## Alt-route checks and failing/unstable states

test_block_altroute() {

rm -f "$db"; echo >"$chks" test
echo >"$run" 'test@0.0.0.1'
test_run 180

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@0.0.0.3'
test_run 200
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

# test1: failing -> blocked if alt-route check works

echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2=0 test@0.0.0.3'
test_run 201; test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https -failing- @ 2001-09-09.05:11]:
  0.0.0.1 :: [2001-09-09.05:11] na
  0.0.0.2 :: [2001-09-09.05:11] na
  0.0.0.3 :: [2001-09-09.05:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# One workaround check succeeds, "ok" addr untouched, host will be blocked
echo >"$run" '0.0.0.1 test@0.0.0.2=0 test@0.0.0.3=0'
test_run_opts+=( -F ); test_run 207; test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https -failing- @ 2001-09-09.05:11]:
  0.0.0.1 :: [2001-09-09.05:11] na
  0.0.0.2 :: [2001-09-09.05:11] na
  0.0.0.3 :: [2001-09-09.05:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" '0.0.0.1=0 test@0.0.0.2=0 test@0.0.0.3'
test_run 211; test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.05:21]:
  0.0.0.1 :: [2001-09-09.05:11] na
  0.0.0.2 :: [2001-09-09.05:11] na
  0.0.0.3 :: [2001-09-09.05:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# When legit-na addr forgotten, blocked state stays in place
# Because alt-route checks are only done for state=failing hosts
test_run_opts+=( -F ); test_run 299
test_run 300; test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.05:21]:
  0.0.0.2 :: [2001-09-09.05:11] na
  0.0.0.3 :: [2001-09-09.05:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# test2: failing->unstable if alt-route checks fail too

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@0.0.0.3'
test_run 301

echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2=0 0.0.0.3'
test_run 302; test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https -failing- @ 2001-09-09.06:53]:
  0.0.0.1 :: [2001-09-09.06:53] na
  0.0.0.2 :: [2001-09-09.06:53] na
  0.0.0.3 :: [2001-09-09.05:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

test_run_opts+=( -F ); test_run 308

test_run 312; test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https /unstable/ @ 2001-09-09.07:03]:
  0.0.0.1 :: [2001-09-09.06:53] na
  0.0.0.2 :: [2001-09-09.06:53] na
  0.0.0.3 :: [2001-09-09.05:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# still unstable after last "ok" forgotten
echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2=0 0.0.0.3'
test_run_opts+=( -F ); test_run 400
test_run 401
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https /unstable/ @ 2001-09-09.08:34]:
  0.0.0.1 :: [2001-09-09.06:53] na
  0.0.0.2 :: [2001-09-09.06:53] na
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# unstable -> na
cp -a "$db"{,.bak}
echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2=0'
test_run 410
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

# unstable -> ok
mv "$db"{.bak,}
echo >"$run" 'test@0.0.0.1 test@0.0.0.2'
test_run 411
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.08:44]:
  0.0.0.1 :: [2001-09-09.08:44] ok
  0.0.0.2 :: [2001-09-09.08:44] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# test3: individual addrs flapping on the other side

echo >"$run" 'test@0.0.0.1 test@0.0.0.2'
test_run 412
test_run 420
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2=0'
test_run 421

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0'
test_run_opts+=( -F ); test_run 427
echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2'
test_run_opts+=( -F ); test_run 428

echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2=0'
test_run 430
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https /unstable/ @ 2001-09-09.09:03]:
  0.0.0.1 :: [2001-09-09.08:54] na
  0.0.0.2 :: [2001-09-09.08:54] na
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

}


## Default AF failure policy

test_block_afs() {

rm -f "$db"; echo >"$chks" test

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::1 test@1::2'
rm -f "$db"; test_run 450
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::1 https
ok test 1::2 https
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::1=0 test@1::2'
rm -f "$db"; test_run 451
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 1::1 https
na test 1::2 https
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::1 test@1::2=0'
rm -f "$db"; test_run 452
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::1 https
ok test 1::2 https
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

}


## DNS zone exports

test_block_zone() {

rm -f "$db"
echo >"$chks" 'test>6' # -Z flags should always override that

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3'
rm -f "$db"; test_run 500
test_run_opts+=( -Z@. ); test_run
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
local-data: 'test A 0.0.0.2'
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3'
rm -f "$db"; test_run 501
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.10:16]:
  0.0.0.1 :: [2001-09-09.10:16] ok
  0.0.0.2 :: [2001-09-09.10:16] na
  1::3 :: [2001-09-09.10:16] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

test_run_opts+=( -Z@. ); test_run 502
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
local-data: 'test A 0.0.0.2'
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

test_run_opts+=( '-Z>.' ); test_run 503
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

test_run_opts+=( '-Z>+.' ); test_run 504
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_run_opts+=( '-Z+>>.' ); test_run 505
diff -uB "$tmpdir"/out{.expected,}.txt

test_run_opts+=( '-Z*^.' ); test_run 506
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" '0.0.0.1 test@0.0.0.2=0 test@1::3'
test_run 511
test_run_opts+=( '-Z@.' ); test_run 512
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.2'
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_run_opts+=( '-Z*@.' ); test_run 513
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" '0.0.0.1 test@0.0.0.2=0 1::3'
test_run 514
test_run_opts+=( '-Z@.' ); test_run 515
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.2'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_run_opts+=( '-Z@*.' ); test_run 516
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

}


## Per-host DNS options

test_block_zone_policy() {

rm -f "$db"
echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3=0 test@1::4'

echo >"$chks" 'test>4'
test_run 520; test_run_opts+=( -Z. ); test_run 520
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
local-data: 'test A 0.0.0.2'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$chks" 'test>6'
test_run 521; test_run_opts+=( -Z. ); test_run 521
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test AAAA 1::3'
local-data: 'test AAAA 1::4'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$chks" 'test>D4'
test_run 522; test_run_opts+=( -Z. ); test_run 522
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$chks" 'test>6LN'
test_run 523; test_run_opts+=( -Z. ); test_run 523
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$chks" 'test>L'
echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3=0 test@1::4'
test_run 524
echo >"$run" '0.0.0.1 test@0.0.0.2=0 1::3=0 test@1::4'
test_run 525; test_run_opts+=( -Z. ); test_run 525
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.2'
local-data: 'test AAAA 1::4'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

}


## Rerouting policy

test_block_reroute_policy() {

test_block_reroute_policy_afany() {
local ts_base=$1

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4'
test_run $(($ts_base + 0))
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3 test@1::4'
test_run $(($ts_base + 1))
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3 test@1::4'
test_run $(($ts_base + 10))
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3=0 test@1::4'
test_run $(($ts_base + 11))
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3=0 test@1::4'
test_run $(($ts_base + 20))
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4=0'
test_run $(($ts_base + 21))
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4=0'
test_run $(($ts_base + 30))
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4=0'
test_run $(($ts_base + 40))
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

}

# policy = af-any default

rm -f "$db"; echo >"$chks" 'test'
test_block_reroute_policy_afany 550
rm -f "$db"; echo >"$chks" 'test>af-any'
test_block_reroute_policy_afany 600

# policy = af-all

rm -f "$db"; echo >"$chks" 'test>af-all'
echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4=0'
test_run 650
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

rm -f "$db"
echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4'
test_run 670
echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3=0 test@1::4'
test_run 671; test_run 680
diff -u "$tmpdir"/out{.expected,}.txt

# policy = af-pick

rm -f "$db"; echo >"$chks" 'test>af-pick'
echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3 test@1::4'
test_run 700
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.13:38]:
  0.0.0.1 :: [2001-09-09.13:38] ok
  0.0.0.2 :: [2001-09-09.13:38] na
  1::3 :: [2001-09-09.13:38] ok
  1::4 :: [2001-09-09.13:38] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3=0 test@1::4'
test_run 701; test_run 710
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.2 https
na test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.13:38]:
  0.0.0.1 :: [2001-09-09.13:38] ok
  0.0.0.2 :: [2001-09-09.13:38] na
  1::3 :: [2001-09-09.13:39] na
  1::4 :: [2001-09-09.13:38] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4=0'
test_run 711; test_run 730
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
na test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.13:38]:
  0.0.0.1 :: [2001-09-09.13:38] ok
  0.0.0.2 :: [2001-09-09.13:49] ok
  1::3 :: [2001-09-09.13:49] ok
  1::4 :: [2001-09-09.13:49] na
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4'
test_run 750
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.14:29]:
  0.0.0.1 :: [2001-09-09.13:38] ok
  0.0.0.2 :: [2001-09-09.13:49] ok
  1::3 :: [2001-09-09.13:49] ok
  1::4 :: [2001-09-09.14:29] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# policy = pick

rm -f "$db"; echo >"$chks" 'test>pick'
echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4=0'
test_run 800
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
na test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.15:20]:
  0.0.0.1 :: [2001-09-09.15:20] ok
  0.0.0.2 :: [2001-09-09.15:20] ok
  1::3 :: [2001-09-09.15:20] ok
  1::4 :: [2001-09-09.15:20] na
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1=0 test@0.0.0.2 test@1::3=0 test@1::4'
test_run 801
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
ok test 0.0.0.2 https
na test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt

echo >"$run" 'test@0.0.0.1 test@0.0.0.2 test@1::3 test@1::4'
test_run 802
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https blocked @ 2001-09-09.15:20]:
  0.0.0.1 :: [2001-09-09.15:22] ok
  0.0.0.2 :: [2001-09-09.15:20] ok
  1::3 :: [2001-09-09.15:22] ok
  1::4 :: [2001-09-09.15:21] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_run 820
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.15:40]:
  0.0.0.1 :: [2001-09-09.15:22] ok
  0.0.0.2 :: [2001-09-09.15:20] ok
  1::3 :: [2001-09-09.15:22] ok
  1::4 :: [2001-09-09.15:21] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

# policy = noroute

rm -f "$db"; echo >"$chks" 'test>noroute'
echo >"$run" 'test@0.0.0.1 test@0.0.0.2=0 test@1::3 test@1::4=0'
test_run 830
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
ok test 1::3 https
ok test 1::4 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [https OK @ 2001-09-09.15:50]:
  0.0.0.1 :: [2001-09-09.15:50] ok
  0.0.0.2 :: [2001-09-09.15:50] na
  1::3 :: [2001-09-09.15:50] ok
  1::4 :: [2001-09-09.15:50] na
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

}


## No-op type=dns checks

test_block_type_dns() {

rm -f "$db"; echo >"$chks" 'test:dns'
echo >"$run" 'test@0.0.0.1=0 test@1::2 test@1::3=0'
test_run 850
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 dns
ok test 1::2 dns
ok test 1::3 dns
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_policy
cat >"$tmpdir"/out.expected.txt <<EOF
test [dns OK @ 2001-09-09.16:10]:
  0.0.0.1 :: [2001-09-09.16:10] ok
  1::2 :: [2001-09-09.16:10] ok
  1::3 :: [2001-09-09.16:10] ok
EOF
diff -uB "$tmpdir"/out{.expected,}.txt
test_run_opts+=( -Z. ); test_run 851
cat >"$tmpdir"/out.expected.txt <<EOF
local-zone: test. static
local-data: 'test A 0.0.0.1'
local-data: 'test AAAA 1::2'
local-data: 'test AAAA 1::3'
EOF
diff -uB "$tmpdir"/out{.expected,}.txt

}


### Run all test blocks from above
# Split into blocks to make it easy to re-run only specific block of linked tests

test_block_init
test_block_basic
test_block_altroute
test_block_afs
test_block_zone
test_block_zone_policy
test_block_reroute_policy
test_block_type_dns

err=0 # success for all tests above
