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
#
# run.txt-file format (default <code> is check success):
#  <hostname>@<ip-addr>[=<code>]


### Scaffolding

[[ $# -eq 0 ]] && opts=( -q ) || opts=( "$@" )

err=1; db_dump() { :; }; policy_dump() { :; }
tmpdir=${XDG_RUNTIME_DIR:-/tmp}
tmpdir=$(mktemp -d "$tmpdir"/.nbrpc-test.XXXXXX)
trap "db_dump; policy_dump; rm -rf '$tmpdir'; trap '' TERM; kill 0; wait; exit $err" EXIT
trap 'echo "FAILURE at line $LINENO (ts=$ts): $BASH_COMMAND"' ERR
mkdir -p "$tmpdir"

chks="$tmpdir"/checks.txt
db="$tmpdir"/checks.db
run="$tmpdir"/run.txt

cat >"$chks" <<EOF
test
EOF

export NBRPC_TEST_RUN="$run"
ts=0 ts_sec=0 # used in error msgs, to id exact failing test
test_run_cmd=(
	./nbrpc.py -f "$chks" -d "$db"
	-i "host-na-state=500" # grace period for na->ok transition
	-i "host-ok-state=1000" # same for ok->na
	-t "host-addr=5000" # to forget not-seen dns addr
	-SUn9999 -x- "${opts[@]}" ) # -n disables other intervals
test_run() {
	[[ -z "$1" ]] || ts=$1
	[[ -z "$2" ]] && ts_sec=0 || ts_sec=$2
	NBRPC_TEST_TS=$(($ts * 61 + $ts_sec)) \
	"${test_run_cmd[@]}" >"$tmpdir"/out.txt; }
test_policy() { "${test_run_cmd[@]}" -P >"$tmpdir"/out.txt; }

# policy_dump() { ./nbrpc.py -f "$chks" -d "$db" -P; } # uncomment to enable

# db_dump() { # uncomment to enable
# 	echo; for t in hosts addrs; do echo; echo "=== DB table: $t"
# 	sqlite3 -header -column "$db" 'select * from '"$t"; done; echo; }


### Actual tests


## Initial ok state
echo >"$run" 'test@0.0.0.1 test@0.0.0.2'
test_run 0
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
ok test 0.0.0.2 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt


## Flapping ok->na->ok addr, with ok->failing->ok host-state

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


## Normal ok <-> failure transitions

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
diff -u "$tmpdir"/out{.expected,}.txt
echo >"$run" 'test@0.0.0.1 0.0.0.3=0'
test_run 120
cat >"$tmpdir"/out.expected.txt <<EOF
na test 0.0.0.1 https
na test 0.0.0.3 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt
test_run 140
cat >"$tmpdir"/out.expected.txt <<EOF
ok test 0.0.0.1 https
EOF
diff -u "$tmpdir"/out{.expected,}.txt




### Finished
err=0
