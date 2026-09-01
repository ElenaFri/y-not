#!/bin/sh
# CLI-level regression tests: exercise the compiled y-not binary end-to-end
# (argument parsing, exit codes), which the C unit tests never touch since
# they link directly against the library functions instead of main.c.
set -u

BIN="${Y_NOT_BIN:-./y-not}"
RUN=0
FAIL=0

pass() { RUN=$((RUN + 1)); echo "ok    $1"; }
fail() { RUN=$((RUN + 1)); FAIL=$((FAIL + 1)); echo "FAIL  $1"; }

expect_exit() {
    desc="$1"; expected="$2"; shift 2
    "$@" >/dev/null 2>&1
    actual=$?
    if [ "$actual" -eq "$expected" ]; then pass "$desc"; else fail "$desc (expected exit $expected, got $actual)"; fi
}

expect_contains() {
    desc="$1"; needle="$2"; shift 2
    out=$("$@" 2>&1)
    case "$out" in
        *"$needle"*) pass "$desc" ;;
        *) fail "$desc (output did not contain: $needle)" ;;
    esac
}

USER_NAME=$(id -un)

# Argument count
expect_exit "no arguments"       1 "$BIN"
expect_exit "one argument"       1 "$BIN" "$USER_NAME"
expect_exit "too many arguments" 1 "$BIN" "$USER_NAME" read /etc/hosts extra

# Unknown operation / unknown user
expect_exit "unknown operation" 1 "$BIN" "$USER_NAME" frobnicate /etc/hosts
expect_exit "unknown user"      1 "$BIN" __y_not_no_such_user__ read /etc/hosts

# Every operation alias must be accepted (long and short form)
expect_exit "operation alias: read"    0 "$BIN" "$USER_NAME" read    /usr/bin/ls
expect_exit "operation alias: r"       0 "$BIN" "$USER_NAME" r       /usr/bin/ls
expect_exit "operation alias: execute" 0 "$BIN" "$USER_NAME" execute /usr/bin/ls
expect_exit "operation alias: x"       0 "$BIN" "$USER_NAME" x       /usr/bin/ls

# Exit code contract: 0 = allowed, 1 = denied (scripts rely on this)
expect_exit "denied path exits 1" 1 "$BIN" "$USER_NAME" read /var/__y_not_no_such_path__
expect_contains "denied path explains why" "no such file or directory" \
    "$BIN" "$USER_NAME" read /var/__y_not_no_such_path__

# A pathologically long path argument must be rejected cleanly, not crash
long_path="/"
i=0
while [ "$i" -lt 600 ]; do
    long_path="${long_path}aaaaaaa/"
    i=$((i + 1))
done
expect_exit "path longer than PATH_MAX is rejected, not a crash" 1 "$BIN" "$USER_NAME" read "$long_path"


echo
echo "$((RUN - FAIL))/$RUN passed"
[ "$FAIL" -eq 0 ]
