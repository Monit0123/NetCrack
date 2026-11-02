#!/bin/sh
# Exercises the privileged helper's file protocol without needing root.
#
# The one thing this cannot test is the administrator prompt itself — that needs
# a logged-in GUI session. Everything downstream of it is covered here: the
# launcher's fallback path, the heartbeat, command execution, exit codes,
# cancellation and shutdown.
#
# Usage: Scripts/test-helper.sh   (exit 0 = everything works)

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAEMON_SRC="$ROOT/NetCrack/Resources/daemon.sh"
LAUNCH_SRC="$ROOT/NetCrack/Resources/launch.sh"

FAILURES=0
CHECK_COUNT=0

pass() {
  CHECK_COUNT=$((CHECK_COUNT + 1))
  printf '  ok    %s\n' "$1"
}

fail() {
  CHECK_COUNT=$((CHECK_COUNT + 1))
  FAILURES=$((FAILURES + 1))
  printf '  FAIL  %s\n' "$1"
}

check() {
  # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then
    pass "$1"
  else
    fail "$1 (expected '$2', got '$3')"
  fi
}

mtime() {
  # GNU stat first, then BSD/macOS: on Linux `stat -f` means "filesystem", so the
  # BSD form cannot simply be tried first.
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0
}

wait_for() {
  # wait_for <file> <attempts>   (0.1 s each)
  i=0
  while [ "$i" -lt "$2" ]; do
    [ -e "$1" ] && return 0
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

cleanup() {
  if [ -n "${DIR:-}" ] && [ -d "$DIR" ]; then
    rm -f "$DIR/alive"
    sleep 0.2
    pkill -f "daemon.sh $DIR" 2>/dev/null
    rm -rf "$DIR"
  fi
}
trap cleanup EXIT INT TERM

for script in "$DAEMON_SRC" "$LAUNCH_SRC"; do
  [ -f "$script" ] || {
    echo "missing $script"
    exit 1
  }
  sh -n "$script" || {
    echo "$script has a syntax error"
    exit 1
  }
done

echo "helper protocol test"
echo "  scripts: $(cd "$(dirname "$DAEMON_SRC")" && pwd)"

BASE=$(mktemp -d "${TMPDIR:-/tmp}/netcrack-helper-test.XXXXXX") || exit 1
DIR="$BASE/rootsession"
mkdir -p "$DIR"
chmod 700 "$DIR"
cp "$DAEMON_SRC" "$DIR/daemon.sh"
cp "$LAUNCH_SRC" "$DIR/launch.sh"
chmod 755 "$DIR/daemon.sh" "$DIR/launch.sh"
# A stand-in for the LaunchDaemon the app writes; launchd is not available to an
# unprivileged test, so the launcher must fall back on its own.
cat >"$DIR/com.netcrack.helper.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.netcrack.helper</string></dict></plist>
PLIST

echo
echo "launcher"
OUTPUT=$(sh "$DIR/launch.sh" "$DIR" "$(id -u)" "$(id -g)" 120 600 2>&1)
echo "$OUTPUT" | sed 's/^/  | /'
echo "$OUTPUT" | grep -q "RESULT=ok" && pass "launcher reports success" || fail "launcher did not report RESULT=ok"
wait_for "$DIR/alive" 50 && pass "heartbeat appeared" || fail "no heartbeat after launch"

echo
echo "command execution"
printf 'echo $$ > "%s/basic.pid"\necho first\necho second\n' "$DIR" >"$DIR/basic.cmd"
wait_for "$DIR/basic.code" 100 && pass "exit status written" || fail "no exit status"
check "exit code" "0" "$(cat "$DIR/basic.code" 2>/dev/null | tr -d '[:space:]')"
check "stdout captured" "first
second" "$(cat "$DIR/basic.out" 2>/dev/null | tr -d '\r')"

echo
echo "failure propagation"
printf 'echo boom >&2\nexit 7\n' "$DIR" >"$DIR/failing.cmd"
wait_for "$DIR/failing.code" 100 && pass "failed command completes" || fail "failed command hung"
check "exit code" "7" "$(cat "$DIR/failing.code" 2>/dev/null | tr -d '[:space:]')"
check "stderr merged into output" "boom" "$(cat "$DIR/failing.out" 2>/dev/null | tr -d '\r')"

echo
echo "heartbeat"
BEFORE=$(mtime "$DIR/alive")
sleep 3
AFTER=$(mtime "$DIR/alive")
[ "$AFTER" -gt "$BEFORE" ] && pass "heartbeat refreshes" || fail "heartbeat stopped ($BEFORE -> $AFTER)"

echo
echo "cancellation"
printf 'echo $$ > "%s/long.pid"\necho running\nexec sleep 120\n' "$DIR" >"$DIR/long.cmd"
wait_for "$DIR/long.pid" 100 && pass "long command started" || fail "long command did not start"
sleep 0.5
printf 'TERM\n\n' >"$DIR/long.kill"
wait_for "$DIR/long.killed" 50 && pass "kill acknowledged" || fail "kill not acknowledged"
sleep 0.5
if pgrep -f "sleep 120" >/dev/null 2>&1; then
  fail "command still running after TERM"
else
  pass "command stopped"
fi

echo
echo "shutdown"
rm -f "$DIR/alive"
sleep 4
if pgrep -f "daemon.sh $DIR" >/dev/null 2>&1; then
  fail "supervisor still running after the heartbeat was removed"
else
  pass "supervisor exits when the heartbeat is removed"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "PASS — $CHECK_COUNT checks"
  exit 0
fi
echo "FAIL — $FAILURES of $CHECK_COUNT checks failed"
exit 1
