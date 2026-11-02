#!/bin/sh
# NetCrack privileged launcher.
#
# Runs as root exactly once, inside the single "administrator privileges" prompt
# that NetCrack shows. Its only job is to get the long-lived supervisor
# (daemon.sh) running in a context that survives this script exiting.
#
# Two mechanisms, in order:
#   1. A LaunchDaemon. launchd owns the process, so it cannot be reaped when the
#      authorisation that started it goes away. This is the supported way to run
#      a root daemon on macOS.
#   2. A detached nohup child, for machines where launchctl refuses (managed
#      Macs, restricted profiles). Kept as a fallback, not as the default.
#
# Usage: launch.sh <session-dir> <uid> <gid> <idle-seconds> <lifetime-seconds>
#
# Always exits 0. Everything it learns goes to stdout *and* to
# <session-dir>/launch.log, so the app can report the real reason instead of
# "did not start".

DIR="$1"
OWNER_UID="${2:-0}"
OWNER_GID="${3:-0}"
IDLE_LIMIT="${4:-1800}"
LIFETIME="${5:-21600}"

LABEL="com.netcrack.helper"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
PLIST_SRC="$DIR/$LABEL.plist"
DAEMON="$DIR/daemon.sh"
LOG="$DIR/launch.log"
DAEMON_LOG="$DIR/daemon.log"
HEARTBEAT="$DIR/alive"

[ -n "$DIR" ] && [ -d "$DIR" ] || {
  echo "FATAL: session directory '$DIR' is missing"
  exit 0
}

handback() {
  [ -e "$1" ] || return 0
  chown "$OWNER_UID:$OWNER_GID" "$1" 2>/dev/null
  chmod 644 "$1" 2>/dev/null
}

# Waits for the supervisor's heartbeat. Removes any stale heartbeat first, so a
# leftover file from a dead session can never be mistaken for a live helper.
wait_for_heartbeat() {
  attempts="$1"
  i=0
  while [ "$i" -lt "$attempts" ]; do
    [ -f "$HEARTBEAT" ] && return 0
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

attempt_launchd() {
  [ -x /bin/launchctl ] || { echo "launchd: /bin/launchctl missing"; return 1; }
  [ -f "$PLIST_SRC" ] || { echo "launchd: $PLIST_SRC missing"; return 1; }

  echo "launchd: installing $PLIST"
  /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1
  rm -f "$PLIST"

  if ! install -o root -g wheel -m 644 "$PLIST_SRC" "$PLIST"; then
    echo "launchd: could not install the plist"
    return 1
  fi

  if ! /bin/launchctl bootstrap system "$PLIST"; then
    echo "launchd: bootstrap failed"
    /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1
    rm -f "$PLIST"
    return 1
  fi

  if wait_for_heartbeat 80; then
    echo "launchd: helper is alive"
    return 0
  fi

  echo "launchd: bootstrap succeeded but no heartbeat appeared within 20 s"
  /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1
  rm -f "$PLIST"
  return 1
}

# `launchctl submit` is deprecated but still present, and unlike bootstrap it
# needs no file in /Library/LaunchDaemons. Useful when a managed Mac refuses to
# let the app install a property list.
attempt_submit() {
  [ -x /bin/launchctl ] || { echo "submit: /bin/launchctl missing"; return 1; }
  # A submitted system job has to be created by root; as anyone else launchctl
  # would quietly put it in a user domain this supervisor cannot serve.
  [ "$(id -u)" = "0" ] || { echo "submit: needs root, skipping"; return 1; }

  echo "submit: handing the supervisor to launchd without a plist"
  /bin/launchctl remove "$LABEL" >/dev/null 2>&1
  if ! /bin/launchctl submit -l "$LABEL" -o "$DAEMON_LOG" -e "$DAEMON_LOG" -- \
    /bin/sh "$DAEMON" "$DIR" "$IDLE_LIMIT" "$LIFETIME" "$OWNER_UID" "$OWNER_GID"; then
    echo "submit: launchctl submit failed"
    return 1
  fi

  if wait_for_heartbeat 60; then
    echo "submit: helper is alive"
    return 0
  fi

  echo "submit: no heartbeat appeared within 15 s"
  /bin/launchctl remove "$LABEL" >/dev/null 2>&1
  return 1
}

attempt_nohup() {
  echo "nohup: starting a detached supervisor"
  rm -f "$PLIST"
  # The child must not keep this script's stdout open, or `do shell script`
  # would wait for it forever. Both streams go to the daemon log instead.
  nohup /bin/sh "$DAEMON" "$DIR" "$IDLE_LIMIT" "$LIFETIME" "$OWNER_UID" "$OWNER_GID" \
    </dev/null >>"$DAEMON_LOG" 2>&1 &

  if wait_for_heartbeat 60; then
    echo "nohup: helper is alive"
    return 0
  fi

  echo "nohup: no heartbeat appeared within 15 s"
  return 1
}

main() {
  echo "=== NetCrack launch $(date '+%Y-%m-%d %H:%M:%S')"
  echo "uid=$(id -u) dir=$DIR idle=$IDLE_LIMIT lifetime=$LIFETIME"

  if [ "$(id -u)" != "0" ]; then
    echo "WARNING: not running as root (uid $(id -u)); launchd will refuse"
  fi

  # Never trust a heartbeat that a dead session left behind.
  rm -f "$HEARTBEAT"
  pkill -f "daemon.sh $DIR" 2>/dev/null

  MODE=""
  if attempt_launchd; then
    MODE=launchd
  elif attempt_submit; then
    MODE=submit
  elif attempt_nohup; then
    MODE=nohup
  fi

  if [ -n "$MODE" ]; then
    handback "$HEARTBEAT"
    handback "$DAEMON_LOG"
    echo "MODE=$MODE"
    echo "RESULT=ok"
    return 0
  fi

  echo "RESULT=failed"
  echo "--- session directory"
  ls -la "$DIR" 2>&1
  echo "--- daemon log (tail)"
  tail -40 "$DAEMON_LOG" 2>&1
  return 0
}

main 2>&1 | tee -a "$LOG"
handback "$LOG"
exit 0
