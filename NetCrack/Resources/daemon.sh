#!/bin/sh
# NetCrack privileged command supervisor.
#
# Started exactly once per authorisation, as root, by launch.sh. It owns the
# session directory and runs root commands handed to it through a file
# protocol, so the app never has to ask for a password twice.
#
# Usage: daemon.sh <session-dir> <idle-seconds> <lifetime-seconds> <uid> <gid>
#
# Protocol, inside <session-dir>:
#   alive          heartbeat, rewritten every 2 s; delete it to shut down
#   <id>.cmd       command for the supervisor to run (appears atomically)
#   <id>.out       merged stdout+stderr
#   <id>.code      exit status, written when the command finishes
#   <id>.pid       PID of the shell running the command
#   <id>.kill      line 1: signal, line 2: pkill -f pattern
#   <id>.killed    acknowledgement of a kill request
#
# Everything it creates is handed back to the app's user, so the UI needs no
# privileges of its own to read the output or clean up.

DIR="$1"
IDLE_LIMIT="${2:-1800}"
LIFETIME="${3:-21600}"
OWNER_UID="${4:-0}"
OWNER_GID="${5:-0}"

HEARTBEAT="$DIR/alive"
LOG="$DIR/daemon.log"
LABEL="com.netcrack.helper"
PLIST="/Library/LaunchDaemons/$LABEL.plist"

[ -n "$DIR" ] && [ -d "$DIR" ] || exit 1
umask 022

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG" 2>/dev/null
}

# Give a file back to the user who owns the session, so the app can always
# read it (output) or remove it (heartbeat) without being root.
handback() {
  [ -e "$1" ] || return 0
  chown "$OWNER_UID:$OWNER_GID" "$1" 2>/dev/null
  chmod 644 "$1" 2>/dev/null
}

chown "$OWNER_UID:$OWNER_GID" "$DIR" 2>/dev/null
chmod 700 "$DIR" 2>/dev/null

log "supervisor start pid=$$ uid=$(id -u) dir=$DIR idle=$IDLE_LIMIT lifetime=$LIFETIME"

: >"$HEARTBEAT" 2>/dev/null || {
  log "FATAL: cannot write $HEARTBEAT"
  exit 1
}
handback "$HEARTBEAT"
log "heartbeat: $HEARTBEAT"

START=$(date +%s)
LAST_ACTIVITY=$START
LAST_TOUCH=0

while :; do
  NOW=$(date +%s)

  # The app removes the heartbeat to ask the supervisor to exit.
  [ -f "$HEARTBEAT" ] || break

  if [ $((NOW - LAST_TOUCH)) -ge 2 ]; then
    : >"$HEARTBEAT" 2>/dev/null || break
    LAST_TOUCH=$NOW
  fi

  for cmd in "$DIR"/*.cmd; do
    [ -e "$cmd" ] || continue
    base=${cmd##*/}
    id=${base%.cmd}
    run="$DIR/$id.run"
    mv "$cmd" "$run" 2>/dev/null || continue
    : >"$DIR/$id.out"
    handback "$DIR/$id.out"
    log "run $id: $(sed -n '1p' "$run" 2>/dev/null | cut -c1-160)"
    (
      /bin/sh "$run" >"$DIR/$id.out" 2>&1
      status=$?
      echo "$status" >"$DIR/$id.code"
      handback "$DIR/$id.out"
      handback "$DIR/$id.code"
      handback "$DIR/$id.pid"
      rm -f "$run"
      log "done $id: exit $status"
    ) &
    LAST_ACTIVITY=$NOW
  done

  for killfile in "$DIR"/*.kill; do
    [ -e "$killfile" ] || continue
    base=${killfile##*/}
    id=${base%.kill}
    SIG=$(sed -n '1p' "$killfile" 2>/dev/null)
    PATTERN=$(sed -n '2p' "$killfile" 2>/dev/null)
    [ -n "$SIG" ] || SIG=TERM
    log "kill $id: signal $SIG pattern '$PATTERN'"
    if [ -n "$PATTERN" ]; then
      pkill -"$SIG" -f "$PATTERN" 2>/dev/null
    fi
    if [ -f "$DIR/$id.pid" ]; then
      kill -"$SIG" "$(cat "$DIR/$id.pid" 2>/dev/null)" 2>/dev/null
    fi
    mv "$killfile" "$DIR/$id.killed" 2>/dev/null
    handback "$DIR/$id.killed"
    LAST_ACTIVITY=$NOW
  done

  # A command that is still running keeps the session alive even when the app
  # looks idle.
  for running in "$DIR"/*.run; do
    [ -e "$running" ] || continue
    LAST_ACTIVITY=$NOW
    break
  done

  if [ $((NOW - LAST_ACTIVITY)) -gt "$IDLE_LIMIT" ]; then
    log "idle for $IDLE_LIMIT s, shutting down"
    break
  fi
  if [ $((NOW - START)) -gt "$LIFETIME" ]; then
    log "lifetime $LIFETIME s reached, shutting down"
    break
  fi

  sleep 1
done

log "supervisor exit pid=$$"
rm -f "$HEARTBEAT"

# Remove the LaunchDaemon so nothing comes back after a reboot. Booting the job
# out terminates this process, so it has to happen in the background, after the
# plist is already gone.
if [ -f "$PLIST" ]; then
  rm -f "$PLIST"
  ( /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 & )
fi
# A supervisor handed over with `launchctl submit` has no property list, so the
# job is removed by label instead. Harmless when there is no such job.
( /bin/launchctl remove "$LABEL" >/dev/null 2>&1 & )

exit 0
