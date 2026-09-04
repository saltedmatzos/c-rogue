#!/bin/sh
# rogue-watchdog — HEALTH-ONLY. Reports, never restarts.
# Design (PV-001 Q3): external init (OpenRC/s6/systemd) supervises and decides
# restarts. The watchdog only checks: (1) pid alive, (2) heartbeat fresh.
# Exit 0 = healthy, 1 = unhealthy (init reacts), 3 = usage.

PIDFILE="${ROGUE_PIDFILE:-/run/rogue.pid}"
HEARTBEAT="${ROGUE_HEARTBEAT:-/run/rogue.heartbeat}"
MAX_AGE_S="${ROGUE_MAX_AGE_S:-120}"

if [ ! -f "$PIDFILE" ]; then
    echo "rogue-watchdog: no pidfile $PIDFILE" >&2
    exit 1
fi

pid=$(cat "$PIDFILE" 2>/dev/null) || { echo "rogue-watchdog: unreadable pidfile" >&2; exit 1; }

# pgrep lesson (Jaakko, PV-001): match exact pid, not a -f pattern.
if ! kill -0 "$pid" 2>/dev/null; then
    echo "rogue-watchdog: pid $pid not alive" >&2
    exit 1
fi

if [ ! -f "$HEARTBEAT" ]; then
    echo "rogue-watchdog: no heartbeat $HEARTBEAT" >&2
    exit 1
fi

now=$(date +%s)
hb=$(cat "$HEARTBEAT" 2>/dev/null) || { echo "rogue-watchdog: unreadable heartbeat" >&2; exit 1; }
age=$((now - hb))

if [ "$age" -gt "$MAX_AGE_S" ]; then
    echo "rogue-watchdog: heartbeat stale ${age}s (>${MAX_AGE_S}s)" >&2
    exit 1
fi

echo "rogue-watchdog: healthy (pid $pid, heartbeat ${age}s)"
exit 0