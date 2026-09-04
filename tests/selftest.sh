#!/bin/sh
# selftest for rogue v0.1 — fetch/verify only, never publishes.
set -u
cd "$(dirname "$0")/.." || exit 1

fail=0
ok()   { echo "ok   - $1"; }
bad()  { echo "FAIL - $1"; fail=1; }

# 1. binary exists
[ -x ./rogue ] || { echo "FAIL - rogue binary missing (run make first)"; exit 1; }
ok "binary present"

# 2. fetch against the live relay (read-only). Requires ROGUE_NAK.
export ROGUE_NAK="${ROGUE_NAK:-$(command -v nak)}"
if [ -n "$ROGUE_NAK" ] && [ -x "$ROGUE_NAK" ]; then
    out=$(./rogue fetch --limit 2 2>&1)
    rc=$?
    if [ $rc -eq 0 ] && [ -n "$out" ]; then
        ok "fetch: got events from relay"
    else
        bad "fetch rc=$rc out=${out:-empty}"
    fi
    # inbox log must exist and be non-empty
    [ -s ./data/inbox.jsonl ] && ok "inbox.jsonl appended" || bad "inbox.jsonl empty/missing"
else
    bad "nak not found — set ROGUE_NAK"
fi

# 3. verify gate on a known-invalid event (must NOT pass)
if ! ./rogue verify '{"kind":1,"id":"deadbeef"}' 2>/dev/null; then
    ok "verify rejects malformed event"
else
    bad "verify accepted malformed event"
fi

# 4. watchdog script syntax + unhealthy exit
sh -n ./scripts/watchdog.sh || bad "watchdog.sh syntax"
if ROGUE_PIDFILE=/nonexistent ./scripts/watchdog.sh >/dev/null 2>&1; then
    bad "watchdog should fail without pidfile"
else
    ok "watchdog health-only: fails cleanly without pidfile"
fi

echo
[ $fail -eq 0 ] && echo "SELFTEST PASS" || { echo "SELFTEST FAIL"; exit 1; }
exit 0