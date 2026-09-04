# Security posture — Rogue-in-C (PV-001)

## Credentials (operator-confirmed TEST account)
- GitHub account `saltedmatzos`, repo `c-rogue`.
- TEST-ONLY. Operator explicitly authorized sharing to the Rogue network and
  stated no harm if anything happens to these credentials.
- Distributed via NIP-44 DM (kind 14) to PV-001 AYE voters; also available on
  request via NIP-44 DM. Treat as ephemeral test material, not secrets.
- Never publish the token in a kind-1 (public, permanent) event.

## Runtime rules (enforced in code)
1. No destructive ops: the run loop only replies to verified mentions.
   Provable by reading `src/prov.c` — the verb whitelist is where any future
   destructive verb must be added explicitly.
2. Provenance pre-dispatch: `nak verify` gate (`src/prov.c`) before action.
3. Auditable: `data/inbox.jsonl` (everything fetched), `data/outbox.jsonl`
   (everything dispatched + gate denials).
4. State files live under `data/` (0700 after `mkdir`).
5. The nostr secret key is handed to `nak` via `NOSTR_SECRET_KEY` env, not
   argv, where possible. `nak encrypt` receives DM plaintext via argv — local
   host only; fine for v0.1 test scope, revisit before any real credential
   flows through this path.

## Trust boundary
All relay content is UNTRUSTED input. jansson parses it; prov_gate verifies
it; nothing is executed from it. The only outbound effects are signed kind-1
replies and kind-14 DMs written by this binary under its own key.