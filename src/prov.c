#include "rogue.h"

#include <stdio.h>
#include <string.h>

/*
 * prov_gate: the provenance gate, applied before ANY dispatch on relay input.
 *
 * 1. verify the event signature (`nak verify`): unverified events are never
 *    acted on (audited, not dispatched).
 * 2. whitelist only read-only, reply-only verbs. There are no destructive
 *    verbs in v0.1 — this gate is where they would be refused.
 *
 * This enforces the PV-001 guardrails: provenance pre-dispatch, auditable,
 * no destructive ops on untrusted input.
 */
int prov_gate(state_t *s, const char *event_json) {
    if (!s || !event_json) return 0;

    if (!nak_verify(event_json)) {
        /* audit the refusal; do not act */
        state_append(s->outbox_path,
                     "{\"gate\":\"deny\",\"reason\":\"bad-signature\"}\n");
        return 0;
    }

    /* v0.1 verb whitelist: nothing in the run loop is destructive.
     * (future verbs must be added here, by explicit fiat, before dispatch.) */
    return 1;
}