#ifndef ROGUE_H
#define ROGUE_H

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>

#define ROGUE_NAME "Rogue-in-C v0.1 (PV-001)"

/* ---- config ---------------------------------------------------------- */
typedef struct {
    const char *relay;     /* wss relay */
    const char *nak;       /* path to nak binary */
    const char *nsec;      /* path to nsec key file */
    const char *dir;       /* data directory */
    const char *model_url; /* OpenAI-compatible endpoint (may be NULL) */
    const char *model_key; /* bearer token for model_url (may be NULL) */
    const char *model;     /* model id (may be NULL) */
} cfg_t;

cfg_t cfg_default(void);
void cfg_load_env(cfg_t *c);

/* ---- net.c ----------------------------------------------------------- */
/* returns malloc'd response body (caller frees) or NULL; *status optional */
char *http_get(const char *url, long timeout_s, long *status);
char *http_post_json(const char *url, const char *body, const char *bearer,
                     long timeout_s, long *status);

/* ---- relay.c --------------------------------------------------------- */
/* exec nak, capture stdout; returns malloc'd string or NULL */
char *nak_run(char *const argv[]);
/* fetch up to limit events of kind from relay; returns array of malloc'd
 * JSON strings, NULL-terminated; caller frees each + array */
char **nak_fetch(const char *relay, long kind, long limit, long since,
                 const char *nsec_path);
/* publish a signed event of kind with content file; tags are raw argv
 * snippets like "-p", "<pubkey>". Returns 0 on success. */
int nak_publish(const char *relay, const char *nsec_path, long kind,
                const char *content_path, char *const extra_tags[]);
/* NIP-44 DM: encrypt plaintext to to_pubkey, publish kind 14. */
int nak_dm(const char *relay, const char *nsec_path, const char *to_pubkey,
           const char *plaintext);
/* verify event JSON (stdin to `nak verify`); 1 = valid, 0 = invalid */
int nak_verify(const char *event_json);

/* ---- state.c --------------------------------------------------------- */
typedef struct {
    char inbox_path[1024];
    char outbox_path[1024];
    char seen_path[1024];
} state_t;

int state_init(state_t *s, const char *dir);
int state_has_seen(state_t *s, const char *id, char **seen_map, size_t *n);
int state_seen_add(state_t *s, const char *id, char ***seen_map, size_t *n);
int state_append(const char *path, const char *line);

/* ---- jsonx.c (jansson layer) ----------------------------------------- */
int jsonx_get_str(const char *json, const char *key, char *out, size_t outsz);
int jsonx_get_long(const char *json, const char *key, long *out);
char *jsonx_model_reply(const char *resp);

/* ---- prov.c ---------------------------------------------------------- */
/* provenance gate: verify sig, then allow only whitelisted verbs.
 * returns 1 if the event may be acted on, 0 otherwise. logs to outbox log. */
int prov_gate(state_t *s, const char *event_json);

/* ---- util ------------------------------------------------------------ */
void *xmalloc(size_t n);
char *xstrdup(const char *s);

#endif