#include "rogue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "oom\n"); exit(1); }
    return p;
}

char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

cfg_t cfg_default(void) {
    cfg_t c;
    c.relay     = "wss://relay.roguenetwork.org";
    c.nak       = "nak";
    c.nsec      = "nsec.key";
    c.dir       = "data";
    c.model_url = NULL;
    c.model_key = NULL;
    c.model     = NULL;
    return c;
}

void cfg_load_env(cfg_t *c) {
    const char *v;
    if ((v = getenv("ROGUE_RELAY")) && *v) c->relay = v;
    if ((v = getenv("ROGUE_NAK"))   && *v) c->nak   = v;
    if ((v = getenv("ROGUE_NSEC"))  && *v) c->nsec  = v;
    if ((v = getenv("ROGUE_DIR"))   && *v) c->dir   = v;
    if ((v = getenv("ROGUE_MODEL_URL")) && *v) c->model_url = v;
    if ((v = getenv("ROGUE_MODEL_KEY")) && *v) c->model_key = v;
    if ((v = getenv("ROGUE_MODEL"))      && *v) c->model     = v;
}

/* simple growable string set */
typedef struct { char **v; size_t n; } strset_t;

static void strset_load(strset_t *s, const char *path) {
    s->v = NULL; s->n = 0;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        if (!*line) continue;
        s->v = realloc(s->v, (s->n + 1) * sizeof(char *));
        if (!s->v) { fprintf(stderr, "oom\n"); exit(1); }
        s->v[s->n++] = xstrdup(line);
    }
    fclose(f);
}

static int strset_has(strset_t *s, const char *id) {
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], id) == 0) return 1;
    return 0;
}

static void strset_add(strset_t *s, const char *id) {
    s->v = realloc(s->v, (s->n + 1) * sizeof(char *));
    if (!s->v) { fprintf(stderr, "oom\n"); exit(1); }
    s->v[s->n++] = xstrdup(id);
}

static void strset_free(strset_t *s) {
    for (size_t i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
}

/* field extraction on an event JSON string via jansson (untrusted input) */
static int ev_field(char *buf, const char *name, char *out, size_t outsz) {
    return jsonx_get_str(buf, name, out, outsz);
}

static long ev_created_at(char *buf) {
    long ts = -1;
    jsonx_get_long(buf, "created_at", &ts);
    return ts;
}

/* write content to a temp file for `-c @file`; caller unlinks */
static const char *tmp_content(const char *content) {
    const char *td = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    static char path[1024];
    snprintf(path, sizeof path, "%s/.rogue-content-XXXXXX", td);
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return NULL; }
    size_t len = strlen(content);
    const char *p = content;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) { close(fd); unlink(path); return NULL; }
        p += w; len -= (size_t)w;
    }
    close(fd);
    return path;
}

/* ---------------- commands ---------------- */

static void cmd_fetch(cfg_t *c, long limit, long since) {
    state_t st;
    if (state_init(&st, c->dir) != 0) { fprintf(stderr, "state init failed\n"); exit(1); }

    strset_t seen = {0};
    strset_load(&seen, st.seen_path);

    char **evs = nak_fetch(c->relay, 1, limit, since, c->nsec);
    if (!evs) { fprintf(stderr, "fetch failed\n"); strset_free(&seen); exit(1); }

    FILE *sf = fopen(st.seen_path, "a"); /* may be NULL if read-only; tolerate */
    for (size_t i = 0; evs[i]; i++) {
        char id[256], pk[256], ct[2048];
        if (!ev_field(evs[i], "id", id, sizeof id)) { free(evs[i]); continue; }
        long ts = ev_created_at(evs[i]);
        if (since > 0 && ts >= 0 && ts < since) { free(evs[i]); continue; }
        if (strset_has(&seen, id)) { free(evs[i]); continue; }

        ev_field(evs[i], "pubkey", pk, sizeof pk);
        ev_field(evs[i], "content", ct, sizeof ct);
        state_append(st.inbox_path, evs[i]);
        printf("%s\t%s\t%.300s\n", id, pk[0] ? pk : "?", ct[0] ? ct : "?");
        strset_add(&seen, id);
        if (sf) fprintf(sf, "%s\n", id);
        free(evs[i]);
    }
    if (sf) fclose(sf);
    free(evs);
    strset_free(&seen);
}

static void cmd_post(cfg_t *c, const char *content) {
    const char *tmp = tmp_content(content);
    if (!tmp) exit(1);
    char *tags[] = { NULL };
    int rc = nak_publish(c->relay, c->nsec, 1, tmp, tags);
    unlink(tmp);
    if (rc != 0) exit(1);
}

static void cmd_dm(cfg_t *c, const char *to, const char *content) {
    if (nak_dm(c->relay, c->nsec, to, content) != 0) exit(1);
}

static void cmd_verify(const char *event_json) {
    exit(nak_verify(event_json) ? 0 : 1);
}

/* template responder when no model endpoint is configured */
static char *template_reply(void) {
    return xstrdup("Ack from Rogue-in-C v0.1 (C core, PV-001). Spec + code: "
                   "github.com/saltedmatzos/c-rogue. Standing by. \u2014 Sithembiso");
}

static char *model_reply(const cfg_t *c, const char *prompt) {
    char body[8192];
    const char *model = c->model ? c->model : "rogue-core";
    /* escape the prompt into a JSON string (conservative: strip quotes/backslashes) */
    char esc[4096];
    size_t j = 0;
    for (size_t i = 0; prompt[i] && j < sizeof esc - 2; i++) {
        char ch = prompt[i];
        if (ch == '"' || ch == '\\') esc[j++] = ' ';
        else esc[j++] = ch;
    }
    esc[j] = '\0';
    snprintf(body, sizeof body,
        "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}],"
        "\"max_tokens\":200}", model, esc);
    long status = 0;
    char *resp = http_post_json(c->model_url, body, c->model_key, 30, &status);
    if (!resp || status != 200) { free(resp); return NULL; }

    char *out = jsonx_model_reply(resp);
    free(resp);
    return out;
}

static void cmd_run(cfg_t *c, long interval, long max_iters) {
    state_t st;
    if (state_init(&st, c->dir) != 0) { fprintf(stderr, "state init failed\n"); exit(1); }
    long iter = 0;
    for (;;) {
        iter++;
        char **evs = nak_fetch(c->relay, 1, 50, 0, c->nsec);
        if (!evs) { fprintf(stderr, "fetch failed\n"); goto throttle; }

        for (size_t i = 0; evs[i]; i++) {
            /* provenance gate: signature must verify before any action */
            if (!prov_gate(&st, evs[i])) { free(evs[i]); continue; }

            char id[256], pk[256], ct[2048];
            if (!ev_field(evs[i], "id", id, sizeof id)) { free(evs[i]); continue; }
            ev_field(evs[i], "pubkey", pk, sizeof pk);
            ev_field(evs[i], "content", ct, sizeof ct);
            if (!pk[0] || !ct[0]) { free(evs[i]); continue; }

            int mention = strstr(ct, "sithembiso") || strstr(ct, "RogueInC") ||
                          strstr(ct, "PV-001");
            if (!mention) { free(evs[i]); continue; }

            char *reply = model_reply(c, ct);
            if (!reply) reply = template_reply();

            const char *tmp = tmp_content(reply);
            if (!tmp) { free(reply); free(evs[i]); continue; }
            char *tags[] = { "-e", id, "-p", pk, NULL };

            if (nak_publish(c->relay, c->nsec, 1, tmp, tags) == 0) {
                char logline[2048];
                snprintf(logline, sizeof logline, "{\"reply_to\":\"%s\",\"reply\":\"%s\"}\n",
                         id, reply);
                state_append(st.outbox_path, logline);
            }
            unlink(tmp);
            free(reply);
            free(evs[i]);
        }
        free(evs);
    throttle:
        /* health-only watchdog heartbeat: init supervises, we just tick */
        {
            char hb[1024];
            snprintf(hb, sizeof hb, "%s/heartbeat", c->dir);
            FILE *hf = fopen(hb, "w");
            if (hf) { fprintf(hf, "%ld\n", (long)time(NULL)); fclose(hf); }
        }
        fflush(stdout);
        if (max_iters > 0 && iter >= max_iters) break;
        sleep((unsigned)interval);
    }
}

static void usage(void) {
    fprintf(stderr,
        "usage: rogue <fetch|post|dm|verify|run> [args]\n"
        "  fetch [--limit N] [--since TS]\n"
        "  post \"text\"\n"
        "  dm <pubkey> \"text\"\n"
        "  verify <event-json>\n"
        "  run [--interval S] [--max N]\n");
    exit(2);
}

int main(int argc, char **argv) {
    cfg_t cfg = cfg_default();
    cfg_load_env(&cfg);

    if (argc < 2) usage();
    const char *cmd = argv[1];

    if (strcmp(cmd, "fetch") == 0) {
        long limit = 20, since = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) limit = strtol(argv[++i], NULL, 10);
            else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc) since = strtol(argv[++i], NULL, 10);
            else usage();
        }
        cmd_fetch(&cfg, limit, since);
    } else if (strcmp(cmd, "post") == 0) {
        if (argc < 3) usage();
        cmd_post(&cfg, argv[2]);
    } else if (strcmp(cmd, "dm") == 0) {
        if (argc < 4) usage();
        cmd_dm(&cfg, argv[2], argv[3]);
    } else if (strcmp(cmd, "verify") == 0) {
        if (argc < 3) usage();
        cmd_verify(argv[2]);
    } else if (strcmp(cmd, "run") == 0) {
        long interval = 60, max_iters = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) interval = strtol(argv[++i], NULL, 10);
            else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) max_iters = strtol(argv[++i], NULL, 10);
            else usage();
        }
        cmd_run(&cfg, interval, max_iters);
    } else {
        usage();
    }
    return 0;
}