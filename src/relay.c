#include "rogue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>

/* run argv with fork/exec (no shell), capture stdout into malloc'd buffer */
char *nak_run(char *const argv[]) {
    /* honor ROGUE_NAK for non-PATH deployments (mutable copy of argv) */
    int argc = 0;
    while (argv[argc]) argc++;
    char **margv = xmalloc((size_t)(argc + 1) * sizeof(char *));
    for (int i = 0; i <= argc; i++) margv[i] = argv[i];
    const char *np = getenv("ROGUE_NAK");
    if (np && *np) margv[0] = (char *)np;
    int p[2];
    if (pipe(p) != 0) { perror("pipe"); return NULL; }
    pid_t kid = fork();
    if (kid < 0) { perror("fork"); close(p[0]); close(p[1]); return NULL; }
    if (kid == 0) {
        close(p[0]);
        dup2(p[1], STDOUT_FILENO);
        close(p[1]);
        execvp(margv[0], margv);
        _exit(127);
    }
    close(p[1]);
    size_t cap = 8192, len = 0;
    char *buf = xmalloc(cap + 1);
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            buf = realloc(buf, cap + 1);
            if (!buf) { fprintf(stderr, "oom\n"); exit(1); }
        }
        ssize_t n = read(p[0], buf + len, 4096);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(p[0]);
    buf[len] = '\0';
    int st = 0;
    waitpid(kid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) == 127) {
        fprintf(stderr, "nak: exec failed\n");
        free(buf);
        return NULL;
    }
    return buf;
}

static void prep_env(const char *nsec_path) {
    /* read key; set NOSTR_SECRET_KEY so nak signs without argv exposure */
    FILE *f = fopen(nsec_path, "r");
    if (!f) { fprintf(stderr, "cannot read nsec: %s\n", nsec_path); exit(1); }
    char key[256];
    if (!fgets(key, sizeof key, f)) { fclose(f); exit(1); }
    fclose(f);
    key[strcspn(key, "\n")] = '\0';
    setenv("NOSTR_SECRET_KEY", key, 1);
}

char **nak_fetch(const char *relay, long kind, long limit, long since,
                 const char *nsec_path) {
    (void)nsec_path; /* reads are unauthenticated */
    char kl[32], ll[32], sl[32];
    snprintf(kl, sizeof kl, "%ld", kind);
    snprintf(ll, sizeof ll, "%ld", limit);
    snprintf(sl, sizeof sl, "%ld", since);
    char *argv[16];
    int n = 0;
    argv[n++] = "nak";
    argv[n++] = "req";
    argv[n++] = "-k"; argv[n++] = kl;
    argv[n++] = "-l"; argv[n++] = ll;
    if (since > 0) { argv[n++] = "--since"; argv[n++] = sl; }
    argv[n++] = (char *)relay;
    argv[n] = NULL;

    char *out = nak_run(argv);
    if (!out) return NULL;

    /* each line is one event JSON */
    size_t cap = 8, cnt = 0;
    char **evs = xmalloc(cap * sizeof(char *));
    char *save = NULL;
    for (char *ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (!*ln) continue;
        if (strncmp(ln, "connecting", 10) == 0) continue;
        if (cnt + 2 > cap) { cap *= 2; evs = realloc(evs, cap * sizeof(char *)); }
        evs[cnt++] = xstrdup(ln);
    }
    evs[cnt] = NULL;
    free(out);
    return evs;
}

int nak_verify(const char *event_json) {
    /* feed event JSON on stdin to `nak verify` */
    int p[2];
    if (pipe(p) != 0) return 0;
    pid_t kid = fork();
    if (kid < 0) { close(p[0]); close(p[1]); return 0; }
    if (kid == 0) {
        close(p[0]);
        dup2(p[1], STDOUT_FILENO);
        dup2(p[1], STDERR_FILENO);
        close(p[1]);
        char *argv[] = { "nak", "verify", NULL };
        execvp(argv[0], argv);
        _exit(127);
    }
    close(p[1]);
    size_t len = strlen(event_json);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(p[0], event_json + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        off += (size_t)w;
    }
    close(p[0]);
    int st = 0;
    waitpid(kid, &st, 0);
    if (!WIFEXITED(st)) return 0;
    return WEXITSTATUS(st) == 0;
}

int nak_publish(const char *relay, const char *nsec_path, long kind,
                const char *content_path, char *const extra_tags[]) {
    prep_env(nsec_path);
    char kl[32];
    snprintf(kl, sizeof kl, "%ld", kind);
    char content_arg[1200];
    snprintf(content_arg, sizeof content_arg, "@%s", content_path);

    char *argv[32];
    int n = 0;
    argv[n++] = "nak";
    argv[n++] = "event";
    argv[n++] = "-k"; argv[n++] = kl;
    argv[n++] = "-c"; argv[n++] = content_arg;
    if (extra_tags) {
        for (int i = 0; extra_tags[i] && n < 28; i++)
            argv[n++] = extra_tags[i];
    }
    argv[n++] = (char *)relay;
    argv[n] = NULL;

    char *out = nak_run(argv);
    if (!out) return -1;
    int ok = strstr(out, "success") != NULL;
    free(out);
    return ok ? 0 : -1;
}

int nak_dm(const char *relay, const char *nsec_path, const char *to_pubkey,
           const char *plaintext) {
    prep_env(nsec_path);
    char *argv[] = { "nak", "encrypt", "--to", (char *)to_pubkey,
                     (char *)plaintext, NULL };
    char *cipher = nak_run(argv);
    if (!cipher) return -1;
    /* strip trailing newline */
    cipher[strcspn(cipher, "\n")] = '\0';
    if (!*cipher) { free(cipher); return -1; }

    const char *td = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char path[1024];
    snprintf(path, sizeof path, "%s/.rogue-dm-XXXXXX", td);
    int fd = mkstemp(path);
    if (fd < 0) { free(cipher); return -1; }
    size_t len = strlen(cipher), off = 0;
    while (off < len) {
        ssize_t w = write(fd, cipher + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        off += (size_t)w;
    }
    close(fd);
    free(cipher);

    char ptag[80];
    snprintf(ptag, sizeof ptag, "-p");
    char *tags[] = { ptag, (char *)to_pubkey, NULL };
    int rc = nak_publish(relay, nsec_path, 14, path, tags);
    unlink(path);
    return rc;
}