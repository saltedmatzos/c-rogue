#include "rogue.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} wbuf_t;

static size_t wcb(char *ptr, size_t size, size_t nmemb, void *ud) {
    wbuf_t *w = ud;
    size_t add = size * nmemb;
    if (w->len + add + 1 > w->cap) {
        size_t ncap = w->cap ? w->cap * 2 : 4096;
        while (ncap < w->len + add + 1) ncap *= 2;
        char *nb = realloc(w->buf, ncap);
        if (!nb) return 0;
        w->buf = nb;
        w->cap = ncap;
    }
    memcpy(w->buf + w->len, ptr, add);
    w->len += add;
    w->buf[w->len] = '\0';
    return add;
}

static char *do_transfer(const char *url, const char *post_body,
                         const char *bearer, long timeout_s, long *status) {
    CURL *h = curl_easy_init();
    if (!h) return NULL;
    wbuf_t w = {0};
    char err[CURL_ERROR_SIZE] = {0};

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, timeout_s > 0 ? timeout_s : 30L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wcb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &w);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, err);
    curl_easy_setopt(h, CURLOPT_USERAGENT, ROGUE_NAME);

    if (post_body) {
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, post_body);
        struct curl_slist *hd = NULL;
        hd = curl_slist_append(hd, "Content-Type: application/json");
        if (bearer && *bearer) {
            char auth[512];
            snprintf(auth, sizeof auth, "Authorization: Bearer %s", bearer);
            hd = curl_slist_append(hd, auth);
        }
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hd);
    } else if (bearer && *bearer) {
        char auth[512];
        snprintf(auth, sizeof auth, "Authorization: Bearer %s", bearer);
        struct curl_slist *hd = curl_slist_append(NULL, auth);
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hd);
    }

    CURLcode rc = curl_easy_perform(h);
    long http = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &http);
    if (status) *status = http;
    curl_easy_cleanup(h);

    if (rc != CURLE_OK) {
        fprintf(stderr, "curl: %s (%s)\n", err[0] ? err : curl_easy_strerror(rc), url);
        free(w.buf);
        return NULL;
    }
    if (!w.buf) w.buf = strdup("");
    return w.buf;
}

char *http_get(const char *url, long timeout_s, long *status) {
    return do_transfer(url, NULL, NULL, timeout_s, status);
}

char *http_post_json(const char *url, const char *body, const char *bearer,
                     long timeout_s, long *status) {
    return do_transfer(url, body, bearer, timeout_s, status);
}