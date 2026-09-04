#include "rogue.h"

#include <jansson.h>
#include <stdio.h>
#include <string.h>

/*
 * jansson layer — the PV-001 Q1 decision: do NOT hand-roll JSON parsing for
 * untrusted relay/model input. All reads of untrusted JSON go through here.
 */

/* get a top-level string field; returns 1 on success, 0 otherwise */
int jsonx_get_str(const char *json, const char *key, char *out, size_t outsz) {
    json_error_t err;
    json_t *root = json_loads(json, 0, &err);
    if (!root) return 0;
    int rc = 0;
    json_t *v = json_object_get(root, key);
    if (json_is_string(v)) {
        const char *s = json_string_value(v);
        if (s) { snprintf(out, outsz, "%s", s); rc = 1; }
    }
    json_decref(root);
    return rc;
}

/* get a top-level integer field; returns 1 on success */
int jsonx_get_long(const char *json, const char *key, long *out) {
    json_error_t err;
    json_t *root = json_loads(json, 0, &err);
    if (!root) return 0;
    int rc = 0;
    json_t *v = json_object_get(root, key);
    if (json_is_integer(v)) { *out = (long)json_integer_value(v); rc = 1; }
    json_decref(root);
    return rc;
}

/*
 * extract choices[0].message.content from an OpenAI-compatible response.
 * Returns malloc'd string or NULL. Uses only array/object access — never
 * trusts field positions.
 */
char *jsonx_model_reply(const char *resp) {
    json_error_t err;
    json_t *root = json_loads(resp, 0, &err);
    if (!root) return NULL;
    char *out = NULL;
    json_t *choices = json_object_get(root, "choices");
    if (json_is_array(choices) && json_array_size(choices) > 0) {
        json_t *first = json_array_get(choices, 0);
        json_t *msg = json_object_get(first, "message");
        json_t *content = json_object_get(msg, "content");
        if (json_is_string(content)) {
            out = strdup(json_string_value(content));
        }
    }
    json_decref(root);
    return out;
}