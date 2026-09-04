#include "rogue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

int state_init(state_t *s, const char *dir) {
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) { perror("mkdir"); return -1; }
    snprintf(s->inbox_path,  sizeof s->inbox_path,  "%s/inbox.jsonl",  dir);
    snprintf(s->outbox_path, sizeof s->outbox_path, "%s/outbox.jsonl", dir);
    snprintf(s->seen_path,   sizeof s->seen_path,   "%s/seen.txt",     dir);
    return 0;
}

int state_append(const char *path, const char *line) {
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    fputs(line, f);
    if (line[strlen(line) - 1] != '\n') fputc('\n', f);
    fclose(f);
    return 0;
}