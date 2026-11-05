// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: a pointer chain through three structures, built stripped for aarch64 Linux. The
// task starts at session_read and asks which field, reached through which pointer offsets, gets the byte count.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct stats {
    uint32_t hits;
    uint32_t misses;
    uint64_t bytes;
    uint16_t errors;
};

struct conn {
    int fd;
    char name[12];
    struct stats *stats;
    struct conn *next;
};

struct session {
    uint64_t id;
    uint32_t flags;
    struct conn *primary;
    struct conn *backup;
};

__attribute__((noinline)) void count_bytes(struct stats *stats, uint64_t n) { stats->bytes += n; }

__attribute__((noinline)) void count_error(struct stats *stats) { stats->errors++; }

__attribute__((noinline)) void conn_read(struct conn *conn, uint64_t n) {
    if (conn->fd < 0) {
        count_error(conn->stats);
        return;
    }
    count_bytes(conn->stats, n);
}

__attribute__((noinline)) void session_read(struct session *session, uint64_t n) {
    session->flags |= 1;
    conn_read(session->primary, n);
}

int main(int argc, char **argv) {
    (void)argv;
    struct stats *stats = calloc(1, sizeof *stats);
    struct conn *conn = calloc(1, sizeof *conn);
    struct session *session = calloc(1, sizeof *session);
    conn->fd = argc;
    conn->stats = stats;
    session->primary = conn;
    session->backup = conn;
    session_read(session, (uint64_t)argc * 100);
    printf("%llu %u\n", (unsigned long long)stats->bytes, stats->errors);
    return 0;
}
