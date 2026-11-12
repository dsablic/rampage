// SPDX-License-Identifier: Apache-2.0
// Suite v3, type propagation: a struct pointer passed down three functions to one indirect call through an
// operations table. The question asks, without giving the layouts, for the offsets of the table, the slot and the arguments.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

struct stream;

struct stream_ops {
    int (*open)(struct stream *stream);
    int (*fill)(struct stream *stream, uint8_t *data, uint32_t size);
    int (*drain)(struct stream *stream, const uint8_t *data, uint32_t size);
    int (*seek)(struct stream *stream, const uint8_t *data, uint32_t size);
    void (*close)(struct stream *stream);
};

struct stream {
    uint32_t id;
    uint32_t mode;
    const struct stream_ops *ops;
    uint8_t *window;
    uint8_t *scratch;
    uint32_t window_len;
    uint32_t scratch_len;
    uint32_t pending;
    uint32_t limit;
    void *cookie;
};

static const char *called = "none";
static const void *seen_data;
static uint32_t seen_size;

static int op_open(struct stream *stream) {
    (void)stream;
    called = "open";
    return 0;
}

static int op_fill(struct stream *stream, uint8_t *data, uint32_t size) {
    (void)stream;
    called = "fill";
    seen_data = data;
    seen_size = size;
    return 1;
}

static int op_drain(struct stream *stream, const uint8_t *data, uint32_t size) {
    (void)stream;
    called = "drain";
    seen_data = data;
    seen_size = size;
    return 2;
}

static int op_seek(struct stream *stream, const uint8_t *data, uint32_t size) {
    (void)stream;
    called = "seek";
    seen_data = data;
    seen_size = size;
    return 3;
}

static void op_close(struct stream *stream) {
    (void)stream;
    called = "close";
}

static const struct stream_ops default_ops = {op_open, op_fill, op_drain, op_seek, op_close};

NOINLINE int stream_emit(struct stream *stream) {
    return stream->ops->drain(stream, stream->scratch, stream->pending);
}

NOINLINE int stream_step(struct stream *stream, uint32_t force) {
    if (!force && stream->pending < stream->limit) {
        return 0;
    }
    if (stream->mode == 0) {
        return -1;
    }
    return stream_emit(stream) + (int)stream->id;
}

NOINLINE int stream_sync(struct stream *stream) {
    int result = stream_step(stream, 1);
    return result < 0 ? -1 : result + (int)stream->window_len;
}

int main(int argc, char **argv) {
    static uint8_t window[32], scratch[48];
    struct stream stream = {7, 1, &default_ops, window, scratch, 0x1111, 0x2222, 0x3333, 0x4444, NULL};
    if (argc > 1) {
        stream.mode = (uint32_t)strtoul(argv[1], NULL, 0);
    }
    stream.cookie = &stream;
    int result = stream_sync(&stream);
    const char *data = seen_data == window ? "window" : seen_data == scratch ? "scratch" : "other";
    const char *size = seen_size == stream.window_len    ? "window_len"
                       : seen_size == stream.scratch_len ? "scratch_len"
                       : seen_size == stream.pending     ? "pending"
                       : seen_size == stream.limit       ? "limit"
                                                         : "other";
    printf("%s %s %s %d\n", called, data, size, result);
    return 0;
}
