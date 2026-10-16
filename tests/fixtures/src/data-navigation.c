#include <stddef.h>

typedef struct {
    float gain;
} State;

typedef struct {
    const char *name;
    void (*initialize)(State *);
    void (*update)(State *, float);
    void (*process)(State *, const float *, float *, size_t);
} Block;

_Thread_local unsigned owned_tls[4096];
volatile unsigned owned_startups;

__attribute__((constructor)) static void record_startup(void) {
    owned_startups += 1;
}

static void initialize(State *state) {
    state->gain = 1.0f;
}

static void update(State *state, float gain) {
    state->gain = gain;
}

static void process(State *state, const float *input, float *output, size_t frames) {
    for (size_t i = 0; i < frames; ++i) output[i] = input[i] * state->gain;
}

static const Block block = {"owned_gain", initialize, update, process};
const Block * const owned_blocks[] = {&block};
