struct HintState { int gain; int bias; };

int fields(struct HintState *state, int sample) {
    return state->gain * sample + state->bias;
}

extern struct HintState *get_state(void);

int local_fields(void) {
    struct HintState *state = get_state();
    return state->gain + state->bias;
}

struct HintState *identity(struct HintState *state) {
    return state;
}

int caller(struct HintState *state, int sample) {
    return fields(state, sample);
}

int computed_return(struct HintState *state, int sample) {
    return fields(state, sample) + 1;
}

extern struct HintState shared_state;

struct HintState *factory(void) {
    return &shared_state;
}

int reader(void) {
    struct HintState *state = factory();
    return state->gain + state->bias;
}

unsigned long long scalar_global = 7;
extern unsigned long long consume_value(unsigned long long value);
extern unsigned long long consume_address(unsigned long long *value);

unsigned long long global_value_caller(void) {
    return consume_value(scalar_global);
}

unsigned long long global_address_caller(void) {
    return consume_address(&scalar_global);
}

int stack_fields(int *state, int unused1, int unused2, int unused3, int unused4, int unused5, int extra) {
    return state[0] + state[1] + extra;
}

int windows_stack_fields(int *state, int unused1, int unused2, int unused3, int extra) {
    return state[0] + state[1] + extra;
}

extern unsigned __int128 produce_wide(void);

unsigned long long sum_wide_return(void) {
    unsigned __int128 value = produce_wide();
    return (unsigned long long)value + (unsigned long long)(value >> 64);
}

struct HintState *identity_factory(struct HintState *state) {
    return state;
}

int identity_reader(struct HintState *state) {
    struct HintState *result = identity_factory(state);
    return result->gain + result->bias;
}

extern int consume_three(int first, int second, int third);

int many_calls(void) {
    int result;
    for (int index = 0; index < 86; ++index)
        result = consume_three(1, 1, 1);
    return result;
}

extern int consume_one(int first);

int many_calls_one(void) {
    int result;
    for (int index = 0; index < 257; ++index)
        result = consume_one(1);
    return result;
}
