/* SPDX-License-Identifier: Apache-2.0
 * Integer-only freestanding reference corpus. Entry main is for analysis, not execution. */

#define KEEP __attribute__((noinline))

struct parity_state {
    unsigned key;
    unsigned count;
    int total;
};

volatile unsigned parity_input = 7;
volatile int parity_sink;

KEEP unsigned parity_decode(unsigned value, unsigned key) {
    return (value ^ key) & 255u;
}

KEEP int parity_update(struct parity_state *state, unsigned command, int value) {
    state->count += 1;
    switch (command) {
    case 1: state->total += value; break;
    case 3: state->total -= value; break;
    case 7: state->key ^= (unsigned)value; break;
    default: return -1;
    }
    return state->total;
}

KEEP unsigned parity_checksum(const unsigned char *bytes, unsigned length, unsigned key) {
    unsigned total = 0;
    for (unsigned i = 0; i < length; ++i) {
        total += parity_decode(bytes[i], key);
    }
    return total;
}

int main(void) {
    const unsigned char bytes[] = {0x43, 0x51, 0x47, 0x5a};
    struct parity_state state = {0x32, 0, 0};
    unsigned command = parity_input;
    int value = (int)(parity_input & 255u);
    parity_sink = parity_update(&state, command, value);
    parity_sink += (int)parity_checksum(bytes, sizeof(bytes), state.key);
    return parity_sink;
}
