/* Owned freestanding positive/negative corpus. Inspect the linked ELF; never execute it.
 * Compile REFERENCE_ONLY=1 for training, and without it for calibration and heldout harnesses.
 * Use distinct actual compiler optimization flags for each build; identical code is an exact-match case,
 * not evidence of near-miss recovery. Source-selected ownership is the three corpus_* functions only.
 */
typedef unsigned int u32;
typedef unsigned long usize;

#define NOINLINE __attribute__((noinline, used))

NOINLINE u32 corpus_crc32(const unsigned char *input, usize length) {
    u32 crc = 0xffffffffu;
    for (usize index = 0; index < length; ++index) {
        crc ^= input[index];
        for (u32 bit = 0; bit < 8; ++bit) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xedb88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xffffffffu;
}

NOINLINE u32 corpus_adler32(const unsigned char *input, usize length) {
    u32 low = 1;
    u32 high = 0;
    for (usize index = 0; index < length; ++index) {
        low += input[index];
        if (low >= 65521u) {
            low -= 65521u;
        }
        high += low;
        if (high >= 65521u) {
            high -= 65521u;
        }
    }
    return (high << 16) | low;
}

NOINLINE usize corpus_runlength(const unsigned char *input, usize length, unsigned char *output) {
    usize used = 0;
    for (usize index = 0; index < length;) {
        unsigned char value = input[index++];
        unsigned char run = 1;
        while (index < length && input[index] == value && run < 253) {
            ++index;
            ++run;
        }
        output[used++] = run;
        output[used++] = value;
    }
    return used;
}

#ifndef REFERENCE_ONLY
/* Deliberately share familiar constants with real algorithms: constants alone must not imply identity. */
NOINLINE u32 application_crc_like(const unsigned char *input, usize length) {
    u32 result = 0xffffffffu;
    for (usize index = 0; index < length; ++index) {
        result += input[index] * 37u;
        if (result & 8u) {
            result ^= 0xedb88320u;
        } else {
            result += 65521u;
        }
        result = (result << 3) | (result >> 29);
    }
    return result;
}

NOINLINE usize application_scan(const unsigned char *input, usize length) {
    usize matches = 0;
    for (usize index = 0; index < length; ++index) {
        if (input[index] == 37 || input[index] == 91) {
            matches += 7;
        } else if (input[index] > 127) {
            matches += 13;
        }
    }
    return matches;
}
#endif

volatile u32 corpus_sink;
unsigned char corpus_input[64];
unsigned char corpus_output[128];

void _start(void) {
    corpus_sink = corpus_crc32(corpus_input, 64);
    corpus_sink ^= corpus_adler32(corpus_input, 64);
    corpus_sink ^= (u32)corpus_runlength(corpus_input, 64, corpus_output);
#ifndef REFERENCE_ONLY
    corpus_sink ^= application_crc_like(corpus_input, 64);
    corpus_sink ^= (u32)application_scan(corpus_input, 64);
#endif
    for (;;) {
        corpus_sink ^= 1;
    }
}
