/* SSE and AVX2 integer code for evaluate_function, built for x86-64 by build.sh: each function uses intrinsics for
 * the vector operations compiled code commonly holds, so a run meets them whatever the compiler's own choices. */
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#define NOINLINE __attribute__((noinline))

/* strlen in the SSE2 style of C libraries: aligned 16-byte loads, pcmpeqb, pmovmskb, bsf. */
NOINLINE size_t vector_strlen(const char *text) {
    const char *aligned = (const char *)((uintptr_t)text & ~(uintptr_t)15);
    __m128i zero = _mm_setzero_si128();
    unsigned mask = (unsigned)_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_load_si128((const __m128i *)aligned), zero));
    mask >>= (unsigned)(text - aligned);
    if (mask != 0) {
        return (size_t)__builtin_ctz(mask);
    }
    for (;;) {
        aligned += 16;
        mask = (unsigned)_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_load_si128((const __m128i *)aligned), zero));
        if (mask != 0) {
            return (size_t)(aligned - text) + (size_t)__builtin_ctz(mask);
        }
    }
}

/* memset in 16-byte stores of a broadcast byte (punpcklbw, pshuflw, pshufd). */
NOINLINE void vector_fill(uint8_t *out, uint8_t byte, size_t length) {
    __m128i value = _mm_cvtsi32_si128(byte);
    value = _mm_unpacklo_epi8(value, value);
    value = _mm_shufflelo_epi16(value, 0);
    value = _mm_shuffle_epi32(value, 0);
    size_t index = 0;
    for (; index + 16 <= length; index += 16) {
        _mm_storeu_si128((__m128i *)(out + index), value);
    }
    for (; index < length; index++) {
        out[index] = byte;
    }
}

/* A checksum mixing arithmetic, shifts, multiplies, packs and horizontal adds over 16-byte blocks. */
NOINLINE uint32_t vector_mix(const uint8_t *data, size_t blocks) {
    __m128i acc = _mm_set1_epi32(0x01020304);
    __m128i words = _mm_setzero_si128();
    for (size_t block = 0; block < blocks; block++) {
        __m128i bytes = _mm_loadu_si128((const __m128i *)(data + 16 * block));
        __m128i sad = _mm_sad_epu8(bytes, _mm_setzero_si128());
        __m128i low = _mm_unpacklo_epi8(bytes, _mm_setzero_si128());
        __m128i high = _mm_unpackhi_epi8(bytes, _mm_setzero_si128());
        __m128i products = _mm_madd_epi16(low, high);
        acc = _mm_add_epi32(acc, products);
        acc = _mm_xor_si128(acc, _mm_slli_epi32(acc, 3));
        acc = _mm_sub_epi32(acc, _mm_srli_epi32(acc, 5));
        acc = _mm_add_epi64(acc, sad);
        words = _mm_adds_epu16(words, _mm_packs_epi32(products, acc));
        words = _mm_max_epi16(words, _mm_mulhi_epi16(low, high));
        acc = _mm_shuffle_epi32(acc, _MM_SHUFFLE(0, 3, 2, 1));
        acc = _mm_add_epi32(acc, _mm_mullo_epi16(low, high));
        acc = _mm_xor_si128(acc, _mm_avg_epu8(bytes, _mm_min_epu8(bytes, high)));
        acc = _mm_or_si128(acc, _mm_and_si128(_mm_cmpgt_epi32(acc, words), _mm_set1_epi32(0x10)));
        acc = _mm_add_epi32(acc, _mm_srai_epi32(_mm_slli_si128(words, 3), 2));
        acc = _mm_andnot_si128(_mm_srli_si128(words, 5), acc);
    }
    __m128i folded = _mm_add_epi32(acc, _mm_shufflehi_epi16(acc, _MM_SHUFFLE(1, 0, 3, 2)));
    folded = _mm_add_epi32(folded, _mm_shuffle_epi32(folded, _MM_SHUFFLE(1, 0, 3, 2)));
    folded = _mm_add_epi32(folded, _mm_shuffle_epi32(folded, _MM_SHUFFLE(2, 3, 0, 1)));
    uint32_t packed = (uint32_t)_mm_movemask_epi8(_mm_packus_epi16(words, acc));
    return (uint32_t)_mm_cvtsi128_si32(folded) ^ (packed << 16) ^ (uint32_t)_mm_extract_epi16(words, 5);
}

/* SSSE3 and SSE4.1: byte shuffles, sign and absolute values, 32-bit min/max and multiplies, extract and test. */
__attribute__((target("sse4.1"))) NOINLINE uint32_t vector_shuffle(const uint8_t *data, const uint8_t *order) {
    __m128i bytes = _mm_loadu_si128((const __m128i *)data);
    __m128i shuffled = _mm_shuffle_epi8(bytes, _mm_loadu_si128((const __m128i *)order));
    __m128i wide = _mm_cvtepu8_epi32(shuffled);
    __m128i signs = _mm_sign_epi8(bytes, shuffled);
    __m128i magnitude = _mm_abs_epi8(signs);
    __m128i paired = _mm_hadd_epi32(wide, _mm_mullo_epi32(wide, _mm_set1_epi32(3)));
    __m128i bounded = _mm_min_epu32(_mm_max_epi32(paired, _mm_set1_epi32(5)), _mm_set1_epi32(900));
    __m128i aligned = _mm_alignr_epi8(magnitude, shuffled, 7);
    uint32_t result = (uint32_t)_mm_extract_epi32(bounded, 1) + (uint32_t)_mm_extract_epi8(aligned, 9);
    result ^= (uint32_t)_mm_movemask_ps(_mm_castsi128_ps(_mm_slli_epi32(bounded, 22))) << 24;
    result += (uint32_t)_mm_testz_si128(magnitude, _mm_set1_epi8(0x40));
    return result + (uint32_t)_mm_extract_epi8(_mm_blendv_epi8(bytes, shuffled, signs), 3);
}

/* AVX2: 32-byte loads, compares, masks and adds. */
__attribute__((target("avx2"))) NOINLINE uint32_t vector_count(const uint8_t *data, size_t blocks, uint8_t wanted) {
    __m256i needle = _mm256_set1_epi8((char)wanted);
    __m256i sums = _mm256_setzero_si256();
    uint32_t count = 0;
    for (size_t block = 0; block < blocks; block++) {
        __m256i bytes = _mm256_loadu_si256((const __m256i *)(data + 32 * block));
        __m256i equal = _mm256_cmpeq_epi8(bytes, needle);
        count += (uint32_t)__builtin_popcount((unsigned)_mm256_movemask_epi8(equal));
        sums = _mm256_add_epi32(sums, _mm256_and_si256(_mm256_cvtepu8_epi32(_mm256_castsi256_si128(bytes)), _mm256_set1_epi32(0xff)));
        sums = _mm256_xor_si256(sums, _mm256_permute4x64_epi64(sums, 0x4e));
    }
    __m128i half = _mm_add_epi32(_mm256_castsi256_si128(sums), _mm256_extracti128_si256(sums, 1));
    half = _mm_add_epi32(half, _mm_shuffle_epi32(half, 0x4e));
    half = _mm_add_epi32(half, _mm_shuffle_epi32(half, 0xb1));
    _mm256_zeroupper();
    return (count << 24) ^ (uint32_t)_mm_cvtsi128_si32(half);
}

int main(int argc, char **argv) {
    static uint8_t buffer[64] __attribute__((aligned(16)));
    vector_fill(buffer, (uint8_t)argc, sizeof buffer - 1);
    return (int)(vector_strlen(argv[0]) + vector_mix(buffer, 2) + vector_shuffle(buffer, buffer + 16) +
                 vector_count(buffer, 1, 1));
}
