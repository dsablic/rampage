/* SPDX-License-Identifier: Apache-2.0
 * Original freestanding acceptance fixture; no third-party source or runtime.
 */

__attribute__((noinline)) unsigned switch_pic(unsigned selector, volatile unsigned *output) {
#ifdef SCHEDULED_GUARD
    output[1] = selector * 17 + 123;
#endif
#ifdef INVERSE_GUARD
    if (__builtin_expect(selector > 7, 1)) {
        *output = 149;
        return 149;
    }
#endif
    switch (selector) {
    case 0: *output += 11; return 11;
    case 1: *output ^= 23; return 23;
    case 2: *output *= 37; return 37;
    case 3: *output -= 53; return 53;
    case 4: *output |= 71; return 71;
    case 5: *output &= 89; return 89;
    case 6: *output <<= 1; return 107;
    case 7: *output >>= 2; return 131;
    default: *output = 149; return 149;
    }
}
