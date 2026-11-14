/* SPDX-License-Identifier: Apache-2.0 */
/* ECDSA P-256 (FIPS 186-4) and RSA PKCS#1 v1.5 (RFC 8017) signature verification over a generic Montgomery
 * multiplier with 32-bit limbs, least significant limb first. Curve parameters are FIPS 186-4 D.1.2.3. */
#include "crypto.h"

#define MAX_LIMBS 64

typedef struct {
    const uint32_t *m;
    uint32_t r2[MAX_LIMBS];
    uint32_t inverse; /* -m^-1 mod 2^32 */
    int n;
} modulus;

static int compare(const uint32_t *a, const uint32_t *b, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

static uint32_t subtract(uint32_t *r, const uint32_t *a, const uint32_t *b, int n) {
    uint64_t borrow = 0;
    for (int i = 0; i < n; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)d;
        borrow = (d >> 32) & 1;
    }
    return (uint32_t)borrow;
}

static uint32_t add(uint32_t *r, const uint32_t *a, const uint32_t *b, int n) {
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        carry += (uint64_t)a[i] + b[i];
        r[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return (uint32_t)carry;
}

static int is_zero(const uint32_t *a, int n) {
    uint32_t any = 0;
    for (int i = 0; i < n; i++) {
        any |= a[i];
    }
    return any == 0;
}

static void mont_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const modulus *mod) {
    uint32_t t[MAX_LIMBS + 2] = {0};
    int n = mod->n;
    for (int i = 0; i < n; i++) {
        uint64_t c = 0;
        for (int j = 0; j < n; j++) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * b[i];
            t[j] = (uint32_t)c;
            c >>= 32;
        }
        c += t[n];
        t[n] = (uint32_t)c;
        t[n + 1] = (uint32_t)(c >> 32);
        uint32_t u = t[0] * mod->inverse;
        c = ((uint64_t)t[0] + (uint64_t)u * mod->m[0]) >> 32;
        for (int j = 1; j < n; j++) {
            c += (uint64_t)t[j] + (uint64_t)u * mod->m[j];
            t[j - 1] = (uint32_t)c;
            c >>= 32;
        }
        c += t[n];
        t[n - 1] = (uint32_t)c;
        t[n] = t[n + 1] + (uint32_t)(c >> 32);
    }
    if (t[n] || compare(t, mod->m, n) >= 0) {
        subtract(t, t, mod->m, n);
    }
    for (int i = 0; i < n; i++) {
        r[i] = t[i];
    }
}

static void modulus_init(modulus *mod, const uint32_t *m, int n) {
    mod->m = m;
    mod->n = n;
    uint32_t x = m[0];
    for (int i = 0; i < 5; i++) {
        x *= 2 - m[0] * x;
    }
    mod->inverse = 0 - x;
    /* R^2 mod m: double 1 until it is 2^(64n) mod m. */
    for (int i = 0; i < n; i++) {
        mod->r2[i] = i == 0;
    }
    for (int i = 0; i < 64 * n; i++) {
        uint32_t carry = add(mod->r2, mod->r2, mod->r2, n);
        if (carry || compare(mod->r2, m, n) >= 0) {
            subtract(mod->r2, mod->r2, m, n);
        }
    }
}

/* r = a^e (a in Montgomery form; e as limbs) in Montgomery form. */
static void mont_pow(uint32_t *r, const uint32_t *a, const uint32_t *e, int e_limbs, const modulus *mod) {
    uint32_t one[MAX_LIMBS] = {1};
    uint32_t x[MAX_LIMBS];
    mont_mul(x, one, mod->r2, mod);
    for (int i = 32 * e_limbs - 1; i >= 0; i--) {
        mont_mul(x, x, x, mod);
        if ((e[i / 32] >> (i % 32)) & 1) {
            mont_mul(x, x, a, mod);
        }
    }
    for (int i = 0; i < mod->n; i++) {
        r[i] = x[i];
    }
}

static void from_bytes(uint32_t *r, const uint8_t *bytes, int n) {
    for (int i = 0; i < n; i++) {
        const uint8_t *word = bytes + 4 * (n - 1 - i);
        r[i] = (uint32_t)word[0] << 24 | (uint32_t)word[1] << 16 | (uint32_t)word[2] << 8 | word[3];
    }
}

/* ------------------------------------------------------------------------------------------------------------ */
/* P-256 */

static const uint32_t P256_P[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
                                   0x00000000, 0x00000000, 0x00000001, 0xffffffff};
static const uint32_t P256_N[8] = {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
                                   0xffffffff, 0xffffffff, 0x00000000, 0xffffffff};
static const uint32_t P256_B[8] = {0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
                                   0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8};
static const uint32_t P256_GX[8] = {0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
                                    0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};
static const uint32_t P256_GY[8] = {0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
                                    0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

typedef struct {
    uint32_t x[8], y[8], z[8];
} point;

static void f_add(uint32_t *r, const uint32_t *a, const uint32_t *b, const modulus *p) {
    if (add(r, a, b, 8) || compare(r, p->m, 8) >= 0) {
        subtract(r, r, p->m, 8);
    }
}

static void f_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, const modulus *p) {
    if (subtract(r, a, b, 8)) {
        add(r, r, p->m, 8);
    }
}

static void point_double(point *r, const point *a, const modulus *p) {
    uint32_t delta[8], gamma[8], beta[8], alpha[8], t1[8], t2[8];
    if (is_zero(a->z, 8)) {
        *r = *a;
        return;
    }
    mont_mul(delta, a->z, a->z, p);
    mont_mul(gamma, a->y, a->y, p);
    mont_mul(beta, a->x, gamma, p);
    f_sub(t1, a->x, delta, p);
    f_add(t2, a->x, delta, p);
    mont_mul(alpha, t1, t2, p);
    f_add(t1, alpha, alpha, p);
    f_add(alpha, t1, alpha, p);
    f_add(t1, a->y, a->z, p);
    mont_mul(t1, t1, t1, p);
    f_sub(t1, t1, gamma, p);
    f_sub(r->z, t1, delta, p);
    f_add(beta, beta, beta, p);
    f_add(beta, beta, beta, p); /* 4 beta */
    mont_mul(t1, alpha, alpha, p);
    f_sub(t1, t1, beta, p);
    f_sub(r->x, t1, beta, p); /* alpha^2 - 8 beta */
    f_sub(t1, beta, r->x, p);
    mont_mul(t1, alpha, t1, p);
    mont_mul(gamma, gamma, gamma, p);
    f_add(gamma, gamma, gamma, p);
    f_add(gamma, gamma, gamma, p);
    f_add(gamma, gamma, gamma, p); /* 8 gamma^2 */
    f_sub(r->y, t1, gamma, p);
}

static void point_add(point *r, const point *a, const point *b, const modulus *p) {
    uint32_t z1z1[8], z2z2[8], u1[8], u2[8], s1[8], s2[8], h[8], i[8], j[8], rr[8], v[8], t[8];
    if (is_zero(a->z, 8)) {
        *r = *b;
        return;
    }
    if (is_zero(b->z, 8)) {
        *r = *a;
        return;
    }
    mont_mul(z1z1, a->z, a->z, p);
    mont_mul(z2z2, b->z, b->z, p);
    mont_mul(u1, a->x, z2z2, p);
    mont_mul(u2, b->x, z1z1, p);
    mont_mul(s1, a->y, b->z, p);
    mont_mul(s1, s1, z2z2, p);
    mont_mul(s2, b->y, a->z, p);
    mont_mul(s2, s2, z1z1, p);
    f_sub(h, u2, u1, p);
    f_sub(rr, s2, s1, p);
    if (is_zero(h, 8)) {
        if (is_zero(rr, 8)) {
            point_double(r, a, p);
        } else {
            for (int k = 0; k < 8; k++) {
                r->x[k] = r->y[k] = r->z[k] = 0;
            }
        }
        return;
    }
    f_add(rr, rr, rr, p);
    f_add(i, h, h, p);
    mont_mul(i, i, i, p);
    mont_mul(j, h, i, p);
    mont_mul(v, u1, i, p);
    point out;
    mont_mul(t, rr, rr, p);
    f_sub(t, t, j, p);
    f_sub(t, t, v, p);
    f_sub(out.x, t, v, p);
    f_sub(t, v, out.x, p);
    mont_mul(t, rr, t, p);
    mont_mul(s1, s1, j, p);
    f_add(s1, s1, s1, p);
    f_sub(out.y, t, s1, p);
    f_add(t, a->z, b->z, p);
    mont_mul(t, t, t, p);
    f_sub(t, t, z1z1, p);
    f_sub(t, t, z2z2, p);
    mont_mul(out.z, t, h, p);
    *r = out;
}

static void point_multiply(point *r, const uint32_t k[8], const point *a, const modulus *p) {
    point acc = {{0}, {0}, {0}};
    for (int bit = 255; bit >= 0; bit--) {
        point_double(&acc, &acc, p);
        if ((k[bit / 32] >> (bit % 32)) & 1) {
            point_add(&acc, &acc, a, p);
        }
    }
    *r = acc;
}

int p256_verify(const uint8_t public_key[64], const uint8_t digest[32], const uint8_t signature[64]) {
    modulus p, n;
    uint32_t r[8], s[8], e[8], w[8], u1[8], u2[8], t[8], exponent[8];
    uint32_t one[8] = {1};
    point g, q, x1, x2;
    modulus_init(&p, P256_P, 8);
    modulus_init(&n, P256_N, 8);
    from_bytes(r, signature, 8);
    from_bytes(s, signature + 32, 8);
    if (is_zero(r, 8) || is_zero(s, 8) || compare(r, P256_N, 8) >= 0 || compare(s, P256_N, 8) >= 0) {
        return 0;
    }
    from_bytes(e, digest, 8);
    if (compare(e, P256_N, 8) >= 0) {
        subtract(e, e, P256_N, 8);
    }
    /* w = s^(n-2) mod n; u1 = e w, u2 = r w */
    subtract(exponent, P256_N, (const uint32_t[8]){2}, 8);
    mont_mul(t, s, n.r2, &n);
    mont_pow(w, t, exponent, 8, &n);
    mont_mul(u1, e, w, &n);
    mont_mul(u2, r, w, &n);
    /* G and Q in Montgomery form, Z = 1 */
    mont_mul(g.x, P256_GX, p.r2, &p);
    mont_mul(g.y, P256_GY, p.r2, &p);
    mont_mul(g.z, one, p.r2, &p);
    from_bytes(t, public_key, 8);
    mont_mul(q.x, t, p.r2, &p);
    from_bytes(t, public_key + 32, 8);
    mont_mul(q.y, t, p.r2, &p);
    for (int i = 0; i < 8; i++) {
        q.z[i] = g.z[i];
    }
    /* Q on the curve: y^2 = x^3 - 3x + b */
    uint32_t lhs[8], rhs[8], b[8];
    mont_mul(lhs, q.y, q.y, &p);
    mont_mul(rhs, q.x, q.x, &p);
    mont_mul(rhs, rhs, q.x, &p);
    f_sub(rhs, rhs, q.x, &p);
    f_sub(rhs, rhs, q.x, &p);
    f_sub(rhs, rhs, q.x, &p);
    mont_mul(b, P256_B, p.r2, &p);
    f_add(rhs, rhs, b, &p);
    if (compare(lhs, rhs, 8) != 0) {
        return 0;
    }
    point_multiply(&x1, u1, &g, &p);
    point_multiply(&x2, u2, &q, &p);
    point_add(&x1, &x1, &x2, &p);
    if (is_zero(x1.z, 8)) {
        return 0;
    }
    /* affine x = X / Z^2 */
    subtract(exponent, P256_P, (const uint32_t[8]){2}, 8);
    mont_mul(t, x1.z, x1.z, &p);
    mont_pow(t, t, exponent, 8, &p);
    mont_mul(t, x1.x, t, &p);
    mont_mul(t, t, one, &p);
    if (compare(t, P256_N, 8) >= 0) {
        subtract(t, t, P256_N, 8);
    }
    return compare(t, r, 8) == 0;
}

/* ------------------------------------------------------------------------------------------------------------ */
/* RSA-2048, e = 65537, PKCS#1 v1.5 with SHA-256 */

static const uint8_t SHA256_DIGEST_INFO[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                               0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

int rsa2048_verify(const uint8_t modulus_bytes[256], const uint8_t digest[32], const uint8_t signature[256]) {
    static uint32_t m[64];
    static modulus mod;
    uint32_t s[64], x[64], sm[64];
    uint32_t one[64] = {1};
    uint8_t em[256];
    from_bytes(m, modulus_bytes, 64);
    from_bytes(s, signature, 64);
    if (compare(s, m, 64) >= 0) {
        return 0;
    }
    modulus_init(&mod, m, 64);
    mont_mul(sm, s, mod.r2, &mod);
    mont_mul(x, sm, sm, &mod);
    for (int i = 1; i < 16; i++) {
        mont_mul(x, x, x, &mod);
    }
    mont_mul(x, x, sm, &mod);
    mont_mul(x, x, one, &mod);
    for (int i = 0; i < 64; i++) {
        em[4 * i] = (uint8_t)(x[63 - i] >> 24);
        em[4 * i + 1] = (uint8_t)(x[63 - i] >> 16);
        em[4 * i + 2] = (uint8_t)(x[63 - i] >> 8);
        em[4 * i + 3] = (uint8_t)x[63 - i];
    }
    if (em[0] != 0 || em[1] != 1) {
        return 0;
    }
    int at = 2;
    while (at < 256 - 52 && em[at] == 0xff) {
        at++;
    }
    if (at != 256 - 52 || em[at] != 0) {
        return 0;
    }
    return equal_bytes(em + at + 1, SHA256_DIGEST_INFO, 19) && equal_bytes(em + at + 20, digest, 32);
}
