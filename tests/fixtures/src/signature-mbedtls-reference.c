/* SPDX-License-Identifier: Apache-2.0 */

#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"

int main(void) {
    static const unsigned char input[16] = "reference bytes";
    static const unsigned char benchmark_key[16] = {0};
    unsigned char digest[32] = {0};
    unsigned char ciphertext[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_ssl_config config;
    int status;

    mbedtls_aes_init(&aes);
    mbedtls_ssl_config_init(&config);
    status = mbedtls_sha256_ret(input, sizeof(input), digest, 0);
    if (status == 0)
        status = mbedtls_aes_setkey_enc(&aes, benchmark_key, 128);
    if (status == 0)
        status = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, ciphertext);
    if (status == 0)
        status = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_config_free(&config);
    mbedtls_aes_free(&aes);
    return status == 0 ? (digest[0] ^ ciphertext[0]) : 1;
}
