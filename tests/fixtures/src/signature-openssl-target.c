/* SPDX-License-Identifier: Apache-2.0 */

#include <openssl/evp.h>
#include <openssl/ssl.h>

int main(void) {
    static const unsigned char first[] = "target digest ";
    static const unsigned char second[] = "in two chunks";
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int length = 0;
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    SSL_CTX *tls_context = SSL_CTX_new(TLS_server_method());
    int status = 2;

    if (digest_context != NULL && tls_context != NULL &&
        EVP_DigestInit_ex(digest_context, EVP_sha512(), NULL) == 1 &&
        EVP_DigestUpdate(digest_context, first, sizeof(first) - 1) == 1 &&
        EVP_DigestUpdate(digest_context, second, sizeof(second) - 1) == 1 &&
        EVP_DigestFinal_ex(digest_context, digest, &length) == 1)
        status = (int)(digest[length - 1] + length);
    EVP_MD_CTX_free(digest_context);
    SSL_CTX_free(tls_context);
    return status;
}
