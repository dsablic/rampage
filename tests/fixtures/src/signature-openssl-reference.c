/* SPDX-License-Identifier: Apache-2.0 */

#include <openssl/evp.h>
#include <openssl/ssl.h>

int main(void) {
    static const unsigned char message[] = "reference digest input";
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int length = 0;
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    SSL_CTX *tls_context = SSL_CTX_new(TLS_client_method());
    int status = 1;

    if (digest_context != NULL && tls_context != NULL &&
        EVP_DigestInit_ex(digest_context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(digest_context, message, sizeof(message) - 1) == 1 &&
        EVP_DigestFinal_ex(digest_context, digest, &length) == 1)
        status = (int)(digest[0] ^ length);
    SSL_CTX_free(tls_context);
    EVP_MD_CTX_free(digest_context);
    return status;
}
