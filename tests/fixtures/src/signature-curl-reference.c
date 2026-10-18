/* SPDX-License-Identifier: Apache-2.0 */

#include <curl/curl.h>

int main(void) {
    CURLU *url = curl_url();
    char *host = NULL;
    int status = 1;

    if (url != NULL &&
        curl_url_set(url, CURLUPART_URL, "http://reference.invalid/path?a=b", 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_HOST, &host, 0) == CURLUE_OK)
        status = (unsigned char)host[0];
    curl_free(host);
    curl_url_cleanup(url);
    return status;
}
