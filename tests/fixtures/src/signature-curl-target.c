/* SPDX-License-Identifier: Apache-2.0 */

#include <curl/curl.h>

int main(void) {
    CURLU *url = curl_url();
    char *path = NULL;
    char *escaped = curl_easy_escape(NULL, "target input /?", 0);
    int status = 2;

    if (url != NULL && escaped != NULL &&
        curl_url_set(url, CURLUPART_URL, "http://target.invalid/other", 0) == CURLUE_OK &&
        curl_url_set(url, CURLUPART_QUERY, escaped, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_PATH, &path, 0) == CURLUE_OK)
        status = (unsigned char)path[0] ^ (unsigned char)escaped[0];
    curl_free(escaped);
    curl_free(path);
    curl_url_cleanup(url);
    return status;
}
