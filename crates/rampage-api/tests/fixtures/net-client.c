/* A small networking client for workflow tests. The address and host are reserved for documentation
 * (TEST-NET-2, example.com); the tests only analyze the compiled program, they never run it. */
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *endpoint = "http://updates.example.com:8080/check";
static const char *fallback = "198.51.100.23";

__attribute__((noinline)) static int open_connection(const char *host) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "8080", &hints, &result) != 0)
        return -1;
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd >= 0 && connect(fd, result->ai_addr, result->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    return fd;
}

int main(int argc, char **argv) {
    int fd = open_connection(argc > 1 ? argv[1] : fallback);
    if (fd < 0) {
        puts("offline");
        return 1;
    }
    send(fd, endpoint, strlen(endpoint), 0);
    close(fd);
    return 0;
}
