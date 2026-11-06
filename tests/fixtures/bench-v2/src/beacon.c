// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: a small client whose single path from main to the imported connect routine runs
// through four of its own functions, next to decoy paths that only log or resolve. Built stripped for aarch64
// Linux, dynamically linked. The task asks for that call chain.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int verbose;

__attribute__((noinline)) static void log_line(const char *text) {
    if (verbose) {
        write(2, text, strlen(text));
    }
}

__attribute__((noinline)) static int parse_port(const char *text) {
    int port = 0;
    for (; *text >= '0' && *text <= '9'; text++) {
        port = port * 10 + (*text - '0');
    }
    return port > 0 && port < 65536 ? port : 4444;
}

__attribute__((noinline)) static int dial(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

__attribute__((noinline)) static int open_channel(const char *host, const char *port_text) {
    log_line("opening channel\n");
    return dial(host, parse_port(port_text));
}

__attribute__((noinline)) static int send_beacon(const char *host, const char *port_text) {
    int fd = open_channel(host, port_text);
    if (fd < 0) {
        log_line("channel failed\n");
        return -1;
    }
    static const char hello[] = "BEACON v2\n";
    write(fd, hello, sizeof hello - 1);
    close(fd);
    return 0;
}

__attribute__((noinline)) static int run(int argc, char **argv) {
    verbose = argc > 3;
    log_line("starting\n");
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const char *port = argc > 2 ? argv[2] : "4444";
    return send_beacon(host, port);
}

int main(int argc, char **argv) {
    int status = run(argc, argv);
    log_line("done\n");
    return status == 0 ? 0 : 1;
}
