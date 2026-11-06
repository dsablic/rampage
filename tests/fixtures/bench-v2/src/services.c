// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: a constant table of fixed-size records holding a string pointer, built stripped
// for x86-64 Linux. The task asks for the name and timeout of the record with a given port.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct service {
    const char *name;
    uint16_t port;
    uint8_t proto;
    uint8_t flags;
    uint32_t timeout_ms;
};

static const struct service services[] = {
    {"gopher-relay", 7070, 6, 0x01, 1500},  {"orchid-sync", 9443, 6, 0x03, 2500},
    {"lantern", 5353, 17, 0x00, 300},       {"quarry-admin", 8443, 6, 0x07, 45000},
    {"tidepool", 8080, 6, 0x01, 30000},     {"ember-metrics", 9100, 6, 0x02, 5000},
    {"basalt", 4433, 17, 0x05, 12000},      {"willow-cache", 6380, 6, 0x00, 750},
    {"quarry-public", 8444, 6, 0x01, 15000}, {"saffron", 2049, 17, 0x04, 60000},
    {"kestrel-push", 5223, 6, 0x02, 90000}, {"marl", 1883, 6, 0x00, 10000},
};

__attribute__((noinline)) const struct service *find_service(uint16_t port) {
    for (size_t i = 0; i < sizeof services / sizeof services[0]; i++) {
        if (services[i].port == port) {
            return &services[i];
        }
    }
    return NULL;
}

__attribute__((noinline)) uint32_t service_timeout(uint16_t port) {
    const struct service *service = find_service(port);
    return service ? service->timeout_ms : 0;
}

int main(int argc, char **argv) {
    uint16_t port = argc > 1 ? (uint16_t)atoi(argv[1]) : 80;
    const struct service *service = find_service(port);
    if (service == NULL) {
        puts("unknown");
        return 1;
    }
    printf("%s proto=%u flags=%u timeout=%u\n", service->name, service->proto, service->flags,
           service_timeout(port));
    return 0;
}
