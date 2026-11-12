// SPDX-License-Identifier: Apache-2.0
// Suite v3, type propagation: one struct pointer carried through several functions (as a first argument, as a
// second argument, and through a context structure). The question asks which members (as offset and size) the
// call tree under job_run stores to, without giving the layout.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

struct job {
    uint8_t kind;
    uint8_t flags;
    uint16_t retries;
    uint32_t state;
    uint64_t deadline;
    char tag[12];
    uint32_t budget;
    const uint8_t *input;
    uint32_t length;
    uint32_t checksum;
    uint64_t total;
    int16_t priority;
    uint16_t owner;
    uint32_t errors;
};

struct run_context {
    uint32_t now;
    uint32_t verdict;
    struct job *job;
};

NOINLINE int job_validate(const struct job *job) {
    if (job->kind > 3 || job->length == 0 || job->input == NULL) {
        return 0;
    }
    return job->length <= job->budget;
}

NOINLINE uint32_t job_sum(struct job *job) {
    uint32_t sum = job->owner;
    for (uint32_t index = 0; index < job->length; index++) {
        sum = sum * 31u + job->input[index];
    }
    job->checksum = sum;
    return sum;
}

NOINLINE void job_account(uint32_t now, struct job *job) {
    uint32_t sum = job_sum(job);
    job->total += sum & 0xFFFFu;
    if (job->flags & 4u) {
        job->deadline = (uint64_t)now + (uint64_t)job->retries * 1000u;
    }
}

NOINLINE void job_finish(struct run_context *context) {
    struct job *job = context->job;
    if (context->verdict) {
        job->state = 2u + (uint32_t)(job->priority < 0);
        job->retries = (uint16_t)(job->retries + 1u + job->kind);
    } else {
        job->errors++;
        job->state = 7;
    }
}

NOINLINE int job_run(struct job *job, uint32_t now) {
    struct run_context context = {now, 0, job};
    context.verdict = (uint32_t)job_validate(job);
    if (context.verdict) {
        job_account(now, job);
    }
    job_finish(&context);
    return (int)context.verdict;
}

// Host harness: fill the job from a pattern, run it, and print the members whose bytes changed.
#define MEMBERS(X) X(kind) X(flags) X(retries) X(state) X(deadline) X(tag) X(budget) X(input) X(length) \
    X(checksum) X(total) X(priority) X(owner) X(errors)

int main(int argc, char **argv) {
    static const uint8_t payload[] = {3, 1, 4, 1, 5, 9, 2, 6};
    struct job job, before;
    if (argc < 5) {
        puts("usage: jobs KIND FLAGS LENGTH FILL");
        return 2;
    }
    memset(&job, (int)strtoul(argv[4], NULL, 0), sizeof job);
    job.kind = (uint8_t)strtoul(argv[1], NULL, 0);
    job.flags = (uint8_t)strtoul(argv[2], NULL, 0);
    job.length = (uint32_t)strtoul(argv[3], NULL, 0);
    job.input = payload;
    job.budget = 64;
    before = job;
    printf("result=%d\n", job_run(&job, 0x1234567u));
#define REPORT(name) \
    if (memcmp(&job.name, &before.name, sizeof job.name) != 0) { \
        puts(#name); \
    }
    MEMBERS(REPORT)
    return 0;
}
