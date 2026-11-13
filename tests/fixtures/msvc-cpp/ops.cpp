// SPDX-License-Identifier: Apache-2.0
// Owned x86 fixture: a C-style operations table called through a struct (`ctx->ops->fn(ctx)`), a double load
// that is not a virtual call, beside one polymorphic class so the image has RTTI vftables. No CRT or SDK header is
// included or linked; the RTTI type descriptor's `type_info` vftable is an owned stand-in, as in shapes.cpp.

#define NOINLINE __declspec(noinline)

class type_info {
public:
    virtual ~type_info();

private:
    void* data_;
    char name_[1];
};
type_info::~type_info() {}

extern "C" const void* const rampage_type_info_vftable[2] = {nullptr, nullptr};
#pragma comment(linker, "/alternatename:??_7type_info@@6B@=_rampage_type_info_vftable")

volatile int g_sink;

typedef decltype(sizeof(0)) size_t;
void operator delete(void*) noexcept {}
void operator delete(void*, size_t) noexcept {}

extern "C" {

struct Context;

struct Operations {
    int (*open)(Context* context, int flags);
    int (*read)(Context* context, char* buffer, int size);
    void (*close)(Context* context);
};

struct Context {
    const Operations* ops;
    int handle;
};

NOINLINE int file_open(Context* context, int flags) { return context->handle = flags + 1; }
NOINLINE int file_read(Context* context, char* buffer, int size) {
    buffer[0] = static_cast<char>(context->handle);
    return size - 1;
}
NOINLINE void file_close(Context* context) { context->handle = 0; }

const Operations g_file_operations = {file_open, file_read, file_close};

// Each call loads the table from the context and the function from the table: `ctx->ops->fn(ctx, ...)`.
NOINLINE int run_operations(Context* context, char* buffer) {
    int total = context->ops->open(context, 4);
    total += context->ops->read(context, buffer, 8);
    context->ops->close(context);
    return total;
}

}  // extern "C"

class Counter {
public:
    virtual ~Counter() {}
    virtual int next() { return ++count_; }

private:
    int count_ = 0;
};

NOINLINE int count_twice(Counter* counter) { return counter->next() + counter->next(); }

extern "C" int ops_entry() {
    Context context{&g_file_operations, 0};
    char buffer[8];
    Counter counter;
    g_sink = count_twice(&counter);
    return run_operations(&context, buffer);
}
