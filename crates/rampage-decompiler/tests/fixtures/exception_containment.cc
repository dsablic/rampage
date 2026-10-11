// Compile with -std=c++14, the vendor include path, librampage_ghidra.a and -lz; pass the specs directory.
#include "../../src/shim.cc"

#include <cassert>
#include <cstdio>
#include <new>
#include <sys/wait.h>
#include <unistd.h>

namespace {
bool failAllocations = false;
size_t allocations = 0;
size_t failAfter = 0;
bool allocationFailed = false;
}

void *operator new(size_t size) {
    if (failAllocations && allocations++ >= failAfter) {
        allocationFailed = true;
        throw std::bad_alloc();
    }
    if (void *memory = malloc(size == 0 ? 1 : size)) return memory;
    throw std::bad_alloc();
}

void *operator new[](size_t size) { return ::operator new(size); }
void operator delete(void *memory) noexcept { free(memory); }
void operator delete[](void *memory) noexcept { free(memory); }
void operator delete(void *memory, size_t) noexcept { free(memory); }
void operator delete[](void *memory, size_t) noexcept { free(memory); }

namespace {
const uint8_t code[] = {0x89, 0xf8, 0xc3};
const uint8_t data[] = {1, 0, 0, 0};
const uint64_t bases[] = {0x1000, 0x2000};
const uint8_t *const bytes[] = {code, data};
const size_t lengths[] = {sizeof(code), sizeof(data)};
const uint64_t sizes[] = {sizeof(code), sizeof(data)};
const uint8_t readable[] = {1, 1};
const uint8_t executable[] = {1, 0};
const uint8_t writable[] = {0, 1};

Handle *open(const char *home, const char *language = "x86:LE:64:default:gcc") {
    return static_cast<Handle *>(rampage_decomp_open(home, language, 2,
        bases, bytes, lengths, sizes, readable, executable, writable));
}

void inject(size_t after) {
    allocations = 0;
    failAfter = after;
    allocationFailed = false;
    failAllocations = true;
}

void disableInjection() { failAllocations = false; }

template <typename Test>
void childTest(const char *operation, size_t after, Test test) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        test();
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s failed after %zu allocations (status %d)\n", operation, after, status);
        abort();
    }
}

template <typename Test>
size_t countAllocations(Test test) {
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(descriptors[0]);
        inject(SIZE_MAX);
        test();
        disableInjection();
        assert(write(descriptors[1], &allocations, sizeof(allocations)) == sizeof(allocations));
        _exit(0);
    }
    close(descriptors[1]);
    size_t count = 0;
    assert(read(descriptors[0], &count, sizeof(count)) == sizeof(count));
    close(descriptors[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return count;
}

void checkPoisoned(Handle *handle) {
    assert(handle->poisoned);
    assert(rampage_decomp_error(handle) != nullptr);
    assert(rampage_decomp_token_count(handle) == 0);
    assert(rampage_decomp_results(handle) == nullptr);
    assert(rampage_decomp_function(handle, 0x1000, "identity", 0) == nullptr);
    assert(rampage_decomp_symbol(handle, 0x1000, "replacement") != nullptr);
    assert(rampage_decomp_import_target(handle, 0x2000) == 0);
    int32_t pointer = 9, integer = 9, longSize = 9;
    rampage_decomp_data_organization(handle, &pointer, &integer, &longSize);
    assert(pointer == 0 && integer == 0 && longSize == 0);
}

enum class Operation { Symbol, AddSymbol, Import, Prototype, Global, Parse, Modes, Function, Close };

void apply(Handle *handle, Operation operation) {
    switch (operation) {
    case Operation::Symbol:
        rampage_decomp_symbol(handle, 0x1000, "a_long_function_name_requiring_allocation"); break;
    case Operation::AddSymbol:
        rampage_decomp_add_symbol(handle, 0x1001, "a_long_function_name_requiring_allocation"); break;
    case Operation::Import:
        rampage_decomp_import(handle, 0x2000, 0, 0, "a_long_import_name_requiring_allocation"); break;
    case Operation::Prototype:
        rampage_decomp_prototype(handle, 0x1000, 0, "int4 identity(int4 argument_name)"); break;
    case Operation::Global:
        rampage_decomp_global(handle, 0x2000, "int4 a_long_global_name_requiring_allocation"); break;
    case Operation::Parse:
        rampage_decomp_parse_c(handle, "typedef int4 a_long_typedef_name_requiring_allocation;"); break;
    case Operation::Modes: {
        const uint64_t addresses[] = {0x1000, 0x1002};
        const uint8_t thumb[] = {1, 0};
        rampage_decomp_set_modes(handle, 2, addresses, thumb); break;
    }
    case Operation::Function:
        rampage_decomp_free_string(rampage_decomp_function(handle, 0x1000, "identity", 0)); break;
    case Operation::Close:
        rampage_decomp_close(handle); break;
    }
}

void sweepOperation(Handle *handle, const char *name, Operation operation, size_t count) {
    for (size_t after = 0; after < count; ++after) {
        childTest(name, after, [&] {
            inject(after);
            apply(handle, operation);
            bool failed = allocationFailed;
            disableInjection();
            if (operation != Operation::Close) {
                if (failed) checkPoisoned(handle);
                inject(0);
                rampage_decomp_close(handle);
            }
            disableInjection();
        });
    }
}

class ThrowingEmitter : public rampage::TokenEmitter {
public:
    explicit ThrowingEmitter(std::vector<rampage::Token> &tokens) : TokenEmitter(tokens) {}
    void clear() override { throw std::bad_alloc(); }
};

void testHelpers(Handle *handle) {
    childTest("recoverable parse error", 0, [&] {
        assert(rampage_decomp_parse_c(handle, "typedef @ broken;") != nullptr);
        assert(!handle->poisoned);
        assert(rampage_decomp_parse_c(handle, "typedef int4 recovered_type;") == nullptr);
        assert(rampage_decomp_error(handle) == nullptr);
        rampage_decomp_close(handle);
    });
    childTest("safe preparation cleanup", 0, [&] {
        inject(0);
        rampage_decomp_global(handle, 0x2000, "int4 a_long_global_name_requiring_allocation");
        disableInjection();
        checkPoisoned(handle);
        assert(!handle->unsafeCleanup);
        rampage_decomp_close(handle);
    });
    childTest("catch all", 0, [&] {
        const char *error = mutate(handle, [](bool &) { throw 17; });
        assert(error != nullptr);
        checkPoisoned(handle);
        rampage_decomp_close(handle);
    });
    childTest("error allocation", 0, [&] {
        LowlevelError error("A detailed native error requiring dynamic string allocation");
        inject(0);
        const char *message = mutate(handle, [&](bool &) { throw std::move(error); });
        disableInjection();
        assert(message != nullptr);
        assert(handle->fallbackError);
        checkPoisoned(handle);
        rampage_decomp_close(handle);
    });
    childTest("printer cleanup", 0, [&] {
        handle->arch->print->setEmitter(new ThrowingEmitter(handle->tokens));
        failDecompilation(handle, nullptr, "Native failure", true);
        checkPoisoned(handle);
        rampage_decomp_close(handle);
    });
    LimitedOutput buffer;
    std::ostream output(&buffer);
    assert(output.tellp() == std::streampos(0));
    output << "abc";
    assert(output.tellp() == std::streampos(3));
    output.seekp(output.tellp());
    assert(output.good());
    output.seekp(0);
    assert(output.fail());
    output.clear();
    output.seekp(1, std::ios::cur);
    assert(output.fail());
    assert(buffer.str() == "abc");
    const char *kind = "unchanged";
    uint64_t address = 7;
    uint8_t present = 1;
    assert(rampage_decomp_token(handle, SIZE_MAX, &kind, &address, &present) == nullptr);
    assert(kind == nullptr && address == 0 && present == 0);
    size_t start = 7, end = 9;
    assert(rampage_decomp_token_span(handle, SIZE_MAX, &start, &end) == 0);
    assert(start == 0 && end == 0);
    assert(rampage_decomp_token_span(handle, 0, nullptr, &end) == 0);
}
}

int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    if (argc == 3) {
        Handle *handle = open(argv[1]);
        assert(handle != nullptr && rampage_decomp_error(handle) == nullptr);
        assert(rampage_decomp_symbol(handle, 0x1000, "identity") == nullptr);
        inject(strtoul(argv[2], nullptr, 10));
        apply(handle, Operation::Function);
        disableInjection();
        checkPoisoned(handle);
        rampage_decomp_close(handle);
        return 0;
    }
    for (size_t after = 0; after < 96; ++after) {
        childTest("startup", after, [&] {
            inject(after);
            Handle *handle = open(argv[1]);
            bool failed = allocationFailed;
            disableInjection();
            if (handle != nullptr) {
                if (failed) checkPoisoned(handle);
                rampage_decomp_close(handle);
            }
            handle = open(argv[1]);
            assert(handle != nullptr);
            rampage_decomp_close(handle);
        });
    }
    Handle *handle = open(argv[1]);
    assert(handle != nullptr && rampage_decomp_error(handle) == nullptr);
    assert(rampage_decomp_symbol(handle, 0x1000, "identity") == nullptr);
    testHelpers(handle);
    for (size_t after = 0; after < 128; ++after) {
        childTest("open", after, [&] {
            inject(after);
            Handle *opened = open(argv[1]);
            bool failed = allocationFailed;
            disableInjection();
            if (opened != nullptr) {
                if (failed) checkPoisoned(opened);
                inject(0);
                rampage_decomp_close(opened);
                disableInjection();
            }
        });
    }
    size_t openAllocations = countAllocations([&] { rampage_decomp_close(open(argv[1])); });
    assert(openAllocations >= 128);
    for (size_t after = openAllocations - 32; after < openAllocations; ++after) {
        childTest("late open", after, [&] {
            inject(after);
            Handle *opened = open(argv[1]);
            disableInjection();
            assert(opened != nullptr);
            checkPoisoned(opened);
            rampage_decomp_close(opened);
        });
    }
    sweepOperation(handle, "symbol", Operation::Symbol, 32);
    sweepOperation(handle, "add symbol", Operation::AddSymbol, 32);
    sweepOperation(handle, "import", Operation::Import, 64);
    sweepOperation(handle, "prototype", Operation::Prototype, 64);
    sweepOperation(handle, "global", Operation::Global, 64);
    sweepOperation(handle, "parse", Operation::Parse, 64);
    sweepOperation(handle, "modes", Operation::Modes, 8);
    Handle *arm = open(argv[1], "ARM:LE:32:v8:default");
    assert(arm != nullptr && rampage_decomp_error(arm) == nullptr);
    size_t modeAllocations = countAllocations([&] { apply(arm, Operation::Modes); });
    sweepOperation(arm, "ARM modes", Operation::Modes, modeAllocations + 1);
    rampage_decomp_close(arm);
    size_t functionAllocations = countAllocations([&] { apply(handle, Operation::Function); });
    sweepOperation(handle, "function", Operation::Function, functionAllocations + 1);
    sweepOperation(handle, "close", Operation::Close, 8);
    char *text = rampage_decomp_function(handle, 0x1000, "identity", 0);
    assert(text != nullptr);
    size_t textLength = strlen(text);
    size_t spans = 0;
    for (size_t index = 0; index < rampage_decomp_token_count(handle); ++index) {
        size_t start = 0, end = 0;
        if (rampage_decomp_token_span(handle, index, &start, &end) == 0) continue;
        const char *kind = nullptr;
        uint64_t address = 0;
        uint8_t present = 0;
        const char *token = rampage_decomp_token(handle, index, &kind, &address, &present);
        assert(start <= end && end <= textLength);
        assert(end - start == strlen(token));
        assert(memcmp(text + start, token, end - start) == 0);
        ++spans;
    }
    assert(spans != 0);
    rampage_decomp_free_string(text);
    assert(rampage_decomp_results(handle) != nullptr);
    rampage_decomp_close(handle);
    rampage_decomp_close(nullptr);
    rampage_decomp_free_string(nullptr);
    puts("C ABI exception containment passed");
}
