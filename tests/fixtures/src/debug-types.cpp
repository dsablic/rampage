// SPDX-License-Identifier: Apache-2.0; original nested C++ fixture, never executed.
#if defined(_WIN32)
extern "C" { int _fltused = 0; }
#endif

struct DebugCell { int count; double level; };

class DebugOwner {
public:
    DebugCell cells[2];
    int bias;
    DebugOwner *next;
    __attribute__((noinline)) double evaluate(int index) const;
};

double DebugOwner::evaluate(int index) const
{
    const DebugCell &cell = cells[index & 1];
    return cell.level + cell.count + bias;
}

DebugOwner debug_owner = { { { 3, 1.5 }, { 7, 2.5 } }, 5, nullptr };

extern "C" __attribute__((noinline)) double debug_cpp_query(DebugOwner *owner, int index)
{
    return owner->evaluate(index);
}

extern "C" int debug_cpp_main(void)
{
    return static_cast<int>(debug_cpp_query(&debug_owner, 1));
}

static_assert(sizeof(DebugCell) == 16, "cell size");
static_assert(sizeof(DebugOwner) == 48, "owner size");
static_assert(__builtin_offsetof(DebugOwner, bias) == 32, "bias offset");
static_assert(__builtin_offsetof(DebugOwner, next) == 40, "self pointer offset");

extern "C" const unsigned int debug_cpp_layout[] = {
    sizeof(DebugCell), __alignof__(DebugCell), __builtin_offsetof(DebugCell, count),
    __builtin_offsetof(DebugCell, level), sizeof(DebugOwner), __alignof__(DebugOwner),
    __builtin_offsetof(DebugOwner, cells), __builtin_offsetof(DebugOwner, bias),
    __builtin_offsetof(DebugOwner, next)
};
