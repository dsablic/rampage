// SPDX-License-Identifier: Apache-2.0
// Owned MSVC-ABI C++ fixture: no CRT or SDK header is included and nothing from them is linked. The handful of
// runtime entry points the ABI needs (frame handler, throw, purecall, terminate) are imports declared in
// runtime-*.def; `type_info`, operator new/delete and the entry point are defined here.

typedef decltype(sizeof(0)) size_t;

class type_info {
public:
    virtual ~type_info();

private:
    void* data_;
    char name_[1];
};
type_info::~type_info() {}

// Every RTTI type descriptor points at `type_info`'s vftable, which the CRT normally supplies. Nothing here
// constructs a `type_info`, so the compiler emits no vftable for it; this owned stand-in takes its place.
extern "C" const void* const rampage_type_info_vftable[2] = {nullptr, nullptr};
#ifdef _M_IX86
#pragma comment(linker, "/alternatename:??_7type_info@@6B@=_rampage_type_info_vftable")
#else
#pragma comment(linker, "/alternatename:??_7type_info@@6B@=rampage_type_info_vftable")
#endif

#define NOINLINE __declspec(noinline)

static char g_arena[1 << 16];
static size_t g_arena_used;
volatile int g_selector = 3;
volatile int g_sink;

void* operator new(size_t size) {
    size = (size + 15) & ~static_cast<size_t>(15);
    void* block = g_arena + g_arena_used;
    g_arena_used += size;
    return block;
}
void operator delete(void*) noexcept {}
void operator delete(void*, size_t) noexcept {}

namespace geo {

// Abstract root with pure virtuals and a virtual destructor.
class Shape {
public:
    explicit Shape(int id) : id_(id) {}
    virtual ~Shape() { g_sink = id_; }
    virtual int area() const = 0;
    virtual int perimeter() const = 0;
    virtual const char* name() const { return "shape"; }
    int id() const { return id_; }

protected:
    int id_;
};

// Single inheritance.
class Rect : public Shape {
public:
    Rect(int id, int w, int h) : Shape(id), w_(w), h_(h) {}
    int area() const override { return w_ * h_; }
    int perimeter() const override { return 2 * (w_ + h_); }
    const char* name() const override { return "rect"; }

protected:
    int w_, h_;
};

class Square final : public Rect {
public:
    Square(int id, int side) : Rect(id, side, side) {}
    const char* name() const override { return "square"; }
};

class Circle : public Shape {
public:
    Circle(int id, int r) : Shape(id), r_(r) {}
    ~Circle() override { g_sink = r_; }
    int area() const override { return 3 * r_ * r_; }
    int perimeter() const override { return 6 * r_; }
    const char* name() const override { return "circle"; }

private:
    int r_;
};

// Unrelated interfaces for multiple inheritance.
class Drawable {
public:
    virtual ~Drawable() {}
    virtual void draw(int depth) = 0;
    virtual int layer() const { return 0; }
};

class Serializable {
public:
    virtual ~Serializable() {}
    virtual int serialize(char* out, int capacity) const = 0;
};

// Multiple inheritance: three vftables and adjustor thunks.
class Sprite : public Rect, public Drawable, public Serializable {
public:
    Sprite(int id, int w, int h, int layer) : Rect(id, w, h), layer_(layer) {}
    void draw(int depth) override { g_sink = depth + layer_; }
    int layer() const override { return layer_; }
    int serialize(char* out, int capacity) const override {
        int written = 0;
        for (const char* text = name(); *text && written < capacity; ++text) out[written++] = *text;
        return written;
    }
    const char* name() const override { return "sprite"; }

private:
    int layer_;
};

// Virtual inheritance diamond: vbtables and a shared virtual base.
class Node {
public:
    virtual ~Node() {}
    virtual int weight() const { return 1; }
    int tag = 7;
};
class LeftNode : public virtual Node {
public:
    int weight() const override { return 2; }
    virtual int left() const { return 10; }
    int l = 1;
};
class RightNode : public virtual Node {
public:
    virtual int right() const { return 20; }
    int r = 2;
};
class JoinNode : public LeftNode, public RightNode {
public:
    int weight() const override { return 5; }
    int left() const override { return 11; }
    int right() const override { return 21; }
    int j = 3;
};

}  // namespace geo

// Class templates with virtual members: one vftable per instantiation.
template <typename T>
class Box {
public:
    explicit Box(T value) : value_(value) {}
    virtual ~Box() {}
    virtual T get() const { return value_; }
    virtual void set(T value) { value_ = value; }

private:
    T value_;
};

template <typename T, int N>
class FixedStack : public Box<T> {
public:
    FixedStack() : Box<T>(T()), count_(0) {}
    NOINLINE bool push(T value) {
        if (count_ == N) return false;
        items_[count_++] = value;
        return true;
    }
    T get() const override { return count_ ? items_[count_ - 1] : T(); }

private:
    T items_[N];
    int count_;
};

// Exception types: a small hierarchy thrown by value and caught by reference.
struct Error {
    explicit Error(int code) : code(code) {}
    virtual ~Error() {}
    virtual const char* what() const { return "error"; }
    int code;
};
struct RangeError : Error {
    RangeError(int code, int index) : Error(code), index(index) {}
    const char* what() const override { return "range"; }
    int index;
};

// A local with a non-trivial destructor: unwinding past it needs a cleanup funclet.
struct Guard {
    NOINLINE explicit Guard(int token) : token(token) { g_sink = token; }
    NOINLINE ~Guard() { g_sink = -token; }
    int token;
};

NOINLINE int checked_index(int index, int limit) {
    if (index < 0) throw 42;
    if (index >= limit) throw RangeError(2, index);
    if (index == 13) throw Error(13);
    return index;
}

// Typed catches, by reference, by value and catch-all, with destructors to unwind.
NOINLINE int guarded_lookup(const int* table, int limit, int index) {
    Guard outer(index);
    try {
        Guard inner(limit);
        return table[checked_index(index, limit)];
    } catch (const RangeError& error) {
        return -error.index;
    } catch (const Error& error) {
        return -error.code;
    } catch (int value) {
        return value;
    } catch (...) {
        return -1;
    }
}

// Nested try blocks and a rethrow.
NOINLINE int nested_handlers(int index) {
    Guard guard(1);
    try {
        try {
            return checked_index(index, 8);
        } catch (int) {
            Guard again(2);
            throw;
        }
    } catch (const Error&) {
        return 100;
    } catch (...) {
        return 200;
    }
}

// Cleanup only: no try block, just destructors on the unwind path.
NOINLINE int cleanup_only(int index) {
    Guard guard(index);
    Guard second(checked_index(index, 4));
    return second.token + checked_index(index + 1, 6);
}

// A dense switch that becomes a jump table.
NOINLINE int classify(int kind) {
    switch (kind) {
        case 0: return 11;
        case 1: g_sink = 5; return 23;
        case 2: g_sink = 9; return 37;
        case 3: return checked_index(kind, 2);
        case 4: g_sink = 1; return 59;
        case 5: return cleanup_only(kind);
        case 6: g_sink = 4; return 73;
        case 7: return 89;
        default: return -1;
    }
}

// Calling conventions; on x64 these keywords are accepted and ignored.
NOINLINE int __cdecl cdecl_sum(int a, int b, int c) { return a + b * 2 + c * 3; }
NOINLINE int __stdcall stdcall_sum(int a, int b, int c) { return a * 5 + b * 7 + c * 11; }
NOINLINE int __fastcall fastcall_sum(int a, int b, int c) { return a * 13 + b * 17 + c * 19; }
NOINLINE int __vectorcall vectorcall_sum(int a, int b, int c) { return a * 23 + b * 29 + c * 31; }

struct Accumulator {
    int total;
    NOINLINE int add(int value) { return total += value; }
    NOINLINE int __stdcall add_stdcall(int value) { return total += value * 2; }
    NOINLINE static int twice(int value) { return value * 2; }
};

// Virtual calls through base pointers; the selector is volatile so nothing is devirtualized.
NOINLINE geo::Shape* make_shape(int kind) {
    switch (kind) {
        case 0: return new geo::Rect(1, 2, 3);
        case 1: return new geo::Square(2, 4);
        case 2: return new geo::Circle(3, 5);
        default: return new geo::Sprite(4, 6, 7, 8);
    }
}

NOINLINE int measure(const geo::Shape* shape) { return shape->area() + shape->perimeter() + shape->name()[0]; }

NOINLINE int render(geo::Drawable* drawable, int depth) {
    drawable->draw(depth);
    return drawable->layer();
}

NOINLINE int store(const geo::Serializable* object, char* out) { return object->serialize(out, 16); }

NOINLINE int walk(const geo::Node* node) { return node->weight() + node->tag; }
NOINLINE int walk_left(const geo::LeftNode* node) { return node->left() + node->l; }
NOINLINE int walk_right(const geo::RightNode* node) { return node->right() + node->r; }

NOINLINE int diamond() {
    geo::JoinNode join;
    geo::LeftNode left;
    geo::RightNode right;
    return walk(&join) + walk_left(&join) + walk_right(&join) + walk(&left) + walk_right(&right);
}

NOINLINE int unbox(const Box<int>* box) { return box->get(); }
NOINLINE int unbox_short(Box<short>* box) {
    box->set(3);
    return box->get();
}
NOINLINE char unbox_text(const Box<const char*>* box) { return box->get()[0]; }

NOINLINE int templates() {
    Box<int> number(5);
    Box<const char*> text("box");
    FixedStack<int, 4> stack;
    FixedStack<short, 8> shorts;
    stack.push(g_selector);
    shorts.push(static_cast<short>(g_selector));
    return unbox(&number) + unbox_text(&text) + unbox(&stack) + unbox_short(&shorts);
}

extern "C" int entry() {
    static const int table[8] = {1, 2, 3, 5, 8, 13, 21, 34};
    int total = 0;
    geo::Shape* shape = make_shape(g_selector);
    total += measure(shape);
    delete shape;
    geo::Sprite sprite(9, 1, 2, 3);
    geo::Circle circle(10, 2);
    char buffer[16];
    total += render(&sprite, 2) + store(&sprite, buffer) + measure(&circle);
    total += diamond() + templates();
    total += guarded_lookup(table, 8, g_selector) + nested_handlers(g_selector) + cleanup_only(g_selector);
    total += classify(g_selector);
    total += cdecl_sum(1, 2, 3) + stdcall_sum(4, 5, 6) + fastcall_sum(7, 8, 9) + vectorcall_sum(1, 2, 3);
    Accumulator accumulator{total};
    total += accumulator.add(3) + accumulator.add_stdcall(4) + Accumulator::twice(g_selector);
    return total;
}
