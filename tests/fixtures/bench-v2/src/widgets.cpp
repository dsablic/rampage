// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: a polymorphic hierarchy with single and multiple inheritance, built stripped for
// x86-64 Linux with RTTI. Tasks ask for the global-namespace hierarchy and for one virtual call's target.
// Every class has an out-of-line key function, so each vtable and type_info is emitted exactly once.
#include <cstdio>

struct Node {
    virtual ~Node();
    virtual int render(int depth) const;
    virtual const char *kind() const;
    int id = 0;
};

struct Serializable {
    virtual ~Serializable();
    virtual int serialize(char *out, int room) const = 0;
};

struct Widget : Node {
    ~Widget() override;
    int render(int depth) const override;
    int width = 10;
};

struct Button : Widget, Serializable {
    ~Button() override;
    int render(int depth) const override;
    const char *kind() const override;
    int serialize(char *out, int room) const override;
    int clicks = 0;
};

struct Slider : Widget {
    ~Slider() override;
    int render(int depth) const override;
    const char *kind() const override;
    int position = 50;
};

struct Toggle : Button {
    ~Toggle() override;
    const char *kind() const override;
    bool on = false;
};

struct Logger : Serializable {
    ~Logger() override;
    int serialize(char *out, int room) const override;
    int lines = 0;
};

Node::~Node() {}
int Node::render(int depth) const { return depth + id; }
const char *Node::kind() const { return "node"; }
Serializable::~Serializable() {}
Widget::~Widget() {}
int Widget::render(int depth) const { return depth * 2 + width; }
Button::~Button() {}
int Button::render(int depth) const { return depth * 3 + clicks; }
const char *Button::kind() const { return "button"; }
int Button::serialize(char *out, int room) const { return std::snprintf(out, room, "button:%d", clicks); }
Slider::~Slider() {}
int Slider::render(int depth) const { return depth * 5 + position; }
const char *Slider::kind() const { return "slider"; }
Toggle::~Toggle() {}
const char *Toggle::kind() const { return on ? "toggle-on" : "toggle-off"; }
Logger::~Logger() {}
int Logger::serialize(char *out, int room) const { return std::snprintf(out, room, "logger:%d", lines); }

// The task's call site: one virtual call through the Node vtable's render slot.
__attribute__((noinline)) int draw(const Node *node, int depth) { return node->render(depth) + 1; }

__attribute__((noinline)) int save(const Serializable *item, char *out, int room) {
    return item->serialize(out, room);
}

__attribute__((noinline)) Node *make(int which) {
    switch (which) {
    case 0: return new Widget;
    case 1: return new Button;
    case 2: return new Slider;
    default: return new Toggle;
    }
}

int main(int argc, char **argv) {
    (void)argv;
    Node *node = make(argc);
    char buffer[32];
    Logger logger;
    int total = draw(node, argc) + save(&logger, buffer, sizeof buffer);
    std::printf("%s %d %s\n", node->kind(), total, buffer);
    delete node;
    return 0;
}
