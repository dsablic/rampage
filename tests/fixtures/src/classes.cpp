// A small polymorphic class hierarchy that forces the compiler to emit Itanium RTTI, for the stripped
// class-recovery fixture. Single and multiple inheritance are both present.
struct Shape {
    virtual ~Shape() {}
    virtual double area() const = 0;
};

struct Printable {
    virtual void print() const = 0;
};

struct Circle : Shape {
    double r;
    explicit Circle(double radius) : r(radius) {}
    double area() const override { return 3.14159 * r * r; }
};

struct Square : Shape, Printable {
    double s;
    explicit Square(double side) : s(side) {}
    double area() const override { return s * s; }
    void print() const override {}
};

static Circle circle(2.0);
static Square square(3.0);

Shape *first() { return &circle; }
Shape *second() { return &square; }
Printable *printable() { return &square; }

int main() {
    return static_cast<int>(first()->area() + second()->area());
}
