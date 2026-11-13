// Objective-C message-send fixture: every way a send's receiver class is statically evident (self in instance
// and class methods, super, class references, +alloc / objc_alloc_init / objc_opt_new results), a category on a
// local superclass, a protocol method implemented by unrelated classes, and overrides that make a self send
// ambiguous. Each send's expected resolution is listed in objc_dispatch truth in the rampage-api tests.
#import <Foundation/Foundation.h>

@protocol Describable
- (NSString *)describe;
@end

@interface Shape : NSObject <Describable>
@property(nonatomic) double scale;
+ (instancetype)unitShape;
+ (NSString *)kind;
- (double)area;
- (double)scaledArea;
@end

@implementation Shape
+ (instancetype)unitShape {
    Shape *shape = [[self alloc] init];
    shape.scale = 1;
    return shape;
}
+ (NSString *)kind {
    return @"shape";
}
- (double)area {
    return 0;
}
- (double)scaledArea {
    return [self area] * self.scale;
}
- (NSString *)describe {
    return [NSString stringWithFormat:@"%@ %f", [[self class] kind], [self scaledArea]];
}
@end

@interface Circle : Shape
@property(nonatomic) double radius;
@end

@implementation Circle
- (instancetype)init {
    self = [super init];
    if (self) {
        _radius = 1;
    }
    return self;
}
+ (NSString *)kind {
    return [[super kind] stringByAppendingString:@"/circle"];
}
- (double)area {
    return 3.14159 * self.radius * self.radius;
}
- (NSString *)describe {
    return [[super describe] stringByAppendingString:@" (round)"];
}
@end

@interface Square : Shape
@property(nonatomic) double side;
+ (Square *)squareWithSide:(double)side;
@end

@implementation Square
+ (Square *)squareWithSide:(double)side {
    Square *square = [[Square alloc] init];
    square.side = side;
    return square;
}
- (double)area {
    return self.side * self.side;
}
@end

@interface Shape (Debug)
- (void)dump;
@end

@implementation Shape (Debug)
- (void)dump {
    NSLog(@"%@ area=%f", [self describe], [self scaledArea]);
}
@end

@interface Label : NSObject <Describable>
@property(nonatomic, copy) NSString *text;
@end

@implementation Label
- (NSString *)describe {
    return self.text ? self.text : @"label";
}
@end

__attribute__((noinline)) static NSString *describe_any(id<Describable> thing) {
    return [thing describe];
}

int main(void) {
    @autoreleasepool {
        Circle *circle = [[Circle alloc] init];
        Square *square = [Square squareWithSide:2];
        Shape *unit = [Shape unitShape];
        Label *label = [Label new];
        [circle dump];
        [square dump];
        NSLog(@"%@ %@ %@", describe_any(circle), describe_any(label), [unit describe]);
        return [Circle kind].length > 0 ? 0 : 1;
    }
}
