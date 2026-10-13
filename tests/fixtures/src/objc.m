// Objective-C metadata fixture: a class hierarchy rooted in NSObject, a protocol, categories on a local and an
// imported class, class and instance methods, properties and ivars.
#import <Foundation/Foundation.h>

@protocol Named
- (NSString *)name;
@end

@interface Animal : NSObject <Named> {
    int _legs;
}
@property(nonatomic, copy) NSString *name;
@property(nonatomic) int legs;
+ (instancetype)animalWithName:(NSString *)name;
- (NSString *)speak;
@end

@implementation Animal
@synthesize legs = _legs;
+ (instancetype)animalWithName:(NSString *)name {
    Animal *animal = [[self alloc] init];
    animal.name = name;
    return animal;
}
- (NSString *)speak {
    return @"...";
}
@end

@interface Dog : Animal
@property(nonatomic) double weight;
+ (int)population;
- (NSString *)speak;
- (void)fetch:(id)thing;
@end

@implementation Dog
+ (int)population {
    return 42;
}
- (NSString *)speak {
    return @"woof";
}
- (void)fetch:(id)thing {
    NSLog(@"%@ fetched %@", self.name, thing);
}
@end

@interface Dog (Tricks)
- (void)rollOver;
+ (Dog *)goodBoy;
@end

@implementation Dog (Tricks)
- (void)rollOver {
    NSLog(@"%@ rolls over", self.name);
}
+ (Dog *)goodBoy {
    return [self animalWithName:@"Rex"];
}
@end

@interface NSString (Shout)
- (NSString *)shout;
@end

@implementation NSString (Shout)
- (NSString *)shout {
    return [self uppercaseString];
}
@end

int main(void) {
    @autoreleasepool {
        Dog *dog = [Dog goodBoy];
        dog.legs = 4;
        [dog fetch:[[dog speak] shout]];
        [dog rollOver];
        return [Dog population] == 42 ? 0 : 1;
    }
}
