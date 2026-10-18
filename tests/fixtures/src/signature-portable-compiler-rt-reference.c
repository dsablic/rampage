extern int __clzdi2(long long);
extern int __ctzdi2(long long);
extern int __paritydi2(long long);
extern int __popcountdi2(long long);
extern int __cmpdi2(long long, long long);
extern int __ucmpdi2(unsigned long long, unsigned long long);
extern long long __muldi3(long long, long long);
extern unsigned long long __udivmoddi4(unsigned long long, unsigned long long, unsigned long long *);

volatile unsigned long long input = 0x123456789abcdefULL;
volatile unsigned long long other = 43;
volatile unsigned long long sink;
unsigned long long remainder;

int profile_entry(void) {
  sink += __clzdi2(input);
  sink += __ctzdi2(input);
  sink += __paritydi2(input);
  sink += __popcountdi2(input);
  sink += __cmpdi2(input, other);
  sink += __ucmpdi2(input, other);
  sink += __muldi3(input, other);
  sink += __udivmoddi4(input, other, &remainder);
  return (int)(sink ^ remainder);
}
