extern int __strverscmp(const char *, const char *);

volatile unsigned long long input = 0x123456789abcdefULL;
volatile unsigned long long other = 43;
volatile unsigned long long sink;
unsigned long long remainder;

int profile_entry(void) {
  sink += __strverscmp("profile10.42", "profile2.10");
  return (int)(sink ^ remainder);
}
