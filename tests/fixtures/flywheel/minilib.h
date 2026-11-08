#ifndef MINILIB_H
#define MINILIB_H
unsigned ml_checksum(const unsigned char *data, unsigned length);
void ml_reverse(unsigned char *data, unsigned length);
int ml_find(const unsigned char *data, unsigned length, unsigned char wanted);
unsigned ml_lookup(unsigned index);
unsigned long ml_sum_squares(const int *values, unsigned count);
unsigned ml_mix(unsigned a, unsigned b, unsigned c);
unsigned ml_scale(const unsigned *values, unsigned count);
#endif
