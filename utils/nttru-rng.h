#ifndef NTTRU_RNG_H
#define NTTRU_RNG_H

#define _GNU_SOURCE

#include <unistd.h>

void randombytes(unsigned char *x, unsigned long long xlen);
void kernelrandombytes(unsigned char *buf, unsigned long long len);
static void kernelrandombytes_fallback(unsigned char *buf,
                                       unsigned long long  len);

#endif /* NTTRU_RNG_H */
