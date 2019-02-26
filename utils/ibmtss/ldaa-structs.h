#ifndef LDAA_STRUCTS_H
#define LDAA_STRUCTS_H

#include <ibmtss/BaseTypes.h>
#include <ibmtss/ldaa-parms.h>

typedef struct {
  UINT32 coeffs[LDAA_N];
} ldaa_poly_t;

typedef struct {
    UINT32 coeffs[(2*(1<<LDAA_LOG_W)-1)*LDAA_N];
} ldaa_integer_matrix_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_R_t;

typedef struct {
    UINT32 v[(2*(1<<LDAA_LOG_W)-1)*LDAA_N];
} ldaa_permutation_t;

#endif
