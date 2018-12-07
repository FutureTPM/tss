#ifndef KYBER_KEYGEN_FP_H
#define KYBER_KEYGEN_FP_H

typedef struct {
    TPM2B_KYBER_PUBLIC_KEY	public_key;
    TPM2B_KYBER_SECRET_KEY	secret_key;
} KYBER_KeyGen_Out;

TPM_RC
TPM2_KYBER_KeyGen(
		 KYBER_KeyGen_Out     *out            // OUT: output parameter list
		 );


#endif
