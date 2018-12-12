#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>

#include "objecttemplates.h"
#include "cryptoutils.h"

int verbose = FALSE;

static void print_usage(void) {
    printf("Usage: kyber_test -k=[NUM]\n");
    printf("\t-k: security level of Kyber\n");
}

static void print_array(unsigned char * buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X", buffer[i]);

        if (i != (size - 1)) {
            printf(", ");
        }
    }
}

int main(int argc, char **argv) {
    TPM_RC			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;
    KYBER_KeyGen_In 	key_in;
    KYBER_KeyGen_Out 	key_out;
    KYBER_Enc_In 	    enc_in;
    KYBER_Enc_Out 	    enc_out;
    KYBER_Dec_In 	    dec_in;
    KYBER_Dec_Out 	    dec_out;

    // Arg Checking
    if (argc < 2 || argc > 3) {
        print_usage();
        exit(1);
    } else {
        // Set Kyber security level
        sscanf(argv[1], "-k=%hhu", &key_in.sec_sel);
        enc_in.sec_sel = key_in.sec_sel;
        dec_in.sec_sel = key_in.sec_sel;
    }

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "3");

    /* Start a TSS context */
    if (rc == 0) {
        rc = TSS_Create(&tssContext);
    }

    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
                 (RESPONSE_PARAMETERS *)&key_out,
                 (COMMAND_PARAMETERS *)&key_in,
                 NULL,
                 TPM_CC_KYBER_KeyGen,
                 TPM_RH_NULL, NULL, 0);
    }

    if (rc == 0) {
        printf("Kyber Public Key: [");
        print_array(key_out.public_key.b.buffer, key_out.public_key.b.size);
        printf("]\n");

        printf("Kyber Secret Key: [");
        print_array(key_out.secret_key.b.buffer, key_out.secret_key.b.size);
        printf("]\n");

        // Copy public key to the encryption input parameters
        memcpy(enc_in.public_key.b.buffer, key_out.public_key.b.buffer, key_out.public_key.b.size);
        enc_in.public_key.b.size = key_out.public_key.b.size;

        // Copy secret key to the decryption input parameters
        memcpy(dec_in.secret_key.b.buffer, key_out.secret_key.b.buffer, key_out.secret_key.b.size);
        dec_in.secret_key.b.size = key_out.secret_key.b.size;
    } else {
        printf("Key Generation Failed\n");
    }

    if (rc == 0) {
        printf("Encrypting with Generated Keys\n");
        rc = TSS_Execute(tssContext,
                 (RESPONSE_PARAMETERS *)&enc_out,
                 (COMMAND_PARAMETERS *)&enc_in,
                 NULL,
                 TPM_CC_KYBER_Enc,
                 TPM_RH_NULL, NULL, 0);
    }

    if (rc == 0) {
        printf("Kyber Shared Key: [");
        print_array(enc_out.shared_key.b.buffer, enc_out.shared_key.b.size);
        printf("]\n");

        printf("Kyber Cipher Text: [");
        print_array(enc_out.cipher_text.b.buffer, enc_out.cipher_text.b.size);
        printf("]\n");

        // Copy cipher text to the decryption input parameters
        memcpy(dec_in.cipher_text.b.buffer, enc_out.cipher_text.b.buffer, enc_out.cipher_text.b.size);
        dec_in.cipher_text.b.size = enc_out.cipher_text.b.size;
    } else {
        printf("Encryption Failed\n");
    }

    if (rc == 0) {
        printf("Decrypting with Generated Keys\n");
        rc = TSS_Execute(tssContext,
                 (RESPONSE_PARAMETERS *)&dec_out,
                 (COMMAND_PARAMETERS *)&dec_in,
                 NULL,
                 TPM_CC_KYBER_Dec,
                 TPM_RH_NULL, NULL, 0);
    }

    if (rc == 0) {
        printf("Kyber Shared Key: [");
        print_array(dec_out.shared_key.b.buffer, dec_out.shared_key.b.size);
        printf("]\n");
    } else {
        printf("Decryption Failed\n");
    }

    {
        TPM_RC rc1 = TSS_Delete(tssContext);
        if (rc == 0) {
            rc = rc1;
        }
    }

    return rc;
}

