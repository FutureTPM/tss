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
    printf("Usage: dilithium_test -m=[NUM]\n");
    printf("\t-m: security mode of Dilithium\n");
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
    DILITHIUM_KeyGen_In 	key_in;
    DILITHIUM_KeyGen_Out 	key_out;

    // Arg Checking
    if (argc < 2 || argc > 3) {
        print_usage();
        exit(1);
    } else {
        // Set Kyber security level
        sscanf(argv[1], "-m=%hhu", &key_in.mode);
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
                 TPM_CC_DILITHIUM_KeyGen,
                 TPM_RH_NULL, NULL, 0);
    }

    if (rc == 0) {
        printf("Dilithium Public Key: [");
        print_array(key_out.public_key.b.buffer, key_out.public_key.b.size);
        printf("]\n");

        printf("Dilithium Secret Key: [");
        print_array(key_out.secret_key.b.buffer, key_out.secret_key.b.size);
        printf("]\n");
    } else {
        printf("Key Generation Failed\n");
    }

    {
        TPM_RC rc1 = TSS_Delete(tssContext);
        if (rc == 0) {
            rc = rc1;
        }
    }

    return rc;
}

