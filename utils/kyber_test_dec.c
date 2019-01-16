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
    printf("Usage: kyber_test_dec -k=[NUM] -sk=[FILE] -ct=[FILE]\n");
    printf("\t-k: security level of Kyber\n");
    printf("\t-sk: file which contains the secret key\n");
    printf("\t-ct: file which contains the cipher text\n");
}

static void print_array(unsigned char * buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X", buffer[i]);

        if (i != (size - 1)) {
            printf(", ");
        }
    }
}

static void read_file(char* file, unsigned char * dst, size_t size) {
    FILE* fd_file = fopen(file, "r");
    char buf[8192];
    fgets(buf, 8192, fd_file);

    for (size_t i = 0; i < size * 2; i++) {
        char c = buf[i];
        int n = 0;
        if ('0' <= c && c <= '9') {
            n = c - '0';
        } else if ('a' <= c && c <= 'f') {
            n = 10 + c - 'a';
        } else if('A' <= c && c <= 'F') {
            n = 10 + c - 'A';
        }
        dst[i / 2] = (dst[i / 2] << 4) | n;
    }

    fclose(fd_file);
}

int main(int argc, char **argv) {
    TPM_RC			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;
    KYBER_Dec_In 	    in;
    KYBER_Dec_Out 	    out;
    char secret_key_file[1024];
    char cipher_text_file[1024];

    // Arg Checking
    if (argc < 4 || argc > 5) {
        print_usage();
        exit(1);
    } else {
        // Set Kyber security level
        sscanf(argv[1], "-k=%hhu", &in.sec_sel);
        // Read secret key file
        sscanf(argv[2], "-sk=%s", secret_key_file);
        // Read cipher text file
        sscanf(argv[3], "-ct=%s", cipher_text_file);
    }

    read_file(secret_key_file, in.secret_key.b.buffer, 1632);
    in.secret_key.b.size = 1632;
    read_file(cipher_text_file, in.cipher_text.b.buffer, 800);
    in.cipher_text.b.size = 800;

    printf("Secret Key: [");
    print_array(in.secret_key.b.buffer, in.secret_key.b.size);
    printf("]\n");

    printf("Cipher Text: [");
    print_array(in.cipher_text.b.buffer, in.cipher_text.b.size);
    printf("]\n");

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "3");

    /* Start a TSS context */
    if (rc == 0) {
        rc = TSS_Create(&tssContext);
    }

    if (rc == 0) {
        printf("Decrypting with Generated Keys\n");
        rc = TSS_Execute(tssContext,
                 (RESPONSE_PARAMETERS *)&out,
                 (COMMAND_PARAMETERS *)&in,
                 NULL,
                 TPM_CC_KYBER_Dec,
                 TPM_RH_NULL, NULL, 0);
    }

    if (rc == 0) {
        printf("Kyber Shared Key: [");
        print_array(out.shared_key.b.buffer, out.shared_key.b.size);
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
