/*
 * MIT License
 *
 * Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			    rc = 0;
    int				    i;                         /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NTTRU_Encrypt_In 	in;
    NTTRU_Encrypt_Out 	out;
    TPMI_DH_OBJECT		keyHandle = 0;
    const char			*decryptFilename = NULL;
    const char			*encryptFilename = NULL;

    uint32_t			written = 0;
    size_t 			    length = 0;
    uint8_t			    *buffer = NULL;            /* for the free */

    setvbuf(stdout, 0, _IONBF, 0);                 /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-id") == 0) {
	    i++;
	    if (i < argc) {
		decryptFilename = argv[i];
	    }
	    else {
		printf("-id option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oe") == 0) {
	    i++;
	    if (i < argc) {
		encryptFilename = argv[i];
	    }
	    else {
		printf("-oe option needs a value\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (decryptFilename == NULL) {
	printf("Missing decrypted file -id\n");
	printUsage();
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* must be freed by caller */
				     &length,
				     decryptFilename);
    }
    if (rc == 0) {
	if (length > 256) {
	    printf("Input data too long %u\n", (unsigned int)length);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	in.keyHandle = keyHandle;

	{
	    in.message.t.size = (uint16_t)length;	/* cast safe, range tested above */
	    memcpy(in.message.t.buffer, buffer, length);
	}
    }
    free (buffer);
    buffer = NULL;
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NTTRU_Encrypt,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (encryptFilename != NULL)) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				   &written,
				   &out.outData,
				   (MarshalFunction_t)TSS_TPM2B_NTTRU_ENCRYPT_Marshalu);
    }
    if ((rc == 0) && (encryptFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(buffer + sizeof(uint32_t),
				      written - sizeof(uint32_t),
				      encryptFilename);
    }
    if (rc == 0) {
	if (verbose) printf("NTTRUencrypt: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("NTTRUencrypt: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(buffer);	/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("NTTRUencrypt\n");
    printf("\n");
    printf("Runs TPM2_NTTRU_Encrypt\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t-id\tdecrypt file name\n");
    printf("\t[-oe\tencrypt file name (default do not save)]\n");
    exit(1);
}
