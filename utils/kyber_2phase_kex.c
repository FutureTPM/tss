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
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscryptoh.h>

static void printUsage(void);

int verbose = TRUE;

int main(int argc, char *argv[])
{
	TPM_RC 			rc = 0;
	int 			i;    /* argc iterator */
	TSS_CONTEXT 		*tssContext = NULL;
	Kyber_2Phase_KEX_In   in;
	Kyber_2Phase_KEX_Out  out;
	TPMI_DH_OBJECT      	static_key_handle = 0;
	TPMI_DH_OBJECT      	alice_static_key_handle = 0;
	TPMI_DH_OBJECT      	ephemeral_key_handle = 0;
	const char          	*cFilename_in_static = NULL;
	const char          	*cFilename_out_1 = NULL;
	const char          	*cFilename_out_2 = NULL;
	const char       		*ssFilename = NULL;
	const char          	*keyPassword = NULL;
	TPMI_SH_AUTH_SESSION        sessionHandle0 = TPM_RS_PW;
	unsigned int                sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION        sessionHandle1 = TPM_RH_NULL;
	unsigned int                sessionAttributes1 = 0;
	TPMI_SH_AUTH_SESSION        sessionHandle2 = TPM_RH_NULL;
	unsigned int                sessionAttributes2 = 0;

	setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	/* command line argument defaults */

	for (i = 1; (i < argc) && (rc == 0); i++) {
		if (strcmp(argv[i], "-hk") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &static_key_handle);
			}
			else {
				printf("Missing parameter for -hk\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-hke") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &ephemeral_key_handle);
			}
			else {
				printf("Missing parameter for -hke\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-hka") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &alice_static_key_handle);
			}
			else {
				printf("Missing parameter for -hka\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-cs") == 0) {
			i++;
			if (i < argc) {
				cFilename_in_static = argv[i];
			}
			else {
				printf("-cs option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-c1") == 0) {
			i++;
			if (i < argc) {
				cFilename_out_1 = argv[i];
			}
			else {
				printf("-c1 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-c2") == 0) {
			i++;
			if (i < argc) {
				cFilename_out_2 = argv[i];
			}
			else {
				printf("-c2 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-ss") == 0) {
			i++;
			if (i < argc) {
				ssFilename = argv[i];
			}
			else {
				printf("-ss option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-pwdk") == 0) {
			i++;
			if (i < argc) {
				keyPassword = argv[i];
			}
			else {
				printf("-pwdk option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-se0") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &sessionHandle0);
			}
			else {
				printf("Missing parameter for -se0\n");
				printUsage();
			}
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &sessionAttributes0);
				if (sessionAttributes0 > 0xff) {
					printf("Out of range session attributes for -se0\n");
					printUsage();
				}
			}
			else {
				printf("Missing parameter for -se0\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-se1") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &sessionHandle1);
			}
			else {
				printf("Missing parameter for -se1\n");
				printUsage();
			}
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &sessionAttributes1);
				if (sessionAttributes1 > 0xff) {
					printf("Out of range session attributes for -se1\n");
					printUsage();
				}
			}
			else {
				printf("Missing parameter for -se1\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-se2") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &sessionHandle2);
			}
			else {
				printf("Missing parameter for -se2\n");
				printUsage();
			}
			i++;
			if (i < argc) {
				sscanf(argv[i], "%x", &sessionAttributes2);
				if (sessionAttributes2 > 0xff) {
					printf("Out of range session attributes for -se2\n");
					printUsage();
				}
			}
			else {
				printf("Missing parameter for -se2\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-h") == 0) {
			printUsage();
		}
		else if (strcmp(argv[i], "-v") == 0) {
			verbose = TRUE;
			TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
		}
		else {
			printf("\n%s is not a valid option\n", argv[i]);
			printUsage();
		}
	}
	if (static_key_handle == 0) {
		printf("Missing handle parameter -hk\n");
		printUsage();
	}
	if (ephemeral_key_handle == 0) {
		printf("Missing handle parameter -hke\n");
		printUsage();
	}
	if (rc == 0) {
		in.static_key = static_key_handle;
		in.ephemeral_key = ephemeral_key_handle;
        in.alice_static_key = alice_static_key_handle;
	}

	if ((rc == 0) && (cFilename_in_static != NULL)) {
		rc = TSS_File_ReadStructure(&in.cipher_text_static,
			(UnmarshalFunction_t)TSS_TPM2B_KYBER_CIPHER_TEXT_Unmarshalu,
			cFilename_in_static);
	}
	else
	{
		in.cipher_text_static.b.size = 0;
	}

    if (verbose)
    {
        printf("Static Cipher Text: ");
        UINT32 i;
        for (i = 0; in.cipher_text_static.b.size != 0 && i < in.cipher_text_static.b.size - 1; i++)
            printf("%02X", in.cipher_text_static.b.buffer[i]);
        printf("\n");
    }

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
			TPM_CC_KYBER_2Phase_KEX,
			sessionHandle0, keyPassword, sessionAttributes0,
			sessionHandle1, NULL, sessionAttributes1,
			sessionHandle2, NULL, sessionAttributes2,
			TPM_RH_NULL, NULL, 0);
	}
	{
		TPM_RC rc1 = TSS_Delete(tssContext);
		if (rc == 0) {
			rc = rc1;
		}
	}

	if ((rc == 0) && (ssFilename != NULL)) {
		rc = TSS_File_WriteStructure(&out.shared_key,
			(MarshalFunction_t)TSS_TPM2B_KYBER_SHARED_KEY_Marshalu,
			ssFilename);
	}

	if ((rc == 0) && (cFilename_out_1 != NULL)) {
		rc = TSS_File_WriteStructure(&out.cipher_text_1,
			(MarshalFunction_t)TSS_TPM2B_KYBER_CIPHER_TEXT_Marshalu,
			cFilename_out_1);
	}

	if ((rc == 0) && (cFilename_out_2 != NULL)) {
		rc = TSS_File_WriteStructure(&out.cipher_text_2,
			(MarshalFunction_t)TSS_TPM2B_KYBER_CIPHER_TEXT_Marshalu,
			cFilename_out_2);
	}

	if (rc == 0) {
		if (verbose)
		{
			printf("Shared Key: ");
            UINT32 i;
			for (i = 0; out.shared_key.b.size != 0 && i < out.shared_key.b.size - 1; i++)
				printf("%02X", out.shared_key.b.buffer[i]);
			printf("\n");
		}
		if (verbose)
		{
			printf("Cipher Text 1: ");
            UINT32 i;
			for (i = 0; out.cipher_text_1.b.size != 0 && i < out.cipher_text_1.b.size - 1; i++)
				printf("%02X", out.cipher_text_1.b.buffer[i]);
			printf("\n");
		}
		if (verbose)
		{
			printf("Cipher Text 2: ");
            UINT32 i;
			for (i = 0; out.cipher_text_2.b.size != 0 && i < out.cipher_text_2.b.size - 1; i++)
				printf("%02X", out.cipher_text_2.b.buffer[i]);
			printf("\n");
		}
		if (verbose) printf("Kyber 2Phase Key Exchange: success\n");
	}
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("Kyber 2Phase Key Exchange: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}


static void printUsage(void)
{
	printf("\n");
	printf("Kyber 2Phase Key Exchange Mutually Authenticated\n");
	printf("\n");
	printf("Runs TPM2_KYBER_2Phase_KEX\n");
	printf("\n");
	printf("\t-hk unrestricted decryption static key handle\n");
	printf("\t-hke unrestricted decryption ephemeral public key handle\n");
	printf("\t-hke unrestricted decryption static public key handle\n");
	printf("\t[-pwdk password for key (default empty)]\n");
	printf("\t-cs cipher object input file name encapsulated with static key \n");
	printf("\t-ss shared secret output data file name (default do not save)]\n");
	printf("\t-c1 cipher object output file name encapsulated with static key (default do not save)\n");
	printf("\t-c2 cipher object output file name encapsulated with ephemeral key (default do not save)\n");
	printf("\n");
	printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
	printf("\t\t01 continue\n");
	printf("\t\t20 command decrypt\n");
	printf("\t\t40 response encrypt\n");
	exit(1);
}
