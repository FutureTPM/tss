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

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
	TPM_RC 			rc = 0;
	int 			i;    /* argc iterator */
	TSS_CONTEXT 		*tssContext = NULL;
	LDAA_Join_In   	in;
	LDAA_Join_Out   out;
	TPMI_DH_OBJECT      	keyHandle = 0;
	const char          	*keyPassword = NULL;
	const char          	*nymFilename = NULL;
	const char          	*publickeyFilename = NULL;
    const char              *bsn_I = NULL;
    unsigned int            bsn_I_len = 0;
    unsigned char           sid, jsid;
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
				sscanf(argv[i], "%x", &keyHandle);
			}
			else {
				printf("Missing parameter for -hk\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-sid") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%hhd", &sid);
			}
			else {
				printf("-sid option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-jsid") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%hhd", &jsid);
			}
			else {
				printf("-jsid option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-bsn") == 0) {
			i++;
			if (i < argc) {
				bsn_I = argv[i];
                bsn_I_len = strlen(argv[i]);
			}
			else {
				printf("-bsn option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-onym") == 0) {
			i++;
			if (i < argc) {
                nymFilename = argv[i];
			}
			else {
				printf("-onym option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-out") == 0) {
			i++;
			if (i < argc) {
                publickeyFilename = argv[i];
			}
			else {
				printf("-out option needs a value\n");
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
	if (keyHandle == 0) {
		printf("Missing handle parameter -hk\n");
		printUsage();
	}
	if (rc == 0) {
		in.key_handle = keyHandle;
        in.sid = sid;
        in.jsid = jsid;
        memmove(in.bsn_I.t.buffer, bsn_I, bsn_I_len);
        in.bsn_I.t.size = bsn_I_len;
        in.nonce.t.size = 0;
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
			TPM_CC_LDAA_Join,
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
	if ((rc == 0) && (nymFilename != NULL)) {
		rc = TSS_File_WriteStructure(&out.nym,
			(MarshalFunction_t)TSS_TPM2B_LDAA_NYM_Marshalu,
			nymFilename);
	}
	if ((rc == 0) && (publickeyFilename != NULL)) {
		rc = TSS_File_WriteStructure(&out.public_key,
			(MarshalFunction_t)TSS_TPM2B_LDAA_PUBLIC_KEY_Marshalu,
			publickeyFilename);
	}

	if (rc == 0) {
		if (verbose)
		{
			printf("Join Token Link: ");
            UINT32 i;
			for (i = 0; i < out.nym.b.size - 1; i++)
				printf("%02X", out.nym.b.buffer[i]);
			printf("\n");
		}
		if (verbose) printf("LDAA Join: success\n");
	}
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("LDAA Join: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}


static void printUsage(void)
{
	printf("\n");
	printf("LDAA Join\n");
	printf("\n");
	printf("Runs TPM2_LDAA_Join\n");
	printf("\n");
	printf("\t-hk unrestricted decryption key handle\n");
	printf("\t[-pwdk password for key (default empty)]\n");
	printf("\t-sid session ID of the LDAA session\n");
	printf("\t-jsid unique submission ID of the LDAA session\n");
	printf("\t-bsn Issuer basename\n");
	printf("\t-onym Output file of the join session link token\n");
	printf("\n");
	printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
	printf("\t\t01 continue\n");
	printf("\t\t20 command decrypt\n");
	printf("\t\t40 response encrypt\n");
	exit(1);
}

