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

int verbose = TRUE;

int main(int argc, char *argv[])
{
	TPM_RC 			rc = 0;
	int 			i;    /* argc iterator */
	TSS_CONTEXT 		*tssContext = NULL;
	static LDAA_SignProof_In    in;
	static LDAA_SignProof_Out   out;
	TPMI_DH_OBJECT      	keyHandle = 0;
	const char          	*keyPassword = NULL;
	const char          	*host_sign_state_1 = NULL;
	const char          	*host_sign_state_2 = NULL;
	const char          	*tpm_sign_state_1 = NULL;
	const char          	*tpm_sign_state_2 = NULL;
	const char          	*sign_group = NULL;
    unsigned char           sid = 0;
    unsigned char           sign_state_type = 255;
    unsigned char           sign_state_sel = 255;
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
		else if (strcmp(argv[i], "-sign") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%hhd", &sign_state_sel);
			}
			else {
				printf("-sign option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-signT") == 0) {
			i++;
			if (i < argc) {
				sscanf(argv[i], "%hhd", &sign_state_type);
			}
			else {
				printf("-signT option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-isign1") == 0) {
			i++;
			if (i < argc) {
                host_sign_state_1 = argv[i];
			}
			else {
				printf("-isign1 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-isign2") == 0) {
			i++;
			if (i < argc) {
                host_sign_state_2 = argv[i];
			}
			else {
				printf("-isign2 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-osign1") == 0) {
			i++;
			if (i < argc) {
                tpm_sign_state_1 = argv[i];
			}
			else {
				printf("-osign1 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-osign2") == 0) {
			i++;
			if (i < argc) {
                tpm_sign_state_2 = argv[i];
			}
			else {
				printf("-osign2 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-ogroup") == 0) {
			i++;
			if (i < argc) {
                sign_group = argv[i];
			}
			else {
				printf("-ogroup option needs a value\n");
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

	if (sign_state_type == 255) {
		printf("Missing sign state type parameter -signT\n");
		printUsage();
	}

	if (sign_state_sel == 255) {
		printf("Missing sign state sel parameter -sign\n");
		printUsage();
	}

	if (host_sign_state_1 == NULL) {
		printf("Missing host sign state 1 parameter -isign1\n");
		printUsage();
	}

	if (host_sign_state_2 == NULL) {
		printf("Missing host sign state 2 parameter -isign2\n");
		printUsage();
	}

	if (tpm_sign_state_1 == NULL) {
		printf("Missing tpm sign state 1 parameter -osign1\n");
		printUsage();
	}

	if (tpm_sign_state_2 == NULL) {
		printf("Missing tpm sign state 2 parameter -osign2\n");
		printUsage();
	}

	if (sign_group == NULL) {
		printf("Missing sign group parameter -ogroup\n");
		printUsage();
	}

	if (rc == 0) {
		in.key_handle = keyHandle;
        in.sid = sid; // TODO: Error check SID
        in.sign_state_type = sign_state_type;
        in.sign_state_sel = sign_state_sel;
	}

	if ((rc == 0) && (host_sign_state_1 != NULL)) {
		rc = TSS_File_Read2B(&in.R1.b,
			sizeof(in.R1.t.buffer),
			host_sign_state_1);
	} else {
        in.R1.t.size = 0;
    }

	if ((rc == 0) && (host_sign_state_2 != NULL)) {
		rc = TSS_File_Read2B(&in.R2.b,
			sizeof(in.R2.t.buffer),
			host_sign_state_2);
	} else {
        in.R2.t.size = 0;
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
			TPM_CC_LDAA_SignProof,
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

	if ((rc == 0) && (tpm_sign_state_1 != NULL)) {
		rc = TSS_File_WriteStructure(&out.R1,
			(MarshalFunction_t)TSS_TPM2B_LDAA_SIGN_STATE_Marshalu,
			tpm_sign_state_1);
	}

	if ((rc == 0) && (tpm_sign_state_2 != NULL)) {
		rc = TSS_File_WriteStructure(&out.R2,
			(MarshalFunction_t)TSS_TPM2B_LDAA_SIGN_STATE_Marshalu,
			tpm_sign_state_2);
	}

	if ((rc == 0) && (sign_group != NULL)) {
		rc = TSS_File_WriteStructure(&out.sign_group,
			(MarshalFunction_t)TSS_TPM2B_LDAA_SIGN_GROUP_Marshalu,
			sign_group);
	}

	if (rc == 0) {
		if (verbose)
		{
			printf("Sign State 1: ");
            UINT32 i;
			for (i = 0; i < out.R1.b.size - 1; i++)
				printf("%02X", out.R1.b.buffer[i]);
			printf("\n");

			printf("Sign State 2: ");
			for (i = 0; i < out.R2.b.size - 1; i++)
				printf("%02X", out.R2.b.buffer[i]);
			printf("\n");

			printf("Sign Group: ");
			for (i = 0; i < out.sign_group.b.size - 1; i++)
				printf("%02X", out.sign_group.b.buffer[i]);
			printf("\n");
		}
		if (verbose) printf("LDAA Sign Proof: success\n");
	}
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("LDAA Sign Proof: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}


static void printUsage(void)
{
	printf("\n");
	printf("LDAA Sign Proof\n");
	printf("\n");
	printf("Runs TPM2_LDAA_SignProof\n");
	printf("\n");
	printf("\t-hk unrestricted decryption key handle\n");
	printf("\t[-pwdk password for key (default empty)]\n");
	printf("\t-sid session ID of the LDAA session\n");
	printf("\t-signT Sign type to process [0-2]\n");
	printf("\t-sign Signature to base the commit on [0-7]\n");
	printf("\t-isign1 File for the first sign state of the Host\n");
	printf("\t-isign2 File for the second sign state of the Host\n");
	printf("\t-osign1 Output file of the addition result of the first host sign state and the TPM\n");
	printf("\t-osign2 Output file of the addition result of the second host sign state and the TPM\n");
	printf("\t-ogroup Output file of the TPM sign group\n");
	printf("\n");
	printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
	printf("\t\t01 continue\n");
	printf("\t\t20 command decrypt\n");
	printf("\t\t40 response encrypt\n");
	exit(1);
}

