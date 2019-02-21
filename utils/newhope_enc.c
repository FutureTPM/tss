/***************************************************************************************
 * Copyright 2018 Infineon Technologies AG ( www.infineon.com ).                       *
 * All rights reserved.                                                                *
 *                                                                                     *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,            *
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,           *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE DISCLAIMED.  IN NO       *
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,     *
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,                 *
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;         *
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY             *
 * WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR            *
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF              *
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                                          *
 *                                                                                     *
 ***************************************************************************************/


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
#ifdef TPM_ALG_NEWHOPE
	UINT32 			i;    /* argc iterator */
	TSS_CONTEXT 		*tssContext = NULL;
	NEWHOPE_Enc_In   		in;
	NEWHOPE_Enc_Out   		out;
	TPMI_DH_OBJECT      	keyHandle = 0;
	const char          	*cFilename = NULL;
	const char       		*ssFilename = NULL;
	const char          	*keyPassword = NULL;
	TPMI_SH_AUTH_SESSION        sessionHandle0 = TPM_RH_NULL;
	unsigned int                sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION        sessionHandle1 = TPM_RH_NULL;
	unsigned int                sessionAttributes1 = 0;
	TPMI_SH_AUTH_SESSION        sessionHandle2 = TPM_RH_NULL;
	unsigned int                sessionAttributes2 = 0;

	setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	/* command line argument defaults */

	for (i = 1; (i < (UINT32)argc) && (rc == 0); i++) {
		if (strcmp(argv[i], "-hk") == 0) {
			i++;
			if (i < (UINT32)argc) {
				sscanf(argv[i], "%x", &keyHandle);
			}
			else {
				printf("Missing parameter for -hk\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-c") == 0) {
			i++;
			if (i < (UINT32)argc) {
				cFilename = argv[i];
			}
			else {
				printf("-c option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-ss") == 0) {
			i++;
			if (i < (UINT32)argc) {
				ssFilename = argv[i];
			}
			else {
				printf("-ss option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-pwdk") == 0) {
			i++;
			if (i < (UINT32)argc) {
				keyPassword = argv[i];
			}
			else {
				printf("-pwdk option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-se0") == 0) {
			i++;
			if (i < (UINT32)argc) {
				sscanf(argv[i], "%x", &sessionHandle0);
			}
			else {
				printf("Missing parameter for -se0\n");
				printUsage();
			}
			i++;
			if (i < (UINT32)argc) {
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
			if (i < (UINT32)argc) {
				sscanf(argv[i], "%x", &sessionHandle1);
			}
			else {
				printf("Missing parameter for -se1\n");
				printUsage();
			}
			i++;
			if (i < (UINT32)argc) {
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
			if (i < (UINT32)argc) {
				sscanf(argv[i], "%x", &sessionHandle2);
			}
			else {
				printf("Missing parameter for -se2\n");
				printUsage();
			}
			i++;
			if (i < (UINT32)argc) {
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
		in.keyHandle = keyHandle;
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
			TPM_CC_NEWHOPE_Enc,
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
		rc = TSS_File_WriteStructure(&out.SharedSecret,
			(MarshalFunction_t)TSS_TPM2B_SHAREDSECRET_NEWHOPE_Marshalu,
			ssFilename);
	}

	if ((rc == 0) && (cFilename != NULL)) {
		rc = TSS_File_WriteStructure(&out.Cipher,
			(MarshalFunction_t)TSS_TPM2B_CIPHER_NEWHOPE_Marshalu,
			cFilename);
	}

	if (rc == 0) {
		if (verbose)
		{
			printf("Cipher: ");
			for (i = 0; i<out.Cipher.b.size-1; i++)
				printf("%02X", out.Cipher.b.buffer[i]);
			printf("\n");
		}
		if (verbose)
		{
			printf("SS: ");
			for (i = 0; i<out.SharedSecret.b.size - 1; i++)
				printf("%02X", out.SharedSecret.b.buffer[i]);
			printf("\n");
		}
		if (verbose) printf("NewHope_Enc: success\n");
	}
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("NewHope_Enc: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
#endif
	return rc;
}


static void printUsage(void)
{
	printf("\n");
	printf("NewHope_Enc\n");
	printf("\n");
	printf("Runs TPM2_NewHope_Enc\n");
	printf("\n");
	printf("\t-hk unrestricted decryption key handle\n");
	printf("\t[-pwdk password for key (default empty)]\n");
	printf("\t[-c cipher object output file name (default do not save)]\n");
	printf("\t[-ss shared secret output data file name (default do not save)]\n");
	printf("\n");
	printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
	printf("\t\t01 continue\n");
	printf("\t\t20 command decrypt\n");
	printf("\t\t40 response encrypt\n");
	exit(1);
}



