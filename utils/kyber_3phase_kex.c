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
	Kyber_3Phase_KEX_In   in;
	Kyber_3Phase_KEX_Out  out;
	TPMI_DH_OBJECT      	static_key_handle = 0;
	TPMI_DH_OBJECT      	ephemeral_key_handle = 0;
	const char          	*cFilename_in_1 = NULL;
	const char          	*cFilename_in_2 = NULL;
	const char       		*ssFilename_in = NULL;
	const char       		*ssFilename_out = NULL;
	const char          	*static_key_password = NULL;
	const char          	*ephemeral_key_password = NULL;
	TPMI_SH_AUTH_SESSION        sessionHandle0 = TPM_RS_PW;
	unsigned int                sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION        sessionHandle1 = TPM_RS_PW;
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
		else if (strcmp(argv[i], "-c1") == 0) {
			i++;
			if (i < argc) {
				cFilename_in_1 = argv[i];
			}
			else {
				printf("-c1 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-c2") == 0) {
			i++;
			if (i < argc) {
				cFilename_in_2 = argv[i];
			}
			else {
				printf("-c2 option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-ssi") == 0) {
			i++;
			if (i < argc) {
				ssFilename_in = argv[i];
			}
			else {
				printf("-ssi option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-sso") == 0) {
			i++;
			if (i < argc) {
				ssFilename_out = argv[i];
			}
			else {
				printf("-sso option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-pwdks") == 0) {
			i++;
			if (i < argc) {
				static_key_password = argv[i];
			}
			else {
				printf("-pwdks option needs a value\n");
				printUsage();
			}
		}
		else if (strcmp(argv[i], "-pwdke") == 0) {
			i++;
			if (i < argc) {
				ephemeral_key_password = argv[i];
			}
			else {
				printf("-pwdke option needs a value\n");
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
	}

	if ((rc == 0) && (cFilename_in_1 != NULL)) {
		rc = TSS_File_ReadStructure(&in.cipher_text_1,
			(UnmarshalFunction_t)TSS_TPM2B_KYBER_CIPHER_TEXT_Unmarshalu,
			cFilename_in_1);
	}
	else
	{
		in.cipher_text_1.b.size = 0;
	}

	if ((rc == 0) && (cFilename_in_2 != NULL)) {
		rc = TSS_File_ReadStructure(&in.cipher_text_2,
			(UnmarshalFunction_t)TSS_TPM2B_KYBER_CIPHER_TEXT_Unmarshalu,
			cFilename_in_2);
	}
	else
	{
		in.cipher_text_2.b.size = 0;
	}

	if ((rc == 0) && (ssFilename_in != NULL)) {
		rc = TSS_File_ReadStructure(&in.shared_key_3,
			(UnmarshalFunction_t)TSS_TPM2B_KYBER_SHARED_KEY_Unmarshalu,
			ssFilename_in);
	}
	else
	{
		in.shared_key_3.b.size = 0;
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
			TPM_CC_KYBER_3Phase_KEX,
			sessionHandle0, static_key_password, sessionAttributes0,
			sessionHandle1, ephemeral_key_password, sessionAttributes1,
			sessionHandle2, NULL, sessionAttributes2,
			TPM_RH_NULL, NULL, 0);
	}
	{
		TPM_RC rc1 = TSS_Delete(tssContext);
		if (rc == 0) {
			rc = rc1;
		}
	}

	if ((rc == 0) && (ssFilename_out != NULL)) {
		rc = TSS_File_WriteStructure(&out.shared_key,
			(MarshalFunction_t)TSS_TPM2B_KYBER_SHARED_KEY_Marshalu,
			ssFilename_out);
	}

	if (rc == 0) {
		if (verbose)
		{
			printf("Shared Key: ");
			for (i = 0; i<out.shared_key.b.size - 1; i++)
				printf("%02X", out.shared_key.b.buffer[i]);
			printf("\n");
		}
		if (verbose) printf("Kyber 3Phase Key Exchange: success\n");
	}
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("Kyber 3Phase Key Exchange: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}


static void printUsage(void)
{
	printf("\n");
	printf("Kyber 3Phase Key Exchange Mutually Authenticated\n");
	printf("\n");
	printf("Runs TPM2_KYBER_3Phase_KEX\n");
	printf("\n");
	printf("\t-hk unrestricted decryption static key handle\n");
	printf("\t-hke unrestricted decryption ephemeral key handle\n");
	printf("\t[-pwdks password for static key (default empty)]\n");
	printf("\t[-pwdke password for ephemeral key (default empty)]\n");
	printf("\t-c1 cipher object input file name encapsulated with static key \n");
	printf("\t-c2 cipher object input file name encapsulated with ephemeral key\n");
	printf("\t-ssi shared secret input data file name (default do not save)]\n");
	printf("\t-sso shared secret output data file name (default do not save)]\n");
	printf("\n");
	printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
	printf("\t\t01 continue\n");
	printf("\t\t20 command decrypt\n");
	printf("\t\t40 response encrypt\n");
	exit(1);
}