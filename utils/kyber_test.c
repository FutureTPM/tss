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

int main(void) {
    TPM_RC			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;
    KYBER_KeyGen_Out 	out;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "3");

    /* Start a TSS context */
    if (rc == 0) {
        rc = TSS_Create(&tssContext);
    }

    /* call TSS to execute the command */
    if (rc == 0) {
        rc = TSS_Execute(tssContext,
                 (RESPONSE_PARAMETERS *)&out,
                 NULL,
                 NULL,
                 TPM_CC_KYBER_KeyGen,
                 TPM_RH_NULL, NULL, 0);
    }

    printf("Kyber Public Key: [\n");
    for (size_t i = 0; i < 736; i++) {
        printf("%02X", out.public_key.b.buffer[i]);

        if (i != 735) {
            printf(", ");
        }
    }
    printf("]\n");

    printf("Kyber Secret Key: [\n");
    for (size_t i = 0; i < 1632; i++) {
        printf("%02X", out.secret_key.b.buffer[i]);

        if (i != 1631) {
            printf(", ");
        }
    }
    printf("]\n");

    {
        TPM_RC rc1 = TSS_Delete(tssContext);
        if (rc == 0) {
            rc = rc1;
        }
    }

    /*
      validate the creation data
    */
    //{
    //    uint16_t	written = 0;;
    //    uint8_t		*buffer = NULL;		/* for the free */
    //    uint32_t 	sizeInBytes;
    //    TPMT_HA		digest;

    //    /* get the digest size from the Name algorithm */
    //    if (rc == 0) {
    //        sizeInBytes = TSS_GetDigestSize(nalg);
    //        if (out.creationHash.b.size != sizeInBytes) {
    //            printf("create: failed, "
    //                   "creationData size %u incompatible with name algorithm %04x\n",
    //                   out.creationHash.b.size, nalg);
    //            rc = EXIT_FAILURE;
    //        }
    //    }
    //    /* re-marshal the output structure */
    //    if (rc == 0) {
    //        rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
    //                       &written,
    //                       &out.creationData.creationData,
    //                       (MarshalFunction_t)TSS_TPMS_CREATION_DATA_Marshal);
    //    }
    //    /* recalculate the creationHash from creationData */
    //    if (rc == 0) {
    //        digest.hashAlg = nalg;			/* Name digest algorithm */
    //        rc = TSS_Hash_Generate(&digest,
    //                   written, buffer,
    //                   0, NULL);
    //    }
    //    /* compare the digest to creation hash */
    //    if (rc == 0) {
    //        int irc;
    //        irc = memcmp((uint8_t *)&digest.digest, &out.creationHash.b.buffer, sizeInBytes);
    //        if (irc != 0) {
    //        printf("create: failed, creationData hash does not match creationHash\n");
    //        rc = EXIT_FAILURE;
    //        }
    //    }
    //    free(buffer);	/* @1 */
    //}

    ///* save the private key */
    //if ((rc == 0) && (privateKeyFilename != NULL)) {
    //    rc = TSS_File_WriteStructure(&out.outPrivate,
    //                     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal,
    //                     privateKeyFilename);
    //}

    ///* save the public key */
    //if ((rc == 0) && (publicKeyFilename != NULL)) {
    //    rc = TSS_File_WriteStructure(&out.outPublic,
    //                     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
    //                     publicKeyFilename);
    //}

    ///* save the optional PEM public key */
    //if ((rc == 0) && (pemFilename != NULL)) {
    //    rc = convertPublicToPEM(&out.outPublic,
    //                pemFilename);
    //}

    ///* save the optional creation ticket */
    //if ((rc == 0) && (ticketFilename != NULL)) {
    //    rc = TSS_File_WriteStructure(&out.creationTicket,
    //                     (MarshalFunction_t)TSS_TPMT_TK_CREATION_Marshal,
    //                     ticketFilename);
    //}

    ///* save the optional creation hash */
    //if ((rc == 0) && (creationHashFilename != NULL)) {
    //    rc = TSS_File_WriteBinaryFile(out.creationHash.b.buffer,
    //                      out.creationHash.b.size,
    //                      creationHashFilename);
    //}

    //if (rc == 0) {
    //    if (verbose) printf("create: success\n");
    //} else {
    //    const char *msg;
    //    const char *submsg;
    //    const char *num;
    //    printf("create: failed, rc %08x\n", rc);
    //    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    //    printf("%s%s%s\n", msg, submsg, num);
    //    rc = EXIT_FAILURE;
    //}
    return rc;
}

