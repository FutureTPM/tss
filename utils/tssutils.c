/********************************************************************************/
/*										*/
/*			    TSS and Application Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*		$Id: tssutils.c 1294 2018-08-09 19:08:34Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2018					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>

#define TSS_ALLOC_MAX  0x20000000  /* 512MiB */

extern int tssVerbose;
extern int tssVverbose;

/* TSS_Malloc() is a general purpose wrapper around malloc()
 */

TPM_RC TSS_Malloc(unsigned char **buffer, uint32_t size)
{
    TPM_RC          rc = 0;

    /* assertion test.  The coding style requires that all allocated pointers
     * are initialized to NULL.  A non-NULL value indicates either a missing
     * initialization or a pointer reuse (a memory leak). */
    if (rc == 0) {
        if (*buffer != NULL) {
            if (tssVerbose)
		printf("TSS_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n",
		       *buffer);
            rc = TSS_RC_ALLOC_INPUT;
        }
    }
    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TSS_ALLOC_MAX) {
            if (tssVerbose) printf("TSS_Malloc: Error, size %u greater than maximum allowed\n",
				   size);
            rc = TSS_RC_MALLOC_SIZE;
        }
    }
    /* verify that the size is not 0, this would be implementation defined and
     * should never occur */
    if (rc == 0) {
        if (size == 0) {
            if (tssVerbose) printf("TSS_Malloc: Error (fatal), size is zero\n");
            rc = TSS_RC_MALLOC_SIZE;
        }
    }
    if (rc == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            if (tssVerbose) printf("TSS_Malloc: Error allocating %u bytes\n", size);
            rc = TSS_RC_OUT_OF_MEMORY;
        }
    }
    return rc;
}

TPM_RC TSS_Realloc(unsigned char **buffer, uint32_t size)
{
    TPM_RC          	rc = 0;
    unsigned char 	*tmpptr;

    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TSS_ALLOC_MAX) {
            if (tssVerbose) printf("TSS_Realloc: Error, size %u greater than maximum allowed\n",
				   size);
            rc = TSS_RC_MALLOC_SIZE;
        }
    }
    /* verify that the size is not 0, this should never occur */
    if (rc == 0) {
        if (size == 0) {
            if (tssVerbose) printf("TSS_Malloc: Error (fatal), size is zero\n");
            rc = TSS_RC_MALLOC_SIZE;
        }
    }
    if (rc == 0) {
	tmpptr = realloc(*buffer, size);
	if (tmpptr == NULL) {
            if (tssVerbose) printf("TSS_Realloc: Error reallocating %u bytes\n", size);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	*buffer = tmpptr;
    }
    return rc;
}


/* TSS_Structure_Marshal() is a general purpose "marshal a structure" function.

   It marshals the structure using "marshalFunction", and returns the malloc'ed stream.

*/

TPM_RC TSS_Structure_Marshal(uint8_t		**buffer,	/* freed by caller */
			     uint32_t		*written,
			     void 		*structure,
			     MarshalFunction_t 	marshalFunction)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer1 = NULL;	/* for marshaling, moves pointer */

    /* marshal once to calculates the byte length */
    if (rc == 0) {
	*written = 0;
	rc = marshalFunction(structure, written, NULL, NULL);
    }
    if (rc == 0) {
	rc = TSS_Malloc(buffer, *written);
    }
    if (rc == 0) {
	buffer1 = *buffer;
	*written = 0;
	rc = marshalFunction(structure, written, &buffer1, NULL);
    }
    return rc;
}

/* TSS_TPM2B_Copy() copies source to target if the source fits the target size */

TPM_RC TSS_TPM2B_Copy(TPM2B *target, TPM2B *source, uint32_t targetSize)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (source->size > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_Copy: size %u greater than target %u\n",
				   source->size, targetSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	memmove(target->buffer, source->buffer, source->size);
	target->size = source->size;
    }
    return rc;
}

/* TSS_TPM2B_Append() appends the source TPM2B to the target TPM2B.

   It checks that the source fits the target size. The target size is the total size, not the size
   remaining.
*/

TPM_RC TSS_TPM2B_Append(TPM2B *target, TPM2B *source, uint32_t targetSize)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (target->size + source->size > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_Append: size %u greater than target %u\n",
				   target->size + source->size, targetSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	memmove(target->buffer + target->size, source->buffer, source->size);
	target->size += source->size;
    }
    return rc;
}

/* TSS_TPM2B_Create() copies the buffer of 'size' into target, checking targetSize */

TPM_RC TSS_TPM2B_Create(TPM2B *target, uint8_t *buffer, uint32_t size, uint32_t targetSize)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (size > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_Create: size %u greater than target %u\n",
				   size, targetSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	target->size = size;
	memmove(target->buffer, buffer, size);
    }
    return rc;
}

/* TSS_TPM2B_CreateUint32() creates a TPM2B from a uint32_t, typically a permanent handle */

TPM_RC TSS_TPM2B_CreateUint32(TPM2B *target, uint32_t source, uint32_t targetSize)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (sizeof(uint32_t) > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_CreateUint32: size %u greater than target %u\n",
				   (unsigned int)sizeof(uint32_t), targetSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	uint32_t sourceNbo = htonl(source);
	memmove(target->buffer, (uint8_t *)&sourceNbo, sizeof(uint32_t));
	target->size = sizeof(uint32_t);
    }
    return rc;
}

/* TSS_TPM2B_StringCopy() copies a NUL terminated string (omitting the NUL) from source to target.

   It checks that the string will fit in targetSize.

   If source is NULL, creates a TPM2B of size 0.
*/

TPM_RC TSS_TPM2B_StringCopy(TPM2B *target, const char *source, uint32_t targetSize)
{
    TPM_RC rc = 0;
    size_t length;
    uint32_t length16;

    if (source != NULL) {
	if (rc == 0) {
	    length = strlen(source);
	    if (length > 0xffffffff) {	/* overflow TPM2B uint32_t */
		if (tssVerbose) printf("TSS_TPM2B_StringCopy: size %u greater than 0xffffffff\n",
				       (unsigned int)length);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	if (rc == 0) {
	    length16 = (uint32_t )length;	/* cast safe after range test */
	    if (length16 > targetSize) {
		if (tssVerbose) printf("TSS_TPM2B_StringCopy: size %u greater than target %u\n",
				       length16, targetSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	if (rc == 0) {
	    target->size = length16;
	    memcpy(target->buffer, source, length);
	}
    }
    else {
	target->size = 0;
    }
    return rc;
}

int TSS_TPM2B_Compare(TPM2B *expect, TPM2B *actual)
{
    int 	irc;
    int 	match = YES;

    if (match == YES) {
	if (expect->size != actual->size) {
	    match = NO;
	}
    }
    if (match == YES) {
	irc = memcmp(expect->buffer, actual->buffer, expect->size);
	if (irc != 0) {
	    match = NO;
	}
    }
    return match;
}

