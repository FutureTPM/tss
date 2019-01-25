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


#ifndef NEWHOPE_FP_H
#define NEWHOPE_FP_H

typedef struct {
	TPMI_DH_OBJECT	keyHandle;
	TPM2B_NEWHOPE_CIPHER Cipher;
} NEWHOPE_Dec_In;

#define RC_NEWHOPE_Dec_keyHandle	(TPM_RC_P + TPM_RC_1)
#define RC_NEWHOPE_Dec_Cipher		(TPM_RC_P + TPM_RC_2)

typedef struct {
	TPM2B_NEWHOPE_SHAREDSECRET SharedSecret;
} NEWHOPE_Dec_Out;


LIB_EXPORT TPM_RC
TPM2_NEWHOPE_Dec(
	NEWHOPE_Dec_In    *in,            // IN: input parameter list
	NEWHOPE_Dec_Out   *out            // OUT: output parameter list
);

typedef struct {
	TPMI_DH_OBJECT	keyHandle;
} NEWHOPE_Enc_In;

#define RC_NEWHOPE_Enc_keyHandle	(TPM_RC_P + TPM_RC_1)

typedef struct {
	TPM2B_NEWHOPE_CIPHER Cipher;
	TPM2B_NEWHOPE_SHAREDSECRET SharedSecret;
} NEWHOPE_Enc_Out;

LIB_EXPORT TPM_RC
TPM2_NEWHOPE_Enc(
	NEWHOPE_Enc_In    *in,            // IN: input parameter list
	NEWHOPE_Enc_Out   *out            // OUT: output parameter list
);

#endif
