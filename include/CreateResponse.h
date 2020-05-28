#ifndef CREATERESPONSE_H
#define CREATERESPONSE_H
#include "tss_includes.h"

struct CreateAttestationKeyResponse {
	TPM2B_PUBLIC attestationPK; 
	TPM2B_ATTEST	certifyInfo;
	TPMT_SIGNATURE	signature;
};


#endif // CREATERESPONSE_H
