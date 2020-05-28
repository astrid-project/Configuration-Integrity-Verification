#ifndef VIRTUALMACHINE_H
#define VIRTUALMACHINE_H
#include "defines.h"
#include "TpmManager.h"
#include "PolicyManager.h"
#include "CreateResponse.h"

class VirtualMachine
{
public:
	VirtualMachine(TSS_CONTEXT* ctx, TpmManager* tpm);

	TPMT_SIGNATURE attestConfiguration(TPM2B_DIGEST& nonce, int* success);
	CreateAttestationKeyResponse createNewAttestationKey(TPM2B_DIGEST& policy_digest, TPML_PCR_SELECTION pcrs);
	Quote quote(TPML_PCR_SELECTION& pcrs, TPM2B_DATA* nonce);
	
	void PCRExtend(const char* fileLocation, uint8_t PCR);

	// Endorsement key, public for PoC
	SealedKey endorsementKey{};

private:
	SealedKey attestationKey{};
	TPML_PCR_SELECTION PCRs{};

	// attestation storage key template
	TPM2B_PUBLIC ak_primary{};
	static void readBinary(unsigned char** data, size_t* len, const char* location);


	// TPM 
	TpmManager* tpm;
	TSS_CONTEXT* ctx;
	PolicyManager policy{};
};
#endif // VIRTUALMACHINE_H
