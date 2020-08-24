#ifndef VMSTRUCTURE_H
#define VMSTRUCTURE_H

#include <cstring>
#include "VirtualMachine.h"
struct VMStructure {
	VMStructure(VirtualMachine& machine, const int ids, TpmManager* tpm, TSS_CONTEXT* ctx) : vm(machine), id(ids)
	{

	    // These values of course depend on current TPM Status, we just read the current values.

		int pcr = 0;
		int maxPCR = 24;

		for(pcr = 0; pcr < maxPCR; pcr++){
		    auto out = tpm->readPCR(ctx,pcr);
		    memcpy(vPCR[pcr],out.pcrValues.digests[0].t.buffer,SHA256_DIGEST_SIZE);
		}


	}

	VirtualMachine vm; 
	TPM2B_PUBLIC attestationKey;
	TPM2B_DIGEST expectedConfiguration;
	int state = UNTRUSTED;
	unsigned char vPCR[24][SHA256_DIGEST_SIZE]; 
	const int id;
};
#endif // VMSTRUCTURE_H
