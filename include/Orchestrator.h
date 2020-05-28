#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H
#include "TpmManager.h"
#include "PolicyManager.h"
#include <vector>
#include "VMStructure.h"
#include "PCRSelection.h"

class Orchestrator
{
public:
	Orchestrator();
	void deployVMs(TSS_CONTEXT* ctx, TpmManager* tpm);
	void deployNewAttestationKey(int vid);
	bool requestAttestationByProof(int vid);
	bool requestAttestationByQuote(int vid);
	void updateMeasurements(int vid, unsigned char* expectedMeassurement, uint8_t pcr, const char* vmFileLocation);

private:
	std::vector<VMStructure> vms; 
	PCRSelector pcrSelector;

	void calculateExpectedConfiguration(int vid, TPML_PCR_SELECTION& selection, unsigned char* result);
	void calculateExpectedPolicy(TPML_PCR_SELECTION* selection, unsigned char* pcrDigest, unsigned char* result);
	bool verifyAttestationKey(CreateAttestationKeyResponse& response, VirtualMachine& vm, TPM2B_DIGEST& policy);
	void generatePublicName(TPM2B_PUBLIC& publicKey, unsigned char* nameOut);
	bool isSelected(int pcr, TPMS_PCR_SELECTION* selection);
};

#endif // ORCHESTRATOR_H
