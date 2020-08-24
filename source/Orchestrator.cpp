#include <cstring>
#include "Orchestrator.h"
#include "cryptoutils.h"
#include <openssl/rand.h>


/**
 * Default constructor for Orchestrator
 */
Orchestrator::Orchestrator() : pcrSelector(TPM_ALG_SHA256) {}


/**
 * Function to deploy Virtual Machines
 *
 * Creates VM and sets it in the strucute in an UNTRUSTED state
 * @param ctx the TSS Context for the TPM
 * @param tpm the TPM for the VM.
 * 
 * NOTE: TPM and Context should be setup in the VM.
 */
void Orchestrator::deployVMs(TSS_CONTEXT* ctx, TpmManager* tpm)
{
	// Create VM
	VirtualMachine vm(ctx,tpm);

	// Push to list (Untrusted state)
	int id = vms.size();
	VMStructure vmstruct(vm, id,tpm,ctx);
	this->vms.push_back(vmstruct);
	
	// Deploy attestation key
	deployNewAttestationKey(id); 

}

/**
 * Instructs VM to create a new attestation key, and verifies that the key was created with the expected configuration
 * Configurations are based on the expected configuration in the VM Structure
 *
 * @param vid is the identifier for the VM to create a new key
 *
 */
void Orchestrator::deployNewAttestationKey(int vid) {

	// Locate VM
	VMStructure* vm = &vms.at(vid);

	// Create PCR Selection
	size_t pcrCount = 4;
	pcrSelector.use_pcrs(pcrCount, 2, 4, 12, 7);
	TPML_PCR_SELECTION selection = pcrSelector.getSelection();

	// Calculate the expected policy digest
	TPM2B_DIGEST policyDigest;
	policyDigest.b.size = SHA256_DIGEST_SIZE;
	unsigned char pcrDigest[SHA256_DIGEST_SIZE];
	calculateExpectedConfiguration(vid, selection, pcrDigest);
	calculateExpectedPolicy(&selection, pcrDigest, policyDigest.b.buffer);

	// Deploy
	CreateAttestationKeyResponse response = vm->vm.createNewAttestationKey(policyDigest, selection);
	vm->attestationKey = response.attestationPK;
	const bool verified = this->verifyAttestationKey(response, vm->vm, policyDigest);

	if (verified) {
		vm->state = TRUSTED;
#ifdef VERBOSE
		printf("[+] Attestation key verified\n");
#endif
	}
	else {
		vm->state = UNTRUSTED;
#ifdef VERBOSE
		printf("[-] Attestation key not correctly created\n");
#endif 
	}
}

/**
 * Starts attestation process with a VM and verifies the response
 *
 * @param vid ID of the virtual machine to start attestation with
 * @return true if attestation succeeds, otherwise false
 */
bool Orchestrator::requestAttestationByProof(int vid)
{
	// Requests random bytes as a nonce
	unsigned char nonce[SHA256_DIGEST_SIZE];
	RAND_bytes(nonce, SHA256_DIGEST_SIZE);

	// We just copy the nonce, no reason to hash it
	TPM2B_DIGEST nounce2B; 
	memcpy(&nounce2B.t.buffer, nonce, SHA256_DIGEST_SIZE);
	nounce2B.t.size = SHA256_DIGEST_SIZE;

	// Locate the VM identified by the identifier.
	VMStructure vm = vms.at(vid);

	// Request it to sign the nonce
	int signatureCompleted;
	TPMT_SIGNATURE signature = vm.vm.attestConfiguration(nounce2B,&signatureCompleted);
	bool attestationOK = false;

	if (signatureCompleted == SUCCESS) {
		// Convert PK to EVP
		EVP_PKEY* vmpk_evp = nullptr;
		convertEcPublicToEvpPubKey(&vmpk_evp, &vm.attestationKey.publicArea.unique.ecc);
		int rc;
		rc = verifyEcSignatureFromEvpPubKey(nonce, SHA256_DIGEST_SIZE, &signature, vmpk_evp);
		attestationOK = rc == SUCCESS;
	}

#ifdef VERBOSE
	if (attestationOK)
		printf("[+] VM %d attested correctly\n", vm.id);
	else
		printf("[-] VM %d failed attestation\n", vm.id);
#endif
	// Return result
	return attestationOK;
}


/**
 * Starts attestation process with a VM and verifies the response by using quotes
 *
 * @param vid ID of the virtual machine to start attestation with
 * @return true if attestation succeeds, otherwise false
 */
bool Orchestrator::requestAttestationByQuote(int vid)
{
	bool sigOK = false;
	bool magicOK = false;
	bool confOK = false;
	bool nonceOK = false;
	TPM2B_DATA nonce;

	// Create nonce
	RAND_bytes(nonce.t.buffer, QUOTE_NONCE_SIZE);
	nonce.t.size = QUOTE_NONCE_SIZE;

	// Create selection
	size_t pcrCount = 4;
	pcrSelector.use_pcrs(pcrCount, 2, 4, 12, 7);
	TPML_PCR_SELECTION selection = pcrSelector.getSelection();

	// locate VM
	VMStructure vm = vms.at(vid);

	// Request quote
	Quote quote = vm.vm.quote(selection,&nonce);

	// Unmarshal data
	TPMS_ATTEST attest;
	BYTE* buffer = quote.quoted.t.attestationData;
	uint32_t size = static_cast<uint32_t>(quote.quoted.t.size);
	TSS_TPMS_ATTEST_Unmarshalu(&attest, &buffer, &size);

	// Calculate expected configuration based on vPCRs
	unsigned char expected_config[SHA256_DIGEST_SIZE];
	calculateExpectedConfiguration(vid, selection, expected_config);

	// Do checks on content
	confOK = (memcmp(expected_config, &attest.attested.quote.pcrDigest.b.buffer, SHA256_DIGEST_SIZE) == 0);
	magicOK = attest.magic == TPM_GENERATED_VALUE;
	nonceOK = TSS_TPM2B_Compare(&attest.extraData.b, &nonce.b);

	// Prepare expected value
	TPMT_HA digest;
	digest.hashAlg = TPM_ALG_SHA256;
	int sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	TSS_Hash_Generate(&digest, quote.quoted.b.size, quote.quoted.b.buffer, 0, NULL);

	
	// Convert PK 
	EVP_PKEY* vmek_evp = nullptr;
	convertEcPublicToEvpPubKey(&vmek_evp, &vm.vm.endorsementKey.outPublic.publicArea.unique.ecc);

	// Verify signature
	int rc = verifyEcSignatureFromEvpPubKey(reinterpret_cast<uint8_t*>(&digest.digest), sizeInBytes, &quote.signature, vmek_evp);
	sigOK = rc == SUCCESS;

	bool qouteVerified = magicOK && nonceOK && sigOK && confOK;


#ifdef VERBOSE
	if (qouteVerified)
		printf("[+] VM %d attested correctly\n", vm.id);
	else
		printf("[-] VM %d failed attestation\n", vm.id);
#endif

	// Return true if all is true
	return qouteVerified;
}

/**
 * Updates vPCR contents with expected meassurements and instructs VM to extend the PCR in question
 *
 * @param vid ID of the virtual machine in question
 * @param expectedMeassurement the expected digest of the file to extend the PCR with
 * @param pcr the pcr register (1-24) to extend
 * @param vmFileLocation relative or absolute file location for the file to be extended on the VM (File location ON the VM)
 */
void Orchestrator::updateMeasurements(int vid, unsigned char* expectedMeassurement, uint8_t pcr, const char* vmFileLocation)
{
	// Locate VM 
	VMStructure* vm = &vms.at(vid);

	// Update vPCR with expected meassurement
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, vm->vPCR[pcr - 1], SHA256_DIGEST_SIZE);			// Original
	SHA256_Update(&sha256, expectedMeassurement, SHA256_DIGEST_SIZE);	    // Extend
	SHA256_Final(vm->vPCR[pcr-1], &sha256);								// Overwrite

	// Execute extend on VM
	vm->vm.PCRExtend(vmFileLocation, pcr - 1);

	// At last make sure to update the attestation key on the VM
	this->deployNewAttestationKey(vid);
}

/**
 * Calculates a PCR Digest - a digest of all the PCRs selected in the selection
 *
 * @param vid ID of the virtual machine to calculate for
 * @param selection is the structure containing the selection of PCRs
 * @param result is a pointer to the variable that will contain the final result
 */
void Orchestrator::calculateExpectedConfiguration(int vid, TPML_PCR_SELECTION& selection, unsigned char* result)
{
	VMStructure* vm = &vms.at(vid);
	TPMS_PCR_SELECTION* select;

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	for (int i = 0; i < selection.count; i++) {
		select = &selection.pcrSelections[i];

		for (int c = 0; c < IMPLEMENTATION_PCR; c++) {
			if (isSelected(c, select)) {
				SHA256_Update(&sha256, vm->vPCR[c], SHA256_DIGEST_SIZE);
			}
		}

	}

	SHA256_Final(result, &sha256);

}

/**
 * Calculates a PolicyDigest for the PolicyPCR - a digest of all the PCRs selected in the selection including command code, selectioncount etc.
 *
 * @param selection is the structure containing the selection of PCRs
 * @param pcrDigest is the digest of all the PCRs selected, can be generated with calculateExpectedConfiguration
 * @param result is a pointer to the variable that will contain the final result
 */
void Orchestrator::calculateExpectedPolicy(TPML_PCR_SELECTION* selection, unsigned char* pcrDigest, unsigned char* result)
{
	unsigned char cc[4] = { 0x00, 0x00, 0x01, 0x7f };
	unsigned char original[SHA256_DIGEST_SIZE];
	memset(original, 0x00, SHA256_DIGEST_SIZE);
	BYTE pcrs[sizeof(TPML_PCR_SELECTION)];
	BYTE* buffer;
	buffer = pcrs;

	UINT16 written = 0;
	TSS_TPML_PCR_SELECTION_Marshal(selection, &written, &buffer, nullptr);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	SHA256_Update(&sha256, original, SHA256_DIGEST_SIZE); // Add "original"
	SHA256_Update(&sha256, cc, CC_SIZE); // Add Command Code
    SHA256_Update(&sha256, pcrs, written); // Add marshalled selection
    SHA256_Update(&sha256, pcrDigest, SHA256_DIGEST_SIZE); // Add digest

	SHA256_Final(result, &sha256);

}


/**
 * Verifies the correctness of a foreign generated attestation key
 * Verifies policy, keyname and signature.
 *
 * @param response data from VM containing necessary data 
 * @param vm the virtual machine in context
 * @param policy the policydigest the key must have been made with
 * @return true if signature, keyname and policydigest is correct.
 */
bool Orchestrator::verifyAttestationKey(CreateAttestationKeyResponse& response, VirtualMachine& vm, TPM2B_DIGEST& policy)
{
	bool digestOK = false;
	bool keyOK = false;
	bool signatureOK = false;
	bool magicOK = false;

	// Container for the unmarshaled data
	TPMS_ATTEST attestData;

	// Pointer to the marshaled data
	BYTE* buffer = response.certifyInfo.b.buffer;
	
	// Size of marshaled data
	uint32_t size = static_cast<uint32_t>(response.certifyInfo.b.size);

	// Unmarshal the data and put into attestData
	TSS_TPMS_ATTEST_Unmarshalu(&attestData, &buffer, &size);

	// Verify it was done in a TPM
	magicOK = attestData.magic == TPM_GENERATED_VALUE;

	// Verify authpolicy is the expected
	digestOK = memcmp(policy.b.buffer, response.attestationPK.publicArea.authPolicy.b.buffer, policy.b.size) == 0;
	
	// Verify name 
	unsigned char name[SHA256_DIGEST_SIZE + 2];
	generatePublicName(response.attestationPK,name);

	if (memcmp(attestData.attested.creation.objectName.b.buffer, name, SHA256_DIGEST_SIZE + 2) == 0)
		keyOK = true;

	// Prepare expected value
	TPMT_HA digest;
	digest.hashAlg = TPM_ALG_SHA256;
	uint16_t sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	TSS_Hash_Generate(&digest, response.certifyInfo.b.size, response.certifyInfo.b.buffer, 0, NULL);

	// Convert PK 
	EVP_PKEY* vmek_evp = nullptr;
	convertEcPublicToEvpPubKey(&vmek_evp, &vm.endorsementKey.outPublic.publicArea.unique.ecc);

	int rc = verifyEcSignatureFromEvpPubKey(reinterpret_cast<uint8_t*>(&digest.digest), sizeInBytes, &response.signature, vmek_evp);
	signatureOK = rc == SUCCESS;

	// Return true if all is valid
	return digestOK && signatureOK && keyOK && magicOK;
}
/**
 * Calculates the "name" of the public key
 * 
 * @param publicKey is the public key to calculate the name of
 * @param nameOut is the result of the operation
 */
void Orchestrator::generatePublicName(TPM2B_PUBLIC& publicKey, unsigned char* nameOut)
{
	TPM2B_TEMPLATE marshaled;
	TPMT_HA name;
	uint16_t written;
	uint32_t size;
	uint8_t* buffer;

	name.hashAlg = publicKey.publicArea.nameAlg;

	written = 0;
	size = sizeof(marshaled.t.buffer);
	buffer = marshaled.t.buffer;

	int rc = TSS_TPMT_PUBLIC_Marshalu(&publicKey.publicArea, &written, &buffer, &size);
	marshaled.t.size = written;

	if (rc == SUCCESS) {
		rc = TSS_Hash_Generate(&name, marshaled.t.size, marshaled.t.buffer,	0, NULL);
	}
	else {
		printf("[-] Error in mashalling key\n");
	}
	if (rc != SUCCESS) printf("[-] Error in hashing marshalled key\n");


	nameOut[0] = name.hashAlg >> 8;
	nameOut[1] = name.hashAlg & 0xff;
	memcpy(&nameOut[2], name.digest.tssmax, SHA256_DIGEST_SIZE);
}

/**
 * Determines if a certain PCR is selected in the selection
 * Original code found in IBM TSS
 *
 * @param pcr is the PCR register to look up (0-23)
 * @param selection is the structure to check against
 * @return true if found, otherwise false
 */
bool Orchestrator::isSelected(int pcr, TPMS_PCR_SELECTION* selection)
{
    return (selection->pcrSelect[pcr / 8] & (1 << (pcr % 8))) != 0 ? pcr < IMPLEMENTATION_PCR : false;
}
