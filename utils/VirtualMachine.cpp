#include "VirtualMachine.h"
#include "Template.h"
#include "openssl/sha.h"

/**
 * Default constructor
 * NOTE: The parameters are for PoC purposes. It should have its own instance of both.
 * @param ctx TSS Context pointer
 * @param tpm TPM pointer
 */
VirtualMachine::VirtualMachine(TSS_CONTEXT* ctx, TpmManager* tpm)
{
	this->tpm = tpm;
	this->ctx = ctx;

	PCRs = TPML_PCR_SELECTION{};
	attestationKey = SealedKey{};
	policy = PolicyManager();

	// Create an unrestricted storage key. 
	// TODO: This would defacto be the same key for all the VMs. Add a unique value to it.
	ak_primary = Template::PrimaryECC_Storage(nullptr);
	PrimaryKey pk = tpm->create_primary_key(ctx, TPM_RH_NULL, ak_primary);

	// Create endorsement key
	// NOTE: This is again for PoC purposes. The EK should be already in the TPM.
	TPM2B_PUBLIC ek_template = Template::ECC_UnrestrictedSigning(nullptr);
	this->endorsementKey = tpm->create_key(ctx, nullptr, pk.objectHandle, nullptr, nullptr, &ek_template);
	tpm->flush_context(ctx, pk.objectHandle);
}

/**
 * Attests to the current configuration
 * Can only successfully execute completely if configuration is valid in regards to the attestation key.
 *
 * @param nonce the nonce to sign
 * @param success is 0 if signature available.
 * @return signature over nonce if the key could be loaded.
 */
TPMT_SIGNATURE VirtualMachine::attestConfiguration(TPM2B_DIGEST& nonce, int* success)
{
	TPM_HANDLE session_handle = 0;

	// 0: Load ak_parent
	PrimaryKey akpk = tpm->create_primary_key(ctx, TPM_RH_NULL, this->ak_primary);

	// 1: Load attestation key
	LoadedKey ak = tpm->load_key(ctx, akpk.objectHandle, nullptr, this->attestationKey, nullptr);

	// 2: Start policySession
	tpm->start_authorization_session(ctx, &session_handle, TPM_SE_POLICY);

	// 3: Execute PolicyPCR
	policy.policyPCR(ctx, &session_handle, this->PCRs);

	// 4: Sign nonce

	TPMT_SIGNATURE signature = tpm->sign(ctx, &nonce, ak.objectHandle, &session_handle, nullptr, success);

	tpm->flush_context(ctx, akpk.objectHandle);
	tpm->flush_context(ctx, ak.objectHandle);

	// 5: return signature 
	return signature;
}


/**
 * Creates a new attestation key in the VM
 *
 * @param policy_digest the digest to seal the key with. Should reflect what the PCR digest would read.
 * @param pcrs the PCR selection that is to be read during attestation
 * @return CreateAttestationKeyResponse containing data to verify the creation of the key
 */
CreateAttestationKeyResponse VirtualMachine::createNewAttestationKey(TPM2B_DIGEST& policy_digest,
                                                                     TPML_PCR_SELECTION pcrs)
{
	// Set the PCR selection for future attestations
	this->PCRs = pcrs;
	BYTE pccs[sizeof(TPML_PCR_SELECTION)];

	BYTE* buffer;
	buffer = pccs;

	UINT16 written = 0;
	TSS_TPML_PCR_SELECTION_Marshal(&pcrs, &written, &buffer, nullptr);

	// Load attestation primary key
	PrimaryKey akpk = tpm->create_primary_key(ctx, TPM_RH_NULL, this->ak_primary);

	// Create the attestation key
	TPM2B_PUBLIC keyTemplate = Template::ECC_Signing(&policy_digest);
	attestationKey = tpm->create_key(ctx, nullptr, akpk.objectHandle, nullptr, nullptr, &keyTemplate);

	// Load AK
	LoadedKey ak_load = tpm->load_key(ctx, akpk.objectHandle, nullptr, attestationKey, nullptr);

	// Load EK
	LoadedKey ek_load = tpm->load_key(ctx, akpk.objectHandle, nullptr, endorsementKey, nullptr);

	// Certify 
	CreationCertificate cert = tpm->certify_creation(ctx, ek_load.objectHandle, ak_load.objectHandle, attestationKey.creationHash,
	                                  attestationKey.creationTicket, nullptr, nullptr);

	// Flush keys
	tpm->flush_context(ctx, ak_load.objectHandle);
	tpm->flush_context(ctx, ek_load.objectHandle);
	tpm->flush_context(ctx, akpk.objectHandle);

	// Return
	CreateAttestationKeyResponse response{};
	response.certifyInfo = cert.certifyInfo;
	response.signature = cert.signature;
	response.attestationPK = attestationKey.outPublic;

	return response;
}

/**
 * Executes a TPM2_Quote on the local TPM and returns the result.
 *
 * @param pcrs is the selection of PCRs to quote
 * @param nonce is the nonce to include in the signature returned
 * @return Quote containing signature and marshalled quote
 */
Quote VirtualMachine::quote(TPML_PCR_SELECTION& pcrs, TPM2B_DATA* nonce)
{
	PrimaryKey akpk = tpm->create_primary_key(ctx, TPM_RH_NULL, this->ak_primary);
	LoadedKey ek_load = tpm->load_key(ctx, akpk.objectHandle, nullptr, endorsementKey, nullptr);

	Quote cert = tpm->getQuote(ctx, pcrs, nonce, ek_load.objectHandle, nullptr);

	tpm->flush_context(ctx, akpk.objectHandle);
	tpm->flush_context(ctx, ek_load.objectHandle);

	return cert;

}

/**
 * Executes a TPM2_PCR_Extend
 *
 * NOTE: Safety critical function! If this is not executed correctly, and adversary could simply extend the PCRs with the correct hash!
 * TODO: Maybe do the hash on the TPM and return signed ticket to orchestrator?
 * @param filelocation is the absolute or relative location of the file to extend with
 * @param PCR is the register to extend
 */
void VirtualMachine::PCRExtend(const char* fileLocation, uint8_t PCR)
{
	// Read file 
	unsigned char* binaryData = nullptr;
	unsigned char dataDigest[SHA256_DIGEST_SIZE];
	size_t length;
	VirtualMachine::readBinary(&binaryData, &length, fileLocation);
	printf("[*] Binary length read: %lu\n", length);

	// Hash it
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, binaryData, length);
	SHA256_Final(dataDigest, &sha256);		

	// Free datapointer
	free(binaryData);

	// Execute extend
    tpm->pcrExtend(ctx, dataDigest, PCR);

}

/**
 * Reads a binary file on the system 
 *
 * @param data is a pointer to a unsigned char array, this pointer is set to point on the heap, remember to free
 * @param len is a pointer to the length of the binary, that is being determined in this function
 * @param location is the location of the file to read

 
 */
void VirtualMachine::readBinary(unsigned char** data, size_t* len, const char* location)
{
		*data = nullptr;
		*len = 0;

		// Open in binary mode
		FILE* f = fopen(location, "rb");
		if (f == nullptr) {
			printf("[-] Not able to find file %s\n", location);
			return;
		}

		// Find filesize
		fseek(f, 0, SEEK_END);
		*len = ftell(f);

		// Go back to beginning
		fseek(f, 0L, SEEK_SET);

		// Allocate memory
		*data = (unsigned char*)malloc(*len);

		// Read binary data
		fread(*data, 1, *len, f);

		// Close
		fclose(f);
}
