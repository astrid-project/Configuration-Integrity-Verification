#include <stdio.h>
#include "Orchestrator.h"
#include "openssl/sha.h"




int main() {
	printf("[-------- Configuration Integrity Verification Test --------]\n");
	Orchestrator os;
	TSS_CONTEXT* ctx = nullptr;
	TpmManager tpm; 

	unsigned char fileHash[SHA256_DIGEST_SIZE] = { 0xc0,0x71,0xf8,0x3c,0x20,0x9b,0x60,0x94,0x42,0xac,0xd1,0xa0,0xa4,0xe9,0xbc,0x6e,0x1a,0x21,0xf8,0x24,0xa2,0x07,0x0e,0x18,0xf1,0x0b,0x3f,0xec,0x6c,0x17,0xe5,0x1f};
	const char* fileLocation = "C:\\Users\\Bonne\\Desktop\\git-bash-real.exe";		// Replace with whatever you have
	const char* BadfileLocation = "C:\\Users\\Bonne\\Desktop\\git-bash-fake.exe";	// Same here. I Just renamed IE :D


	tpm.initialize_new_context(&ctx);
	tpm.boot_tpm(ctx);
	

	printf("[*] Deploying VM\n");
	os.deployVMs(ctx,&tpm);


	/* Do a legit attestation */

	printf("[*] Asking VM to re-meassure\n");
    os.updateMeasurements(0, fileHash, 12, fileLocation);

	printf("[*] Requesting VM to attest via quote\n");
    os.requestAttestationByQuote(0);
	
	printf("[*] Requesting VM to attest via proof\n");
    os.requestAttestationByProof(0);


	/* Emulate that the binary changed */

	printf("[*] Asking VM to re-meassure (Bad file!)\n");
    os.updateMeasurements(0, fileHash, 12, BadfileLocation);

	printf("[*] Requesting VM to attest via quote (Should fail)\n");
    os.requestAttestationByQuote(0);

	printf("[*] Requesting VM to attest via proof (Should fail)\n");
    os.requestAttestationByProof(0);

//	TSS_Delete(ctx);

	return 0;
}
