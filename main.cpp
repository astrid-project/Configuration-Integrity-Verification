#include <stdio.h>
#include "Orchestrator.h"




int main(){
	printf("[-------- Configuration Integrity Verification Test --------]\n");
	Orchestrator os;
	TSS_CONTEXT* ctx = nullptr;
	TpmManager tpm;
    TSS_SetProperty(nullptr, TPM_TRACE_LEVEL, "1");

    // Correct hash of AttestableFile_correct
	unsigned char fileHash[SHA256_DIGEST_SIZE] = {0x3f,0xce,0x6f,0xd6,0xb7,0xff,0x35,0x31,0xd7,0xcb,0xcb,0xa4,0x69,0xda,0xe0,0x87,0xf9,0xd2,0x9d,0xc7,0xdc,0x8d,0x9e,0x7f,0xe3,0x74,0x18,0x88,0x25,0xab,0x1c,0xe5};
	const char* fileLocation = "../data/AttestableFile_correct";		// Replace with whatever you have
	const char* BadfileLocation = "../data/AttestableFile_modified";	// For testing purposes the location of the modified binary


	tpm.initialize_new_context(&ctx);
	tpm.boot_tpm(ctx);


    printf("[*] Deploying VM\n");
	os.deployVMs(ctx,&tpm);


	printf("[*] Asking VM to re-meassure\n");
    os.updateMeasurements(0, fileHash, 12, fileLocation);

	printf("[*] Requesting VM to attest via quote\n");
    os.requestAttestationByQuote(0);

	printf("[*] Requesting VM to attest via proof\n");
    os.requestAttestationByProof(0);


	// Simulate that the binary changed

	printf("[*] Asking VM to re-meassure (Bad file!)\n");
    os.updateMeasurements(0, fileHash, 12, BadfileLocation);

	printf("[*] Requesting VM to attest via quote (Should fail)\n");
    os.requestAttestationByQuote(0);

	printf("[*] Requesting VM to attest via proof (Should fail)\n");
    os.requestAttestationByProof(0);

	TSS_Delete(ctx);
/*
 * For timing purpuses
    FILE* fd = fopen("C:\\Users\\s180222\\Documents\\Timings.txt", "a");
    char buf[2048];
    snprintf(buf, sizeof(buf), "\n\n");
    fwrite(buf, sizeof(char), strlen(buf), fd);
    fclose(fd);

    */

	return 0;
}