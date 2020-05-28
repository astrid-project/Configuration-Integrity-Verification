#ifndef VMSTRUCTURE_H
#define VMSTRUCTURE_H

#include "VirtualMachine.h"
struct VMStructure {
	VMStructure(VirtualMachine& machine, const int ids) : vm(machine), id(ids) 
	{
		//PCR 1-16 is all zeroes 
		for (int pcr = 0; pcr < 17; pcr++) {
			for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
				vPCR[pcr][i] = 0x00; 
			}
		}

		//PCR 17-23 is all ff 
		for (int pcr = 17; pcr < 23; pcr++) {
			for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
				vPCR[pcr][i] = 0xff;
			}
		}

		// PCR 24 is all zeroes
		for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
			vPCR[23][i] = 0x00;
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
