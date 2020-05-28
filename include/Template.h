
#ifndef TEMPLATE_H
#define TEMPLATE_H
#include "ibmtss/TPM_Types.h"

class Template {
public:
    static TPM2B_PUBLIC PrimaryECC_Storage(TPM2B_DIGEST *policyDigest);

    static TPM2B_PUBLIC ECC_Signing(TPM2B_DIGEST *policyDigest);

    static TPM2B_PUBLIC ECC_UnrestrictedSigning(TPM2B_DIGEST *policyDigest);
    
};


#endif // TEMPLATE_H
