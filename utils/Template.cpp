#include "Template.h"
#include "ibmtss/Implementation.h"

TPM2B_PUBLIC Template::PrimaryECC_Storage(TPM2B_DIGEST *policyDigest) {
    TPM2B_PUBLIC public_template = {};
    auto publicArea = &public_template.publicArea;

    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;


    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    deleteObjectAttributes.val = 0;


    publicArea->objectAttributes = addObjectAttributes;
    publicArea->type = TPM_ALG_ECC;        /* RSA or ECC */
    publicArea->nameAlg = TPM_ALG_SHA256;
    publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
    publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
    publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
    publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
    publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    publicArea->parameters.eccDetail.symmetric.keyBits.aes = 128;
    publicArea->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
    publicArea->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
    publicArea->unique.ecc.x.t.size = 0;
    publicArea->unique.ecc.y.t.size = 0;
    publicArea->unique.rsa.t.size = 0;


    if (policyDigest == nullptr)
        publicArea->authPolicy.t.size = 0;
    else {
        publicArea->authPolicy = *policyDigest;
    }


    return public_template;
}

TPM2B_PUBLIC Template::ECC_Signing(TPM2B_DIGEST *policyDigest) {
    TPM2B_PUBLIC public_template = {};
    auto publicArea = &public_template.publicArea;

    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;

    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    deleteObjectAttributes.val = 0;
    if (policyDigest != nullptr) {
        publicArea->authPolicy = *policyDigest;
    } else {
        publicArea->authPolicy.t.size = 0;
    }
    publicArea->objectAttributes = addObjectAttributes;
    publicArea->type = TPM_ALG_ECC;        /* RSA or ECC */
    publicArea->nameAlg = TPM_ALG_SHA256;
    publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    publicArea->objectAttributes.val |= TPMA_OBJECT_ADMINWITHPOLICY; // Set (ADMIN role authorization must be provided by a policy session.)
    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_USERWITHAUTH;
    publicArea->objectAttributes.val |= TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
    publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
    publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    publicArea->parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    publicArea->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.kdf.details.mgf1.hashAlg = TPM_ALG_SHA256;
    publicArea->unique.ecc.x.t.size = 0;
    publicArea->unique.ecc.y.t.size = 0;

    return public_template;
}

TPM2B_PUBLIC Template::ECC_UnrestrictedSigning(TPM2B_DIGEST *policyDigest) {
    TPM2B_PUBLIC public_template = {};
    auto publicArea = &public_template.publicArea;

    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;

    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    deleteObjectAttributes.val = 0;
    if (policyDigest != nullptr) {
        publicArea->authPolicy = *policyDigest;
    } else {
        publicArea->authPolicy.t.size = 0;
    }
    publicArea->objectAttributes = addObjectAttributes;
    publicArea->type = TPM_ALG_ECC;        /* RSA or ECC */
    publicArea->nameAlg = TPM_ALG_SHA256;
    publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH; // Set (ADMIN role authorization must be provided by a policy session.)
    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val |= TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
    publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
    publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    publicArea->parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    publicArea->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.kdf.details.mgf1.hashAlg = TPM_ALG_SHA256;
    publicArea->unique.ecc.x.t.size = 0;
    publicArea->unique.ecc.y.t.size = 0;
    return public_template;
}

