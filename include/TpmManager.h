#ifndef TPMMANAGER_H
#define TPMMANAGER_H
#include <ibmtss/tss.h>
#include <map>

using NV_INDEX = TPMI_RH_NV_INDEX;
using SealedKey = Create_Out;
using LoadedKey = Load_Out;
using LoadedPublicKey = LoadExternal_Out;
using PublicData = ReadPublic_Out;

class TpmManager {
public:
    void boot_tpm(TSS_CONTEXT *ctx);
    void initialize_new_context(TSS_CONTEXT **ctx);
    void start_authorization_session(TSS_CONTEXT *ctx, TPMI_SH_POLICY *sessionHandle, TPM_SE sessionType);
    void flush_context(TSS_CONTEXT *ctx, TPM_HANDLE handle);
    PCR_Read_Out readPCR(TSS_CONTEXT *ctx, int pcr);
    void pcrExtend(TSS_CONTEXT *ctx, unsigned char *binaryHash, uint8_t pcr);
    CertifyCreation_Out certify_creation(TSS_CONTEXT* ctx, TPM_HANDLE& signing_key, TPM_HANDLE& certifiable_key, TPM2B_DIGEST& creation_hash, TPMT_TK_CREATION& creation_ticket, const TPM_HANDLE* sessionHandle, const char* pass);
    Quote_Out getQuote(TSS_CONTEXT* ctx, TPML_PCR_SELECTION& pcrs, TPM2B_DATA* extra, TPM_HANDLE signingKey, const char* signingKeyPass);
    TPMT_SIGNATURE sign(TSS_CONTEXT* ctx, TPM2B_DIGEST* digest, TPM_HANDLE key, const TPM_HANDLE* policySession, TPMT_TK_HASHCHECK *validation, int* err);
    CreatePrimary_Out create_primary_key(TSS_CONTEXT* ctx, TPMI_RH_HIERARCHY hierarchy, TPM2B_PUBLIC& pubTemplate);
    SealedKey create_key(TSS_CONTEXT *ctx, unsigned char *authvalue, TPM_HANDLE parent, char *parentPass, const TPM_HANDLE *session, TPM2B_PUBLIC *pubTemplate);
    LoadedKey load_key(TSS_CONTEXT *ctx, TPM_HANDLE parent, unsigned char *parent_pass, SealedKey &sealedKey, const TPM_HANDLE *pSession);


private:
    void handle_TPM_error();
    int last_err = 0;
};

#endif // TPMMANAGER_H
