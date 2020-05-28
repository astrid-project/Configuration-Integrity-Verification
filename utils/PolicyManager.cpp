//
// Created by s180222 on 05-02-2020.
//

#include "PolicyManager.h"
#include "defines.h"
#include "tss_includes.h"

void PolicyManager::policyPCR(TSS_CONTEXT *ctx, const TPMI_SH_POLICY *session, TPML_PCR_SELECTION pcrs) {
#ifdef VERBOSE
    printf("[*] Executing PolicyPCR\n");
#endif
    PolicyPCR_In in;
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
    unsigned int sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;

    in.policySession = *session;
    in.pcrDigest.b.size = 0;
    in.pcrs = pcrs;
    last_err_ = TSS_Execute(ctx,
                            nullptr,
                            (COMMAND_PARAMETERS *) &in,
                            nullptr,
                            TPM_CC_PolicyPCR,
                            sessionHandle0, NULL, sessionAttributes0,
                            sessionHandle1, NULL, sessionAttributes1,
                            sessionHandle2, NULL, sessionAttributes2,
                            TPM_RH_NULL, NULL, 0);
    if (last_err_ != SUCCESS) handle_TPM_error();
}

void PolicyManager::handle_TPM_error() {
    const char *msg;
    const char *submsg;
    const char *num;

    TSS_ResponseCode_toString(&msg, &submsg, &num, static_cast<TPM_RC>(last_err_));
    printf("[-] An error occured: %s (%s %s).\n", msg, submsg, num);
}


