#ifndef POLICYMANAGER_H
#define POLICYMANAGER_H
#include "tss_includes.h"
#include "TpmManager.h"

class PolicyManager {
public:
    void policyPCR(TSS_CONTEXT *ctx, const TPMI_SH_POLICY *session, TPML_PCR_SELECTION pcrs);
private:
    void handle_TPM_error();
    int last_err_ = 0;

};

#endif // POLICYMANAGER_H
