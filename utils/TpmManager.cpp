//
// Created by s180222 on 04-02-2020.
//

#include <Template.h>
#include <string>
#include "TpmManager.h"
#include "tss_includes.h"
#include "defines.h"

#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib") // htonl
#else
#include <cstring> // memcpy
#endif


/* Runs a powercycle on the TPM */
void TpmManager::boot_tpm(TSS_CONTEXT* user_ctx)
{
#ifndef HWTPM

#ifdef VERBOSE
	printf("[*] Running TPM Powercycle\n");
#endif

	TSS_CONTEXT* ctx = nullptr;
	last_err = TSS_Create(&ctx);

	last_err = TSS_TransmitPlatform(ctx, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");
	if (last_err != SUCCESS) handle_TPM_error();
	last_err = TSS_TransmitPlatform(ctx, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform");
	if (last_err != SUCCESS) handle_TPM_error();
	last_err = TSS_TransmitPlatform(ctx, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
	if (last_err != SUCCESS) handle_TPM_error();

	TSS_Delete(ctx);

	Startup_In in;
	in.startupType = TPM_SU_CLEAR;
	last_err = TSS_Execute(user_ctx,
	                       nullptr,
	                       (COMMAND_PARAMETERS*)&in,
	                       nullptr,
	                       TPM_CC_Startup,
	                       TPM_RH_NULL, NULL, 0);
#endif
}


void TpmManager::initialize_new_context(TSS_CONTEXT** ctx)
{
#ifdef VERBOSE
	printf("[*] Initializing new context\n");
#endif

	last_err = TSS_Create(ctx);
	if (last_err != SUCCESS) handle_TPM_error();
}


void TpmManager::handle_TPM_error()
{
	const char* msg = nullptr;
	const char* submsg = nullptr;
	const char* num = nullptr;

	TSS_ResponseCode_toString(&msg, &submsg, &num, static_cast<TPM_RC>(last_err));
	printf("[-] An error occured: %s (%s %s)\n", msg, submsg, num);
	//TODO: If unexpected or severe, do cleanup and exit.
}



void TpmManager::pcrExtend(TSS_CONTEXT *ctx, unsigned char *binaryHash, uint8_t pcr)
{

#ifdef VERBOSE
	printf("[*] Executing PCR Extend\n");
#endif

	PCR_Extend_In 		in;

	in.digests.count = 1;
	in.digests.digests[0].hashAlg = TPM_ALG_SHA256;
	in.pcrHandle = pcr;
	memcpy((uint8_t*)&in.digests.digests[0].digest, binaryHash, SHA256_DIGEST_SIZE); // Can be optimized

	last_err = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_PCR_Extend,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
	if (last_err != SUCCESS) handle_TPM_error();
}

CertifyCreation_Out TpmManager::certify_creation(TSS_CONTEXT* ctx, TPM_HANDLE& signing_key, TPM_HANDLE& certifiable_key,
                                                 TPM2B_DIGEST& creation_hash, TPMT_TK_CREATION& creation_ticket,
                                                 TPM_HANDLE* sessionHandle, const char* pass)
{
#ifdef VERBOSE
	printf("[*] Executing Certify Creation\n");
#endif
	CertifyCreation_In in;
	CertifyCreation_Out out;
	TPMI_SH_AUTH_SESSION sessionHandle0 = sessionHandle == nullptr ? TPM_RS_PW : *sessionHandle;
	unsigned int sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	unsigned int sessionAttributes1 = 0;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes2 = 0;


	in.objectHandle = certifiable_key;
	in.signHandle = signing_key;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	in.qualifyingData.t.size = 0;
	in.creationHash = creation_hash;
	in.creationTicket = creation_ticket;


	int rc = TSS_Execute(ctx,
	                     (RESPONSE_PARAMETERS*)&out,
	                     (COMMAND_PARAMETERS*)&in,
	                     nullptr,
	                     TPM_CC_CertifyCreation,
	                     sessionHandle0, pass, sessionAttributes0,
	                     sessionHandle1, NULL, sessionAttributes1,
	                     sessionHandle2, NULL, sessionAttributes2,
	                     TPM_RH_NULL, NULL, 0);

	if (rc != SUCCESS)
		handle_TPM_error();

	return out;
}

Quote_Out TpmManager::getQuote(TSS_CONTEXT* ctx, TPML_PCR_SELECTION& pcrs, TPM2B_DATA* extra, TPM_HANDLE signingKey, const char* signingKeyPass)
{
#ifdef VERBOSE
	printf("[*] Executing PCR Quote\n");
#endif
	Quote_In 			in;
	Quote_Out 			out;

	TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
	unsigned int		sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
	unsigned int		sessionAttributes1 = 0;
	TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
	unsigned int		sessionAttributes2 = 0;

	in.PCRselect = pcrs;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	in.signHandle = signingKey;
	if (extra != nullptr)
		in.qualifyingData = *extra;
	else in.qualifyingData.t.size = 0;

	last_err = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Quote,
		sessionHandle0, signingKeyPass, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

	return out;
}

CreatePrimary_Out TpmManager::create_primary_key(TSS_CONTEXT* ctx, TPMI_RH_HIERARCHY hierarchy,
                                                 TPM2B_PUBLIC& pubTemplate)
{
#ifdef VERBOSE
	printf("[*] Creating Primary Key\n");
#endif
	CreatePrimary_In in;
	CreatePrimary_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;
	unsigned int sessionAttributes0 = 0;

	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
	in.primaryHandle = hierarchy;
	in.inSensitive.sensitive.data.t.size = 0;
	in.inSensitive.sensitive.userAuth.t.size = 0;

	in.inPublic = pubTemplate;

	last_err = TSS_Execute(ctx,
	                       (RESPONSE_PARAMETERS*)&out,
	                       (COMMAND_PARAMETERS*)&in,
	                       nullptr,
	                       TPM_CC_CreatePrimary,
	                       sessionHandle0, NULL, sessionAttributes0,
	                       sessionHandle1, NULL, sessionAttributes1,
	                       sessionHandle2, NULL, sessionAttributes2,
	                       TPM_RH_NULL, NULL, 0);
	if (last_err != SUCCESS)
		handle_TPM_error();
	return out;
}
void TpmManager::start_authorization_session(TSS_CONTEXT* ctx, TPMI_SH_POLICY* sessionHandle, TPM_SE sessionType)
{
#ifdef VERBOSE
	std::string type;
	if (sessionType == TPM_SE_HMAC) type = "HMAC";
	else if (sessionType == TPM_SE_POLICY) type = "Policy";
	else if (sessionType == TPM_SE_TRIAL) type = "Trial";

	printf("[*] Starting authroization session of type %s\n", type.c_str());

#endif
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;


	in.tpmKey = TPM_RH_NULL;
	in.encryptedSalt.b.size = 0;
	in.bind = TPM_RH_NULL;
	in.nonceCaller.t.size = 0;
	in.symmetric.algorithm = TPM_ALG_XOR;
	in.authHash = TPM_ALG_SHA256;
	in.symmetric.keyBits.xorr = TPM_ALG_SHA256;
	in.symmetric.mode.sym = TPM_ALG_NULL; /* none for xor */
	extra.bindPassword = nullptr;
	in.sessionType = sessionType;

	last_err = TSS_Execute(ctx,
	                       (RESPONSE_PARAMETERS*)&out,
	                       (COMMAND_PARAMETERS*)&in,
	                       (EXTRA_PARAMETERS*)&extra,
	                       TPM_CC_StartAuthSession,
	                       TPM_RH_NULL, NULL, 0);
	if (last_err != SUCCESS)
		handle_TPM_error();

	*sessionHandle = out.sessionHandle;
}

void TpmManager::flush_context(TSS_CONTEXT* ctx, TPM_HANDLE handle)
{
#ifdef VERBOSE
	printf("[*] Flushing handle %08x\n", handle);
#endif
	FlushContext_In in;
	in.flushHandle = handle;

	last_err = TSS_Execute(ctx,
	                       nullptr,
	                       (COMMAND_PARAMETERS*)&in,
	                       nullptr,
	                       TPM_CC_FlushContext,
	                       TPM_RH_NULL, NULL, 0);

	if (last_err != SUCCESS)
		handle_TPM_error();
}

LoadedKey TpmManager::load_key(TSS_CONTEXT* ctx, TPM_HANDLE parent, unsigned char* parent_pass, Create_Out& sealedKey,
                               const TPM_HANDLE* policySession)
{
#ifdef VERBOSE
	printf("[*] Loading key\n");
#endif
	Load_In in;
	Load_Out out;
	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	unsigned int sessionAttributes0 = 0;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	unsigned int sessionAttributes1 = 0;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes2 = 0;
	in.inPrivate = sealedKey.outPrivate;
	in.inPublic = sealedKey.outPublic;
	in.parentHandle = parent;

	if (policySession != nullptr)
	{
		sessionHandle0 = *policySession;
		sessionAttributes0 = 1;
	}


	last_err = TSS_Execute(ctx,
	                       (RESPONSE_PARAMETERS*)&out,
	                       (COMMAND_PARAMETERS*)&in,
	                       nullptr,
	                       TPM_CC_Load,
	                       sessionHandle0, parent_pass, sessionAttributes0,
	                       sessionHandle1, NULL, sessionAttributes1,
	                       sessionHandle2, NULL, sessionAttributes2,
	                       TPM_RH_NULL, NULL, 0);
	if (last_err != SUCCESS) handle_TPM_error();

	return out;
}

TPMT_SIGNATURE TpmManager::sign(TSS_CONTEXT* ctx, TPM2B_DIGEST* digest, TPM_HANDLE key,
                                const TPM_HANDLE* policySession, TPMT_TK_HASHCHECK* validation, int* err)
{
#ifdef VERBOSE
	printf("[*] Signing message\n");
#endif
	Sign_In in;
	Sign_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = policySession == nullptr ? TPM_RS_PW : *policySession;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = policySession == nullptr ? 0 : 1;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.keyHandle = key;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
	if (validation != nullptr)
		in.validation = *validation;
	else
	{
		in.validation.tag = TPM_ST_HASHCHECK;
		in.validation.hierarchy = TPM_RH_NULL;
		in.validation.digest.t.size = 0;
	}
	in.digest = *digest;

	if (last_err != SUCCESS)
		handle_TPM_error();

	last_err = TSS_Execute(ctx,
	                       (RESPONSE_PARAMETERS*)&out,
	                       (COMMAND_PARAMETERS*)&in,
	                       nullptr,
	                       TPM_CC_Sign,
	                       sessionHandle0, NULL, sessionAttributes0,
	                       sessionHandle1, NULL, sessionAttributes1,
	                       sessionHandle2, NULL, sessionAttributes2,
	                       TPM_RH_NULL, NULL, 0);

	if (last_err != SUCCESS) {
		handle_TPM_error();
	}

	*err = last_err;
	return out.signature;
}


SealedKey TpmManager::create_key(TSS_CONTEXT* ctx, unsigned char* authvalue, TPM_HANDLE parent,
                                 char* parentPass, const TPM_HANDLE* session, TPM2B_PUBLIC* pubTemplate)
{
#ifdef VERBOSE
	printf("[*] Creating Key\n");
#endif
	Create_In in;
	Create_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = session == nullptr ? TPM_RS_PW : *session;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = session == nullptr ? 0 : 1;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;


	in.inSensitive.sensitive.data.t.size = 0;
	in.parentHandle = parent;
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
	in.inPublic = *pubTemplate;
	if (authvalue == nullptr)
	{
		in.inSensitive.sensitive.userAuth.t.size = 0;
	}
	else
	{
		last_err = TSS_TPM2B_Create(&in.inSensitive.sensitive.userAuth.b, authvalue, SHA256_DIGEST_SIZE,
		                            sizeof(TPMU_HA));
		if (last_err != SUCCESS) handle_TPM_error();
	}

	last_err = TSS_Execute(ctx,
	                       (RESPONSE_PARAMETERS*)&out,
	                       (COMMAND_PARAMETERS*)&in,
	                       nullptr,
	                       TPM_CC_Create,
	                       sessionHandle0, parentPass, sessionAttributes0,
	                       sessionHandle1, NULL, sessionAttributes1,
	                       sessionHandle2, NULL, sessionAttributes2,
	                       TPM_RH_NULL, NULL, 0);
	if (last_err != SUCCESS)
		handle_TPM_error();


	return out;
}

