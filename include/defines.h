#pragma once
#include "tss_includes.h"

#define SUCCESS 0
#define QUOTE_NONCE_SIZE 8
#define TRUSTED 1
#define UNTRUSTED 0
#define CC_SIZE 4
typedef Create_Out SealedKey;
typedef Quote_Out Quote;
typedef CreatePrimary_Out PrimaryKey;
typedef CertifyCreation_Out CreationCertificate;
