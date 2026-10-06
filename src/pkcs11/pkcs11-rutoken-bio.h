/* Rutoken BioLib ABI, independently declared from SDK 2026 biopkcs11*.h. */
#ifndef OPENSC_PKCS11_RUTOKEN_BIO_H
#define OPENSC_PKCS11_RUTOKEN_BIO_H

#include "pkcs11-rutoken.h"

#ifdef _WIN32
#pragma pack(push, rutoken_bio, 1)
#endif

typedef struct CK_FUNCTION_LIST_BIO CK_FUNCTION_LIST_BIO;
typedef CK_FUNCTION_LIST_BIO *CK_FUNCTION_LIST_BIO_PTR;
typedef CK_FUNCTION_LIST_BIO_PTR *CK_FUNCTION_LIST_BIO_PTR_PTR;

#define CK_BIO_MAX_ADAPTER_NAME_LENGTH 32

typedef struct CK_BIO_SCANNERS_ADAPTER_INFO {
	CK_CHAR name[CK_BIO_MAX_ADAPTER_NAME_LENGTH];
	CK_BBOOL available;
} CK_BIO_SCANNERS_ADAPTER_INFO, *CK_BIO_SCANNERS_ADAPTER_INFO_PTR;

typedef struct CK_BIO_SCANNER_INFO {
	CK_ULONG id;
	CK_CHAR adapterName[CK_BIO_MAX_ADAPTER_NAME_LENGTH];
} CK_BIO_SCANNER_INFO, *CK_BIO_SCANNER_INFO_PTR;

typedef CK_ULONG CK_BIO_FINGERPRINT_TYPE;
typedef CK_BIO_FINGERPRINT_TYPE *CK_BIO_FINGERPRINT_TYPE_PTR;

typedef struct CK_BIO_FINGERPRINT_INFO {
	CK_ULONG fingerprintId;
	CK_VENDOR_AUTHENTICATION_FACTOR_TYPE type;
	CK_ULONG retryCountLeft;
	CK_ULONG maxRetryCount;
} CK_BIO_FINGERPRINT_INFO, *CK_BIO_FINGERPRINT_INFO_PTR;

typedef struct CK_BIO_FINGERPRINT_SCAN_PARAMS {
	CK_BIO_FINGERPRINT_TYPE type;
	CK_ULONG targetScansCount;
} CK_BIO_FINGERPRINT_SCAN_PARAMS, *CK_BIO_FINGERPRINT_SCAN_PARAMS_PTR;

typedef struct CK_BIO_FINGERPRINT_SCAN_STATUS {
	CK_BIO_FINGERPRINT_TYPE type;
	CK_ULONG currentScansCount;
	CK_ULONG targetScansCount;
} CK_BIO_FINGERPRINT_SCAN_STATUS, *CK_BIO_FINGERPRINT_SCAN_STATUS_PTR;

#define CK_BIO_FUNCTION(name, args) typedef CK_RV (*CK_ ## name) args
CK_BIO_FUNCTION(C_BIO_GetFunctionListBio, (CK_FUNCTION_LIST_BIO_PTR_PTR));
CK_BIO_FUNCTION(C_BIO_Initialize, (CK_BYTE));
CK_BIO_FUNCTION(C_BIO_Finalize, (CK_VOID_PTR));
CK_BIO_FUNCTION(C_BIO_ListScannersAdapters,
		(CK_BIO_SCANNERS_ADAPTER_INFO_PTR, CK_ULONG_PTR));
CK_BIO_FUNCTION(C_BIO_ListScanners, (CK_BIO_SCANNER_INFO_PTR, CK_ULONG_PTR));
CK_BIO_FUNCTION(C_BIO_SetDefaultScanner, (CK_BIO_SCANNER_INFO_PTR));
CK_BIO_FUNCTION(C_BIO_GetFingerprintInfo,
		(CK_SESSION_HANDLE, CK_BIO_FINGERPRINT_INFO_PTR,
		 CK_BIO_FINGERPRINT_SCAN_PARAMS_PTR, CK_ULONG_PTR));
CK_BIO_FUNCTION(C_BIO_SetFingerprintInit,
		(CK_SESSION_HANDLE, CK_BIO_FINGERPRINT_SCAN_PARAMS_PTR, CK_ULONG,
		 CK_BIO_FINGERPRINT_TYPE_PTR));
CK_BIO_FUNCTION(C_BIO_SetFingerprintStatus,
		(CK_SESSION_HANDLE, CK_BIO_FINGERPRINT_SCAN_STATUS_PTR, CK_ULONG_PTR));
CK_BIO_FUNCTION(C_BIO_SetFingerprintScan,
		(CK_SESSION_HANDLE, CK_ULONG, CK_BIO_FINGERPRINT_TYPE_PTR));
CK_BIO_FUNCTION(C_BIO_SetFingerprintScanCancel, (CK_SESSION_HANDLE));
CK_BIO_FUNCTION(C_BIO_SetFingerprintFinal, (CK_SESSION_HANDLE, CK_ULONG_PTR));
CK_BIO_FUNCTION(C_BIO_UnblockFingerprint, (CK_SESSION_HANDLE));
CK_BIO_FUNCTION(C_BIO_Authenticate,
		(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_ULONG, CK_BYTE));
CK_BIO_FUNCTION(C_BIO_AuthenticateCancel, (CK_SESSION_HANDLE));
CK_BIO_FUNCTION(C_BIO_Deauthenticate, (CK_SESSION_HANDLE, CK_BYTE));
#undef CK_BIO_FUNCTION

struct CK_FUNCTION_LIST_BIO {
	CK_VERSION version;
	CK_C_BIO_GetFunctionListBio C_BIO_GetFunctionListBio;
	CK_C_BIO_Initialize C_BIO_Initialize;
	CK_C_BIO_Finalize C_BIO_Finalize;
	CK_C_BIO_ListScannersAdapters C_BIO_ListScannersAdapters;
	CK_C_BIO_ListScanners C_BIO_ListScanners;
	CK_C_BIO_SetDefaultScanner C_BIO_SetDefaultScanner;
	CK_C_BIO_GetFingerprintInfo C_BIO_GetFingerprintInfo;
	CK_C_BIO_SetFingerprintInit C_BIO_SetFingerprintInit;
	CK_C_BIO_SetFingerprintStatus C_BIO_SetFingerprintStatus;
	CK_C_BIO_SetFingerprintScan C_BIO_SetFingerprintScan;
	CK_C_BIO_SetFingerprintScanCancel C_BIO_SetFingerprintScanCancel;
	CK_C_BIO_SetFingerprintFinal C_BIO_SetFingerprintFinal;
	CK_C_BIO_UnblockFingerprint C_BIO_UnblockFingerprint;
	CK_C_BIO_Authenticate C_BIO_Authenticate;
	CK_C_BIO_AuthenticateCancel C_BIO_AuthenticateCancel;
	CK_C_BIO_Deauthenticate C_BIO_Deauthenticate;
};

CK_RV CK_SPEC C_BIO_GetFunctionListBio(CK_FUNCTION_LIST_BIO_PTR_PTR);

#ifdef _WIN32
#pragma pack(pop, rutoken_bio)
#endif
#endif
