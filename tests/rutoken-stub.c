#define CRYPTOKI_EXPORTS
#include "pkcs11/pkcs11-rutoken.h"

#include <string.h>

static CK_FUNCTION_LIST standard_functions;
static CK_FUNCTION_LIST_EXTENDED extended_functions;

#define STUB_FUNCTION(name, number, parameters) \
CK_RV CK_SPEC name parameters \
{ \
	return CKR_VENDOR_DEFINED + (number); \
}

CK_RV CK_SPEC
C_Initialize(CK_VOID_PTR pInitArgs)
{
	(void)pInitArgs;
	return CKR_OK;
}

CK_RV CK_SPEC
C_Finalize(CK_VOID_PTR pReserved)
{
	(void)pReserved;
	return CKR_OK;
}

CK_RV CK_SPEC
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &standard_functions;
	return CKR_OK;
}

CK_RV CK_SPEC
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		CK_ULONG_PTR pulCount)
{
	(void)tokenPresent;
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;
	if (!pSlotList) {
		*pulCount = 1;
		return CKR_OK;
	}
	if (*pulCount < 1) {
		*pulCount = 1;
		return CKR_BUFFER_TOO_SMALL;
	}
	pSlotList[0] = 7;
	*pulCount = 1;
	return CKR_OK;
}

CK_RV CK_SPEC
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	memset(pInfo, 0, sizeof(*pInfo));
	pInfo->flags = CKF_TOKEN_PRESENT;
	return CKR_OK;
}

CK_RV CK_SPEC
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	(void)flags;
	(void)pApplication;
	(void)notify;
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!phSession)
		return CKR_ARGUMENTS_BAD;
	*phSession = 23;
	return CKR_OK;
}

CK_RV CK_SPEC
C_CloseSession(CK_SESSION_HANDLE hSession)
{
	return hSession == 23 ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

CK_RV CK_SPEC
C_EX_GetTokenInfoExtended(CK_SLOT_ID slotID,
		CK_TOKEN_INFO_EXTENDED_PTR pInfo)
{
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (pInfo->ulSizeofThisStructure != sizeof(*pInfo))
		return CKR_BUFFER_TOO_SMALL;
	memset(pInfo, 0, sizeof(*pInfo));
	pInfo->ulSizeofThisStructure = sizeof(*pInfo);
	pInfo->ulTokenType = 1;
	pInfo->ulTokenClass = 1;
	pInfo->ulProtocolNumber = 2;
	pInfo->ulMicrocodeNumber = 3;
	pInfo->ulOrderNumber = 4;
	pInfo->ulTotalMemory = 4096;
	pInfo->ulFreeMemory = 2048;
	pInfo->ulMinAdminPinLen = 6;
	pInfo->ulMaxAdminPinLen = 32;
	pInfo->ulMinUserPinLen = 6;
	pInfo->ulMaxUserPinLen = 32;
	pInfo->ulMaxAdminRetryCount = 10;
	pInfo->ulAdminRetryCountLeft = 9;
	pInfo->ulMaxUserRetryCount = 10;
	pInfo->ulUserRetryCountLeft = 8;
	memcpy(pInfo->serialNumber, "12345678", sizeof(pInfo->serialNumber));
	return CKR_OK;
}

CK_RV CK_SPEC
C_EX_GetTokenName(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pLabel,
		CK_ULONG_PTR pulLabelLen)
{
	static const char label[] = "Test Rutoken";
	CK_ULONG needed = sizeof(label) - 1;

	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pulLabelLen)
		return CKR_ARGUMENTS_BAD;
	if (!pLabel) {
		*pulLabelLen = needed;
		return CKR_OK;
	}
	if (*pulLabelLen < needed) {
		*pulLabelLen = needed;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(pLabel, label, needed);
	*pulLabelLen = needed;
	return CKR_OK;
}

CK_RV CK_SPEC
C_EX_GetFunctionListExtended(CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &extended_functions;
	return CKR_OK;
}

STUB_FUNCTION(C_EX_InitToken, 1,
		(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		 CK_RUTOKEN_INIT_PARAM_PTR pInitInfo))
STUB_FUNCTION(C_EX_UnblockUserPIN, 3, (CK_SESSION_HANDLE hSession))
STUB_FUNCTION(C_EX_SetTokenName, 4,
		(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pLabel, CK_ULONG ulLabelLen))
STUB_FUNCTION(C_EX_SetLicense, 5,
		(CK_SESSION_HANDLE hSession, CK_ULONG ulLicenseNum,
		 CK_BYTE_PTR pLicense, CK_ULONG ulLicenseLen))
STUB_FUNCTION(C_EX_GetLicense, 6,
		(CK_SESSION_HANDLE hSession, CK_ULONG ulLicenseNum,
		 CK_BYTE_PTR pLicense, CK_ULONG_PTR pulLicenseLen))
STUB_FUNCTION(C_EX_GetCertificateInfoText, 7,
		(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hCert,
		 CK_CHAR_PTR *pInfo, CK_ULONG_PTR pulInfoLen))
STUB_FUNCTION(C_EX_PKCS7Sign, 8,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		 CK_OBJECT_HANDLE hCert, CK_BYTE_PTR *ppEnvelope,
		 CK_ULONG_PTR pEnvelopeLen, CK_OBJECT_HANDLE hPrivKey,
		 CK_OBJECT_HANDLE_PTR phCertificates, CK_ULONG ulCertificatesLen,
		 CK_ULONG flags))
STUB_FUNCTION(C_EX_CreateCSR, 9,
		(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey,
		 CK_CHAR_PTR *dn, CK_ULONG dnLength, CK_BYTE_PTR *pCsr,
		 CK_ULONG_PTR pulCsrLength, CK_OBJECT_HANDLE hPrivKey,
		 CK_CHAR_PTR *pAttributes, CK_ULONG ulAttributesLength,
		 CK_CHAR_PTR *pExtensions, CK_ULONG ulExtensionsLength))
STUB_FUNCTION(C_EX_FreeBuffer, 10, (CK_BYTE_PTR pBuffer))
STUB_FUNCTION(C_EX_SetLocalPIN, 12,
		(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pUserPin, CK_ULONG ulUserPinLen,
		 CK_UTF8CHAR_PTR pNewLocalPin, CK_ULONG ulNewLocalPinLen,
		 CK_ULONG ulLocalID))
STUB_FUNCTION(C_EX_LoadActivationKey, 13,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR key, CK_ULONG keySize))
STUB_FUNCTION(C_EX_SetActivationPassword, 14,
		(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR password))
STUB_FUNCTION(C_EX_GetVolumesInfo, 15,
		(CK_SLOT_ID slotID, CK_VOLUME_INFO_EXTENDED_PTR pInfo,
		 CK_ULONG_PTR pulInfoCount))
STUB_FUNCTION(C_EX_GetDriveSize, 16,
		(CK_SLOT_ID slotID, CK_ULONG_PTR pulDriveSize))
STUB_FUNCTION(C_EX_ChangeVolumeAttributes, 17,
		(CK_SLOT_ID slotID, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
		 CK_ULONG ulPinLen, CK_VOLUME_ID_EXTENDED idVolume,
		 CK_ACCESS_MODE_EXTENDED newAccessMode, CK_BBOOL bPermanent))
STUB_FUNCTION(C_EX_FormatDrive, 18,
		(CK_SLOT_ID slotID, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
		 CK_ULONG ulPinLen, CK_VOLUME_FORMAT_INFO_EXTENDED_PTR pInitParams,
		 CK_ULONG ulInitParamsCount))
STUB_FUNCTION(C_EX_TokenManage, 19,
		(CK_SESSION_HANDLE hSession, CK_ULONG ulMode, CK_VOID_PTR pValue))
STUB_FUNCTION(C_EX_GenerateActivationPassword, 20,
		(CK_SESSION_HANDLE hSession, CK_ULONG ulPasswordNumber,
		 CK_UTF8CHAR_PTR pPassword, CK_ULONG_PTR pulPasswordSize,
		 CK_ULONG ulPasswordCharacterSet))
STUB_FUNCTION(C_EX_GetJournal, 21,
		(CK_SLOT_ID slotID, CK_BYTE_PTR pJournal, CK_ULONG_PTR pulJournalSize))
STUB_FUNCTION(C_EX_SignInvisibleInit, 22,
		(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey))
STUB_FUNCTION(C_EX_SignInvisible, 23,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen))
STUB_FUNCTION(C_EX_SlotManage, 24,
		(CK_SLOT_ID slotID, CK_ULONG ulMode, CK_VOID_PTR pValue))
STUB_FUNCTION(C_EX_WrapKey, 25,
		(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pGenerationMechanism,
		 CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount,
		 CK_MECHANISM_PTR pDerivationMechanism, CK_OBJECT_HANDLE hBaseKey,
		 CK_MECHANISM_PTR pWrappingMechanism, CK_BYTE_PTR pWrappedKey,
		 CK_ULONG_PTR pulWrappedKeyLen, CK_OBJECT_HANDLE_PTR phKey))
STUB_FUNCTION(C_EX_UnwrapKey, 26,
		(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pDerivationMechanism,
		 CK_OBJECT_HANDLE hBaseKey, CK_MECHANISM_PTR pUnwrappingMechanism,
		 CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
		 CK_ATTRIBUTE_PTR pKeyTemplate, CK_ULONG ulKeyAttributeCount,
		 CK_OBJECT_HANDLE_PTR phKey))
STUB_FUNCTION(C_EX_PKCS7VerifyInit, 27,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pCms, CK_ULONG ulCmsSize,
		 CK_VENDOR_X509_STORE_PTR pStore, CK_VENDOR_CRL_MODE ckMode,
		 CK_FLAGS flags))
STUB_FUNCTION(C_EX_PKCS7Verify, 28,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR_PTR ppData,
		 CK_ULONG_PTR pulDataSize,
		 CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		 CK_ULONG_PTR pulSignerCertificatesCount))
STUB_FUNCTION(C_EX_PKCS7VerifyUpdate, 29,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataSize))
STUB_FUNCTION(C_EX_PKCS7VerifyFinal, 30,
		(CK_SESSION_HANDLE hSession,
		 CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		 CK_ULONG_PTR pulSignerCertificatesCount))
STUB_FUNCTION(C_EX_Authenticate, 31,
		(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hAuthObject,
		 CK_BYTE_PTR pData, CK_ULONG ulDataSize))
STUB_FUNCTION(C_EX_Deauthenticate, 32,
		(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hAuthObject))
STUB_FUNCTION(C_EX_UnblockAuthenticator, 33,
		(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hAuthObject))

#undef STUB_FUNCTION

static CK_FUNCTION_LIST standard_functions = {
	.version = { 2, 40 },
	.C_Initialize = C_Initialize,
	.C_Finalize = C_Finalize,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = C_GetSlotList,
	.C_GetSlotInfo = C_GetSlotInfo,
	.C_OpenSession = C_OpenSession,
	.C_CloseSession = C_CloseSession
};

static CK_FUNCTION_LIST_EXTENDED extended_functions = {
	.version = { 2, 40 },
	.C_EX_GetFunctionListExtended = C_EX_GetFunctionListExtended,
	.C_EX_InitToken = C_EX_InitToken,
	.C_EX_GetTokenInfoExtended = C_EX_GetTokenInfoExtended,
	.C_EX_UnblockUserPIN = C_EX_UnblockUserPIN,
	.C_EX_SetTokenName = C_EX_SetTokenName,
	.C_EX_SetLicense = C_EX_SetLicense,
	.C_EX_GetLicense = C_EX_GetLicense,
	.C_EX_GetCertificateInfoText = C_EX_GetCertificateInfoText,
	.C_EX_PKCS7Sign = C_EX_PKCS7Sign,
	.C_EX_CreateCSR = C_EX_CreateCSR,
	.C_EX_FreeBuffer = C_EX_FreeBuffer,
	.C_EX_GetTokenName = C_EX_GetTokenName,
	.C_EX_SetLocalPIN = C_EX_SetLocalPIN,
	.C_EX_LoadActivationKey = C_EX_LoadActivationKey,
	.C_EX_SetActivationPassword = C_EX_SetActivationPassword,
	.C_EX_GetVolumesInfo = C_EX_GetVolumesInfo,
	.C_EX_GetDriveSize = C_EX_GetDriveSize,
	.C_EX_ChangeVolumeAttributes = C_EX_ChangeVolumeAttributes,
	.C_EX_FormatDrive = C_EX_FormatDrive,
	.C_EX_TokenManage = C_EX_TokenManage,
	.C_EX_GenerateActivationPassword = C_EX_GenerateActivationPassword,
	.C_EX_GetJournal = C_EX_GetJournal,
	.C_EX_SignInvisibleInit = C_EX_SignInvisibleInit,
	.C_EX_SignInvisible = C_EX_SignInvisible,
	.C_EX_SlotManage = C_EX_SlotManage,
	.C_EX_WrapKey = C_EX_WrapKey,
	.C_EX_UnwrapKey = C_EX_UnwrapKey,
	.C_EX_PKCS7VerifyInit = C_EX_PKCS7VerifyInit,
	.C_EX_PKCS7Verify = C_EX_PKCS7Verify,
	.C_EX_PKCS7VerifyUpdate = C_EX_PKCS7VerifyUpdate,
	.C_EX_PKCS7VerifyFinal = C_EX_PKCS7VerifyFinal,
	.C_EX_Authenticate = C_EX_Authenticate,
	.C_EX_Deauthenticate = C_EX_Deauthenticate,
	.C_EX_UnblockAuthenticator = C_EX_UnblockAuthenticator
};
