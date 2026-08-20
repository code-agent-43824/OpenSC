#define CRYPTOKI_EXPORTS
#include "pkcs11/pkcs11-rutoken.h"

#include <string.h>

static CK_FUNCTION_LIST standard_functions;
static CK_FUNCTION_LIST_EXTENDED extended_functions;

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
	.C_EX_GetTokenInfoExtended = C_EX_GetTokenInfoExtended,
	.C_EX_GetTokenName = C_EX_GetTokenName
};
