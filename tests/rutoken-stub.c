#define CRYPTOKI_EXPORTS
#include "pkcs11/pkcs11-rutoken.h"

#include <stdlib.h>
#include <string.h>

static CK_FUNCTION_LIST standard_functions;
static CK_FUNCTION_LIST_EXTENDED extended_functions;

/* Slot 7 holds the token, session 23 is the only session. A slot or session
 * handle of ORDER_PROBE makes every extension function return only its
 * CKR_VENDOR_DEFINED + number, so that rutoken-driver.c can check the order
 * of the function table through pkcs11-spy. */
#define ORDER_PROBE 99
#define ORDER_CODE(number) (CKR_VENDOR_DEFINED + (number))

struct test_object {
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS object_class;
	const char *id;
	const char *label;
	const char *text;
};

static const struct test_object objects[] = {
	{ 101, CKO_CERTIFICATE, "\x01\x02", "Test certificate 1",
		"Subject: CN=Test certificate 1\nIssuer: CN=Test CA\n" },
	{ 102, CKO_CERTIFICATE, "\x03\x04", "Test certificate 2",
		"Subject: CN=\"Test\" 2\nIssuer: CN=Test CA\n" },
	/* a label in CP1251 and a text in UTF-8 */
	{ 103, CKO_CERTIFICATE, "\x05\x06", "\xd2\xe5\xf1\xf2",
		"Subject: CN=\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82\tTab\n" },
	{ 201, CKO_PRIVATE_KEY, "\x01\x02", "Test key", NULL },
};
#define OBJECT_COUNT (sizeof(objects) / sizeof(objects[0]))

static CK_ATTRIBUTE search_template[4];
static CK_ULONG search_count;
static CK_ULONG search_position;
static int search_active;

#define STUB_FUNCTION(name, number, parameters) \
CK_RV CK_SPEC name parameters \
{ \
	return CKR_VENDOR_DEFINED + (number); \
}

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
	(void)pInitArgs;
	return CKR_OK;
}

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &standard_functions;
	return CKR_OK;
}

CK_RV
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

CK_RV
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

CK_RV
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

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
	return hSession == 23 ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

static int
object_matches(const struct test_object *object)
{
	const CK_ATTRIBUTE *attribute;
	CK_ULONG i;

	for (i = 0; i < search_count; i++) {
		attribute = &search_template[i];
		switch (attribute->type) {
		case CKA_CLASS:
			if (attribute->ulValueLen != sizeof(CK_OBJECT_CLASS) ||
					memcmp(attribute->pValue, &object->object_class,
						sizeof(CK_OBJECT_CLASS)))
				return 0;
			break;
		case CKA_ID:
			if (attribute->ulValueLen != 2 ||
					memcmp(attribute->pValue, object->id, 2))
				return 0;
			break;
		case CKA_LABEL:
			if (attribute->ulValueLen != strlen(object->label) ||
					memcmp(attribute->pValue, object->label,
						attribute->ulValueLen))
				return 0;
			break;
		default:
			return 0;
		}
	}
	return 1;
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount)
{
	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (search_active)
		return CKR_OPERATION_ACTIVE;
	if ((!pTemplate && ulCount) ||
			ulCount > sizeof(search_template) / sizeof(search_template[0]))
		return CKR_ARGUMENTS_BAD;
	if (ulCount)
		memcpy(search_template, pTemplate, ulCount * sizeof(*pTemplate));
	search_count = ulCount;
	search_position = 0;
	search_active = 1;
	return CKR_OK;
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	CK_ULONG found = 0;

	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (!search_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!phObject || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;
	while (found < ulMaxObjectCount && search_position < OBJECT_COUNT) {
		if (object_matches(&objects[search_position]))
			phObject[found++] = objects[search_position].handle;
		search_position++;
	}
	*pulObjectCount = found;
	return CKR_OK;
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (!search_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	search_active = 0;
	return CKR_OK;
}

static const struct test_object *
find_object(CK_OBJECT_HANDLE handle)
{
	size_t i;

	for (i = 0; i < OBJECT_COUNT; i++)
		if (objects[i].handle == handle)
			return &objects[i];
	return NULL;
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	const struct test_object *object = find_object(hObject);
	CK_RV rv = CKR_OK;
	const void *value;
	CK_ULONG i, length;

	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (!object)
		return CKR_OBJECT_HANDLE_INVALID;
	if (!pTemplate && ulCount)
		return CKR_ARGUMENTS_BAD;
	for (i = 0; i < ulCount; i++) {
		switch (pTemplate[i].type) {
		case CKA_CLASS:
			value = &object->object_class;
			length = sizeof(object->object_class);
			break;
		case CKA_ID:
			value = object->id;
			length = 2;
			break;
		case CKA_LABEL:
			value = object->label;
			length = strlen(object->label);
			break;
		default:
			pTemplate[i].ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			continue;
		}
		if (!pTemplate[i].pValue) {
			pTemplate[i].ulValueLen = length;
		} else if (pTemplate[i].ulValueLen < length) {
			pTemplate[i].ulValueLen = (CK_ULONG)-1;
			rv = CKR_BUFFER_TOO_SMALL;
		} else {
			memcpy(pTemplate[i].pValue, value, length);
			pTemplate[i].ulValueLen = length;
		}
	}
	return rv;
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
	/* the remaining values were reported by a Rutoken ECP 3.0 Flash */
	pInfo->flags = TOKEN_FLAGS_USER_CHANGE_USER_PIN |
		TOKEN_FLAGS_HAS_FLASH_DRIVE | TOKEN_FLAGS_SUPPORT_JOURNAL |
		TOKEN_FLAGS_USER_PIN_UTF8 | TOKEN_FLAGS_ADMIN_PIN_UTF8;
	memcpy(pInfo->ATR, "\x3b\x8b\x01Rutoken DS \xc1", 15);
	pInfo->ulATRLen = 15;
	pInfo->ulBatteryVoltage = 0;
	pInfo->ulBatteryPercentage = (CK_ULONG)-1;
	pInfo->ulBatteryFlags = (CK_ULONG)-1;
	pInfo->ulBodyColor = TOKEN_BODY_COLOR_UNKNOWN;
	pInfo->ulFirmwareChecksum = 0xA5674611UL;
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

/* License 1 is empty, license 2 holds the bytes 1..72 and license 4 cannot
 * be read. As in the real library, a size query needs no buffer and a
 * buffer must hold 72 bytes. */
CK_RV CK_SPEC
C_EX_GetLicense(CK_SESSION_HANDLE hSession, CK_ULONG ulLicenseNum,
		CK_BYTE_PTR pLicense, CK_ULONG_PTR pulLicenseLen)
{
	CK_ULONG i;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(6);
	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pulLicenseLen || ulLicenseNum < 1 || ulLicenseNum > 4)
		return CKR_ARGUMENTS_BAD;
	if (ulLicenseNum == 4)
		return CKR_RTPKCS11_DATA_CORRUPTED;
	if (!pLicense) {
		*pulLicenseLen = 72;
		return CKR_OK;
	}
	if (*pulLicenseLen < 72) {
		*pulLicenseLen = 72;
		return CKR_BUFFER_TOO_SMALL;
	}
	for (i = 0; i < 72; i++)
		pLicense[i] = ulLicenseNum == 2 ? (CK_BYTE)(i + 1) : 0;
	*pulLicenseLen = 72;
	return CKR_OK;
}

static int allocated_buffers;

CK_RV CK_SPEC
C_EX_GetCertificateInfoText(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hCert,
		CK_CHAR_PTR *pInfo, CK_ULONG_PTR pulInfoLen)
{
	const struct test_object *object = find_object(hCert);
	size_t length;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(7);
	if (hSession != 23)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pInfo || !pulInfoLen)
		return CKR_ARGUMENTS_BAD;
	if (!object || object->object_class != CKO_CERTIFICATE)
		return CKR_OBJECT_HANDLE_INVALID;
	/* the text is returned with its terminating NUL */
	length = strlen(object->text) + 1;
	*pInfo = malloc(length);
	if (!*pInfo)
		return CKR_HOST_MEMORY;
	memcpy(*pInfo, object->text, length);
	*pulInfoLen = (CK_ULONG)length;
	allocated_buffers++;
	return CKR_OK;
}

/* NULL is the order probe; the real library behavior for it is unknown. */
CK_RV CK_SPEC
C_EX_FreeBuffer(CK_BYTE_PTR pBuffer)
{
	if (!pBuffer)
		return ORDER_CODE(10);
	free(pBuffer);
	allocated_buffers--;
	return CKR_OK;
}

static const CK_VOLUME_INFO_EXTENDED volumes[] = {
	{ 1, 512, ACCESS_MODE_RW, CKU_USER, 0 },
	{ 2, 16, ACCESS_MODE_CD, CKU_SO, 0 },
	{ 3, 256, ACCESS_MODE_HIDDEN, 3, 0 },
};

CK_RV CK_SPEC
C_EX_GetVolumesInfo(CK_SLOT_ID slotID, CK_VOLUME_INFO_EXTENDED_PTR pInfo,
		CK_ULONG_PTR pulInfoCount)
{
	const CK_ULONG count = sizeof(volumes) / sizeof(volumes[0]);

	if (slotID == ORDER_PROBE)
		return ORDER_CODE(15);
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pulInfoCount)
		return CKR_ARGUMENTS_BAD;
	if (!pInfo) {
		*pulInfoCount = count;
		return CKR_OK;
	}
	if (*pulInfoCount < count) {
		*pulInfoCount = count;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(pInfo, volumes, sizeof(volumes));
	*pulInfoCount = count;
	return CKR_OK;
}

CK_RV CK_SPEC
C_EX_GetDriveSize(CK_SLOT_ID slotID, CK_ULONG_PTR pulDriveSize)
{
	if (slotID == ORDER_PROBE)
		return ORDER_CODE(16);
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pulDriveSize)
		return CKR_ARGUMENTS_BAD;
	*pulDriveSize = 1024;
	return CKR_OK;
}

/* One record in the documented format: operation data, hash, signature and
 * device ID inside TLV 0x80. */
static const CK_BYTE journal[] = {
	0x80, 0x7C,
	0x85, 0x0C, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x01, 0x2A,
	0xAA, 0x20,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0xB6, 0x40,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x83, 0x08, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
};

CK_RV CK_SPEC
C_EX_GetJournal(CK_SLOT_ID slotID, CK_BYTE_PTR pJournal,
		CK_ULONG_PTR pulJournalSize)
{
	if (slotID == ORDER_PROBE)
		return ORDER_CODE(21);
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pulJournalSize)
		return CKR_ARGUMENTS_BAD;
	if (!pJournal) {
		*pulJournalSize = sizeof(journal);
		return CKR_OK;
	}
	if (*pulJournalSize < sizeof(journal)) {
		*pulJournalSize = sizeof(journal);
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(pJournal, journal, sizeof(journal));
	*pulJournalSize = sizeof(journal);
	return CKR_OK;
}

/* The User PIN need not be changed, the SO PIN must be; local PINs 3 and 5
 * exist. The real library code for a missing local PIN is unknown. */
CK_RV CK_SPEC
C_EX_SlotManage(CK_SLOT_ID slotID, CK_ULONG ulMode, CK_VOID_PTR pValue)
{
	CK_LOCAL_PIN_INFO *pin = pValue;

	if (slotID == ORDER_PROBE)
		return ORDER_CODE(24);
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pValue)
		return CKR_ARGUMENTS_BAD;
	switch (ulMode) {
	case MODE_GET_PIN_SET_TO_BE_CHANGED:
		if (*(CK_USER_TYPE *)pValue == CKU_USER)
			return CKR_OK;
		if (*(CK_USER_TYPE *)pValue == CKU_SO)
			return CKR_PIN_EXPIRED;
		return CKR_USER_TYPE_INVALID;
	case MODE_GET_LOCAL_PIN_INFO:
		if (pin->ulPinID == 3) {
			pin->ulMinSize = 1;
			pin->ulMaxSize = 249;
			pin->ulMaxRetryCount = 10;
			pin->ulCurrentRetryCount = 10;
			pin->flags = LOCAL_PIN_FLAGS_NOT_DEFAULT;
			return CKR_OK;
		}
		if (pin->ulPinID == 5) {
			pin->ulMinSize = 4;
			pin->ulMaxSize = 32;
			pin->ulMaxRetryCount = 5;
			pin->ulCurrentRetryCount = 3;
			pin->flags = LOCAL_PIN_FLAGS_IS_UTF8;
			return CKR_OK;
		}
		return CKR_ARGUMENTS_BAD;
	default:
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
}

CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
	(void)pReserved;
	/* a buffer from C_EX_GetCertificateInfoText was not released */
	return allocated_buffers ? CKR_GENERAL_ERROR : CKR_OK;
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
STUB_FUNCTION(C_EX_SetLocalPIN, 12,
		(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pUserPin, CK_ULONG ulUserPinLen,
		 CK_UTF8CHAR_PTR pNewLocalPin, CK_ULONG ulNewLocalPinLen,
		 CK_ULONG ulLocalID))
STUB_FUNCTION(C_EX_LoadActivationKey, 13,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR key, CK_ULONG keySize))
STUB_FUNCTION(C_EX_SetActivationPassword, 14,
		(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR password))
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
STUB_FUNCTION(C_EX_SignInvisibleInit, 22,
		(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey))
STUB_FUNCTION(C_EX_SignInvisible, 23,
		(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen))
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
	.C_CloseSession = C_CloseSession,
	.C_GetAttributeValue = C_GetAttributeValue,
	.C_FindObjectsInit = C_FindObjectsInit,
	.C_FindObjects = C_FindObjects,
	.C_FindObjectsFinal = C_FindObjectsFinal
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
