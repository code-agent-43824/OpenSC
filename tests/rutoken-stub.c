#define CRYPTOKI_EXPORTS
#include "pkcs11/pkcs11-rutoken.h"

#include <stdlib.h>
#include <string.h>

static CK_FUNCTION_LIST standard_functions;
static CK_FUNCTION_LIST_EXTENDED extended_functions;

/* Slot 7 holds the token; read-only sessions get handle 23, read-write
 * sessions 24. A slot or session handle of ORDER_PROBE makes every extension
 * function return only its CKR_VENDOR_DEFINED + number, so that
 * rutoken-driver.c can check the order of the function table through
 * pkcs11-spy. */
#define SESSION_RO 23
#define SESSION_RW 24
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
	{ 202, CKO_PUBLIC_KEY, "\x01\x02", "Test key", NULL },
};
#define OBJECT_COUNT (sizeof(objects) / sizeof(objects[0]))

/* Objects created through C_GenerateKeyPair and C_CreateObject keep copies
 * of their templates. */
#define DYNAMIC_OBJECTS 8
#define DYNAMIC_ATTRIBUTES 16

struct dynamic_object {
	CK_OBJECT_HANDLE handle;	/* 0 for an unused entry */
	CK_ULONG count;
	CK_ATTRIBUTE attributes[DYNAMIC_ATTRIBUTES];
};

static struct dynamic_object dynamic_objects[DYNAMIC_OBJECTS];
static CK_OBJECT_HANDLE next_dynamic_handle = 1001;

static CK_ATTRIBUTE search_template[4];
static CK_ULONG search_count;
static CK_ULONG search_position;
static int search_active;
static int logged_in;
static int sign_active;
static int verify_active;
static CK_MECHANISM_TYPE sign_mechanism;

static int
session_valid(CK_SESSION_HANDLE hSession)
{
	return hSession == SESSION_RO || hSession == SESSION_RW;
}

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

static void
pad_string(CK_UTF8CHAR *field, size_t size, const char *text)
{
	memset(field, ' ', size);
	memcpy(field, text, strlen(text) < size ? strlen(text) : size);
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	memset(pInfo, 0, sizeof(*pInfo));
	pad_string(pInfo->label, sizeof(pInfo->label), "Test Rutoken");
	pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
			"OpenSC test");
	pad_string(pInfo->model, sizeof(pInfo->model), "Rutoken stub");
	pad_string(pInfo->serialNumber, sizeof(pInfo->serialNumber), "12345678");
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED |
		CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulMaxPinLen = 32;
	pInfo->ulMinPinLen = 6;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	return CKR_OK;
}

CK_RV
C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	(void)pApplication;
	(void)notify;
	if (slotID != 7)
		return CKR_SLOT_ID_INVALID;
	if (!phSession)
		return CKR_ARGUMENTS_BAD;
	*phSession = (flags & CKF_RW_SESSION) ? SESSION_RW : SESSION_RO;
	return CKR_OK;
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
	return session_valid(hSession) ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;
	if (!pPin || !ulPinLen)
		return CKR_PIN_INCORRECT;
	if (logged_in)
		return CKR_USER_ALREADY_LOGGED_IN;
	logged_in = 1;
	return CKR_OK;
}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	logged_in = 0;
	return CKR_OK;
}

static void
release_dynamic(struct dynamic_object *object)
{
	CK_ULONG i;

	for (i = 0; i < object->count; i++)
		free(object->attributes[i].pValue);
	memset(object, 0, sizeof(*object));
}

static CK_RV
store_dynamic(const CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
		const CK_ATTRIBUTE *extra, CK_OBJECT_HANDLE_PTR phObject)
{
	struct dynamic_object *object = NULL;
	const CK_ATTRIBUTE *source;
	CK_ULONG i, total = ulCount + (extra ? 1 : 0);
	size_t j;

	if ((!pTemplate && ulCount) || !phObject)
		return CKR_ARGUMENTS_BAD;
	if (total > DYNAMIC_ATTRIBUTES)
		return CKR_TEMPLATE_INCONSISTENT;
	for (j = 0; j < DYNAMIC_OBJECTS && !object; j++)
		if (!dynamic_objects[j].handle)
			object = &dynamic_objects[j];
	if (!object)
		return CKR_DEVICE_MEMORY;
	for (i = 0; i < total; i++) {
		source = i < ulCount ? &pTemplate[i] : extra;
		object->attributes[i].type = source->type;
		object->attributes[i].ulValueLen = source->ulValueLen;
		object->attributes[i].pValue =
				malloc(source->ulValueLen ? source->ulValueLen : 1);
		object->count = i + 1;
		if (!object->attributes[i].pValue) {
			release_dynamic(object);
			return CKR_HOST_MEMORY;
		}
		if (source->ulValueLen)
			memcpy(object->attributes[i].pValue, source->pValue,
					source->ulValueLen);
	}
	object->handle = next_dynamic_handle++;
	*phObject = object->handle;
	return CKR_OK;
}

static struct dynamic_object *
find_dynamic(CK_OBJECT_HANDLE handle)
{
	size_t i;

	for (i = 0; handle && i < DYNAMIC_OBJECTS; i++)
		if (dynamic_objects[i].handle == handle)
			return &dynamic_objects[i];
	return NULL;
}

static const CK_ATTRIBUTE *
dynamic_attribute(const struct dynamic_object *object, CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; i < object->count; i++)
		if (object->attributes[i].type == type)
			return &object->attributes[i];
	return NULL;
}

static int
dynamic_class(const struct dynamic_object *object, CK_OBJECT_CLASS object_class)
{
	const CK_ATTRIBUTE *attribute = dynamic_attribute(object, CKA_CLASS);

	return attribute && attribute->ulValueLen == sizeof(object_class) &&
			!memcmp(attribute->pValue, &object_class, sizeof(object_class));
}

static int
dynamic_matches(const struct dynamic_object *object)
{
	const CK_ATTRIBUTE *stored;
	CK_ULONG i;

	for (i = 0; i < search_count; i++) {
		stored = dynamic_attribute(object, search_template[i].type);
		if (!stored || stored->ulValueLen != search_template[i].ulValueLen ||
				(stored->ulValueLen && memcmp(stored->pValue,
					search_template[i].pValue, stored->ulValueLen)))
			return 0;
	}
	return 1;
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
	if (!session_valid(hSession))
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

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!search_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!phObject || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;
	while (found < ulMaxObjectCount &&
			search_position < OBJECT_COUNT + DYNAMIC_OBJECTS) {
		if (search_position < OBJECT_COUNT) {
			if (object_matches(&objects[search_position]))
				phObject[found++] = objects[search_position].handle;
		} else {
			const struct dynamic_object *object =
					&dynamic_objects[search_position - OBJECT_COUNT];

			if (object->handle && dynamic_matches(object))
				phObject[found++] = object->handle;
		}
		search_position++;
	}
	*pulObjectCount = found;
	return CKR_OK;
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!session_valid(hSession))
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

static int
static_attribute(const struct test_object *object, CK_ATTRIBUTE_TYPE type,
		const void **value, CK_ULONG *length)
{
	switch (type) {
	case CKA_CLASS:
		*value = &object->object_class;
		*length = sizeof(object->object_class);
		return 1;
	case CKA_ID:
		*value = object->id;
		*length = 2;
		return 1;
	case CKA_LABEL:
		*value = object->label;
		*length = (CK_ULONG)strlen(object->label);
		return 1;
	default:
		return 0;
	}
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	const struct test_object *object = find_object(hObject);
	const struct dynamic_object *created = find_dynamic(hObject);
	const CK_ATTRIBUTE *stored;
	CK_RV rv = CKR_OK;
	const void *value;
	CK_ULONG i, length;
	int known;

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!object && !created)
		return CKR_OBJECT_HANDLE_INVALID;
	if (!pTemplate && ulCount)
		return CKR_ARGUMENTS_BAD;
	for (i = 0; i < ulCount; i++) {
		if (object) {
			known = static_attribute(object, pTemplate[i].type, &value,
					&length);
		} else {
			stored = dynamic_attribute(created, pTemplate[i].type);
			known = stored != NULL;
			if (known) {
				value = stored->pValue;
				length = stored->ulValueLen;
			}
		}
		if (!known) {
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

/* The signature depends only on the data length, so that C_Verify can
 * check it without keys. */
static void
test_signature(CK_ULONG data_length, CK_BYTE *signature)
{
	CK_ULONG i;

	for (i = 0; i < 64; i++)
		signature[i] = (CK_BYTE)(0xC0 ^ i ^ (data_length & 0xFF));
}

CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_BYTE value[64];
	CK_ATTRIBUTE public_value = { CKA_VALUE, value, sizeof(value) };
	struct dynamic_object *public_key;
	CK_ULONG i;
	CK_RV rv;

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (hSession != SESSION_RW)
		return CKR_SESSION_READ_ONLY;
	if (!logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (!pMechanism || pMechanism->mechanism != CKM_GOSTR3410_KEY_PAIR_GEN)
		return CKR_MECHANISM_INVALID;
	if (!phPublicKey || !phPrivateKey)
		return CKR_ARGUMENTS_BAD;
	for (i = 0; i < sizeof(value); i++)
		value[i] = (CK_BYTE)(0x10 + i);
	rv = store_dynamic(pPublicKeyTemplate, ulPublicKeyAttributeCount,
			&public_value, phPublicKey);
	if (rv != CKR_OK)
		return rv;
	rv = store_dynamic(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, NULL,
			phPrivateKey);
	if (rv != CKR_OK && (public_key = find_dynamic(*phPublicKey)) != NULL)
		release_dynamic(public_key);
	return rv;
}

CK_RV
C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
	const struct dynamic_object *key = find_dynamic(hKey);

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (!key || !dynamic_class(key, CKO_PRIVATE_KEY))
		return CKR_KEY_HANDLE_INVALID;
	if (!pMechanism || (pMechanism->mechanism != CKM_GOSTR3410 &&
			pMechanism->mechanism != CKM_GOSTR3410_WITH_GOSTR3411_12_256))
		return CKR_MECHANISM_INVALID;
	sign_mechanism = pMechanism->mechanism;
	sign_active = 1;
	return CKR_OK;
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!sign_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if ((!pData && ulDataLen) || !pulSignatureLen)
		return CKR_ARGUMENTS_BAD;
	if (sign_mechanism == CKM_GOSTR3410 && ulDataLen != 32) {
		sign_active = 0;
		return CKR_DATA_LEN_RANGE;
	}
	if (!pSignature) {
		*pulSignatureLen = 64;
		return CKR_OK;
	}
	if (*pulSignatureLen < 64) {
		*pulSignatureLen = 64;
		return CKR_BUFFER_TOO_SMALL;
	}
	test_signature(ulDataLen, pSignature);
	*pulSignatureLen = 64;
	sign_active = 0;
	return CKR_OK;
}

CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
	const struct dynamic_object *key = find_dynamic(hKey);

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!key || !dynamic_class(key, CKO_PUBLIC_KEY))
		return CKR_KEY_HANDLE_INVALID;
	if (!pMechanism || pMechanism->mechanism != CKM_GOSTR3410)
		return CKR_MECHANISM_INVALID;
	verify_active = 1;
	return CKR_OK;
}

CK_RV
C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE expected[64];

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!verify_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	verify_active = 0;
	if ((!pData && ulDataLen) || !pSignature)
		return CKR_ARGUMENTS_BAD;
	if (ulSignatureLen != sizeof(expected))
		return CKR_SIGNATURE_LEN_RANGE;
	test_signature(ulDataLen, expected);
	return memcmp(expected, pSignature, sizeof(expected)) ?
			CKR_SIGNATURE_INVALID : CKR_OK;
}

CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (hSession != SESSION_RW)
		return CKR_SESSION_READ_ONLY;
	return store_dynamic(pTemplate, ulCount, NULL, phObject);
}

CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	struct dynamic_object *object = find_dynamic(hObject);

	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (hSession != SESSION_RW)
		return CKR_SESSION_READ_ONLY;
	if (find_object(hObject))
		return CKR_ACTION_PROHIBITED;
	if (!object)
		return CKR_OBJECT_HANDLE_INVALID;
	release_dynamic(object);
	return CKR_OK;
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
	/* a Rutoken Touch for the --rutoken-confirm-by-touch tests */
	if (getenv("RUTOKEN_STUB_HAS_BUTTON"))
		pInfo->flags |= TOKEN_FLAGS_HAS_BUTTON;
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

	if (!session_valid(hSession))
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
	if (!session_valid(hSession))
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
	if (!session_valid(hSession))
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

/* A static or created object of this class. */
static int
object_is(CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS object_class)
{
	const struct test_object *object = find_object(handle);
	const struct dynamic_object *created = find_dynamic(handle);

	if (object)
		return object->object_class == object_class;
	return created && dynamic_class(created, object_class);
}

static const CK_BYTE *
object_id(CK_OBJECT_HANDLE handle, CK_ULONG *length)
{
	const struct test_object *object = find_object(handle);
	const struct dynamic_object *created = find_dynamic(handle);
	const CK_ATTRIBUTE *id;

	if (object) {
		*length = 2;
		return (const CK_BYTE *)object->id;
	}
	if (!created || !(id = dynamic_attribute(created, CKA_ID)))
		return NULL;
	*length = id->ulValueLen;
	return id->pValue;
}

/* A private key shares the CKA_ID of the certificate. */
static int
have_key_for(CK_OBJECT_HANDLE certificate)
{
	const CK_BYTE *id, *key_id;
	CK_ULONG length, key_length;
	size_t i;

	if (!(id = object_id(certificate, &length)))
		return 0;
	for (i = 0; i < OBJECT_COUNT; i++)
		if (objects[i].object_class == CKO_PRIVATE_KEY && length == 2 &&
				!memcmp(objects[i].id, id, 2))
			return 1;
	for (i = 0; i < DYNAMIC_OBJECTS; i++) {
		if (!dynamic_objects[i].handle ||
				!dynamic_class(&dynamic_objects[i], CKO_PRIVATE_KEY))
			continue;
		key_id = object_id(dynamic_objects[i].handle, &key_length);
		if (key_id && key_length == length && !memcmp(key_id, id, length))
			return 1;
	}
	return 0;
}

/* The stub "CMS": magic, detached flag, data length and FNV-1a hash of the
 * data (both BE32), then the data of an attached signature. */
static const CK_BYTE cms_magic[] = { 'S', 'T', 'U', 'B', '-', 'P', '7' };
#define CMS_HEADER (sizeof(cms_magic) + 9)
#define FNV_OFFSET 2166136261UL

static CK_ULONG
fnv1a(CK_ULONG hash, const CK_BYTE *data, CK_ULONG length)
{
	CK_ULONG i;

	for (i = 0; i < length; i++)
		hash = ((hash ^ data[i]) * 16777619UL) & 0xFFFFFFFFUL;
	return hash;
}

static void
put_be32(CK_BYTE *p, CK_ULONG value)
{
	p[0] = (CK_BYTE)(value >> 24);
	p[1] = (CK_BYTE)(value >> 16);
	p[2] = (CK_BYTE)(value >> 8);
	p[3] = (CK_BYTE)value;
}

static CK_ULONG
get_be32(const CK_BYTE *p)
{
	return ((CK_ULONG)p[0] << 24) | ((CK_ULONG)p[1] << 16) |
			((CK_ULONG)p[2] << 8) | p[3];
}

CK_RV CK_SPEC
C_EX_PKCS7Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataLen, CK_OBJECT_HANDLE hCert, CK_BYTE_PTR *ppEnvelope,
		CK_ULONG_PTR pEnvelopeLen, CK_OBJECT_HANDLE hPrivKey,
		CK_OBJECT_HANDLE_PTR phCertificates, CK_ULONG ulCertificatesLen,
		CK_ULONG flags)
{
	CK_ULONG i, length;
	CK_BYTE_PTR envelope;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(8);
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (!pData || !ulDataLen || !ppEnvelope || !pEnvelopeLen ||
			(!phCertificates && ulCertificatesLen) ||
			(flags & ~(PKCS7_DETACHED_SIGNATURE | USE_HARDWARE_HASH)))
		return CKR_ARGUMENTS_BAD;
	if (!object_is(hCert, CKO_CERTIFICATE))
		return CKR_OBJECT_HANDLE_INVALID;
	if (hPrivKey != CK_INVALID_HANDLE ?
			!object_is(hPrivKey, CKO_PRIVATE_KEY) : !have_key_for(hCert))
		return CKR_KEY_HANDLE_INVALID;
	for (i = 0; i < ulCertificatesLen; i++)
		if (!object_is(phCertificates[i], CKO_CERTIFICATE))
			return CKR_OBJECT_HANDLE_INVALID;
	length = CMS_HEADER + (flags & PKCS7_DETACHED_SIGNATURE ? 0 : ulDataLen);
	envelope = malloc(length);
	if (!envelope)
		return CKR_HOST_MEMORY;
	memcpy(envelope, cms_magic, sizeof(cms_magic));
	envelope[sizeof(cms_magic)] = (CK_BYTE)(flags & PKCS7_DETACHED_SIGNATURE);
	put_be32(envelope + sizeof(cms_magic) + 1, ulDataLen);
	put_be32(envelope + sizeof(cms_magic) + 5,
			fnv1a(FNV_OFFSET, pData, ulDataLen));
	if (!(flags & PKCS7_DETACHED_SIGNATURE))
		memcpy(envelope + CMS_HEADER, pData, ulDataLen);
	allocated_buffers++;
	*ppEnvelope = envelope;
	*pEnvelopeLen = length;
	return CKR_OK;
}

/* The C_EX_PKCS7Verify* operation of the session. */
static struct {
	int active;
	int detached;
	CK_RV status;		/* CKR_OK or CKR_CERT_CHAIN_NOT_VERIFIED */
	CK_ULONG length;	/* length and hash of the signed data */
	CK_ULONG hash;
	CK_ULONG received;	/* detached: data of C_EX_PKCS7VerifyUpdate */
	CK_ULONG running;
	CK_BYTE_PTR data;	/* attached: copy of the signed data */
} cms_verify;

static void
cms_verify_reset(void)
{
	free(cms_verify.data);
	memset(&cms_verify, 0, sizeof(cms_verify));
}

static const CK_BYTE signer_certificate[] = "stub signer certificate";

static CK_RV
cms_signers(CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		CK_ULONG_PTR pulSignerCertificatesCount)
{
	CK_VENDOR_BUFFER_PTR signers = malloc(sizeof(*signers));

	if (!signers)
		return CKR_HOST_MEMORY;
	signers->pData = malloc(sizeof(signer_certificate));
	if (!signers->pData) {
		free(signers);
		return CKR_HOST_MEMORY;
	}
	memcpy(signers->pData, signer_certificate, sizeof(signer_certificate));
	signers->ulSize = sizeof(signer_certificate);
	allocated_buffers += 2;
	*ppSignerCertificates = signers;
	*pulSignerCertificatesCount = 1;
	return CKR_OK;
}

CK_RV CK_SPEC
C_EX_PKCS7VerifyInit(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pCms,
		CK_ULONG ulCmsSize, CK_VENDOR_X509_STORE_PTR pStore,
		CK_VENDOR_CRL_MODE ckMode, CK_FLAGS flags)
{
	CK_ULONG length;
	int detached;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(27);
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (cms_verify.active)
		return CKR_OPERATION_ACTIVE;
	if (!pCms || ulCmsSize < CMS_HEADER || !pStore || ckMode > ALL_CRL_CHECK)
		return CKR_ARGUMENTS_BAD;
	detached = pCms[sizeof(cms_magic)];
	length = get_be32(pCms + sizeof(cms_magic) + 1);
	if (memcmp(pCms, cms_magic, sizeof(cms_magic)) || detached > 1 ||
			ulCmsSize - CMS_HEADER != (detached ? 0 : length))
		return CKR_DATA_INVALID;
	if (!detached) {
		cms_verify.data = malloc(length ? length : 1);
		if (!cms_verify.data)
			return CKR_HOST_MEMORY;
		memcpy(cms_verify.data, pCms + CMS_HEADER, length);
	}
	cms_verify.active = 1;
	cms_verify.detached = detached;
	cms_verify.length = length;
	cms_verify.hash = get_be32(pCms + sizeof(cms_magic) + 5);
	cms_verify.running = FNV_OFFSET;
	/* the signer is trusted only through a certificate of the store */
	cms_verify.status = ((flags & CKF_VENDOR_CHECK_SIGNATURE_ONLY) ||
			pStore->ulTrustedCertificateCount) ?
			CKR_OK : CKR_CERT_CHAIN_NOT_VERIFIED;
	return CKR_OK;
}

CK_RV CK_SPEC
C_EX_PKCS7Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR_PTR ppData,
		CK_ULONG_PTR pulDataSize, CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		CK_ULONG_PTR pulSignerCertificatesCount)
{
	CK_RV rv, status = cms_verify.status;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(28);
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!cms_verify.active)
		return CKR_OPERATION_NOT_INITIALIZED;
	/* a detached signature needs C_EX_PKCS7VerifyUpdate and Final */
	if (cms_verify.detached)
		return CKR_OPERATION_ACTIVE;
	if (!ppData || !pulDataSize || !ppSignerCertificates ||
			!pulSignerCertificatesCount)
		rv = CKR_ARGUMENTS_BAD;
	else if (fnv1a(FNV_OFFSET, cms_verify.data, cms_verify.length) !=
			cms_verify.hash)
		rv = CKR_SIGNATURE_INVALID;
	else
		rv = cms_signers(ppSignerCertificates, pulSignerCertificatesCount);
	if (rv == CKR_OK) {
		*ppData = cms_verify.data;
		*pulDataSize = cms_verify.length;
		cms_verify.data = NULL;
		allocated_buffers++;
	}
	cms_verify_reset();
	return rv == CKR_OK ? status : rv;
}

CK_RV CK_SPEC
C_EX_PKCS7VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataSize)
{
	if (hSession == ORDER_PROBE)
		return ORDER_CODE(29);
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!cms_verify.active || !cms_verify.detached)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!pData && ulDataSize) {
		cms_verify_reset();
		return CKR_ARGUMENTS_BAD;
	}
	cms_verify.running = fnv1a(cms_verify.running, pData, ulDataSize);
	cms_verify.received += ulDataSize;
	return CKR_OK;
}

CK_RV CK_SPEC
C_EX_PKCS7VerifyFinal(CK_SESSION_HANDLE hSession,
		CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		CK_ULONG_PTR pulSignerCertificatesCount)
{
	CK_RV rv, status = cms_verify.status;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(30);
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!cms_verify.active || !cms_verify.detached)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!ppSignerCertificates || !pulSignerCertificatesCount)
		rv = CKR_ARGUMENTS_BAD;
	else if (cms_verify.received != cms_verify.length ||
			cms_verify.running != cms_verify.hash)
		rv = CKR_SIGNATURE_INVALID;
	else
		rv = cms_signers(ppSignerCertificates, pulSignerCertificatesCount);
	cms_verify_reset();
	return rv == CKR_OK ? status : rv;
}

/* The stub "CSR" is the text "stub CSR:" followed by " type=value" pairs of
 * the distinguished name. */
CK_RV CK_SPEC
C_EX_CreateCSR(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey,
		CK_CHAR_PTR *dn, CK_ULONG dnLength, CK_BYTE_PTR *pCsr,
		CK_ULONG_PTR pulCsrLength, CK_OBJECT_HANDLE hPrivKey,
		CK_CHAR_PTR *pAttributes, CK_ULONG ulAttributesLength,
		CK_CHAR_PTR *pExtensions, CK_ULONG ulExtensionsLength)
{
	static const char prefix[] = "stub CSR:";
	size_t length = sizeof(prefix) - 1, part;
	CK_BYTE_PTR csr;
	CK_ULONG i;

	if (hSession == ORDER_PROBE)
		return ORDER_CODE(9);
	if (!session_valid(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (!dn || !dnLength || dnLength % 2 || !pCsr || !pulCsrLength ||
			(!pAttributes && ulAttributesLength) || ulAttributesLength % 2 ||
			(!pExtensions && ulExtensionsLength) || ulExtensionsLength % 2)
		return CKR_ARGUMENTS_BAD;
	if (!object_is(hPublicKey, CKO_PUBLIC_KEY) ||
			(hPrivKey != CK_INVALID_HANDLE &&
			 !object_is(hPrivKey, CKO_PRIVATE_KEY)))
		return CKR_KEY_HANDLE_INVALID;
	for (i = 0; i < dnLength; i++) {
		if (!dn[i])
			return CKR_ARGUMENTS_BAD;
		length += strlen((const char *)dn[i]) + 1;
	}
	csr = malloc(length);
	if (!csr)
		return CKR_HOST_MEMORY;
	memcpy(csr, prefix, sizeof(prefix) - 1);
	length = sizeof(prefix) - 1;
	for (i = 0; i < dnLength; i++) {
		part = strlen((const char *)dn[i]);
		csr[length++] = i % 2 ? '=' : ' ';
		memcpy(csr + length, dn[i], part);
		length += part;
	}
	allocated_buffers++;
	*pCsr = csr;
	*pulCsrLength = (CK_ULONG)length;
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

/* One record in the format of the Rutoken SDK sample JournalParse.c inside
 * TLV 0x80, in the tag order of the device: hash, signature, operation
 * information (signature with the GOST private key RSF 0x0005 that allows
 * key exchange, hash computed by the token, 298 signatures) and device ID. */
static const CK_BYTE journal[] = {
	0x80, 0x7C,
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
	0x85, 0x0C, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x01, 0x2A,
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
		/* the library answers other user types so */
		return CKR_ARGUMENTS_BAD;
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
		/* local PINs are 3..31; the library reports a missing one as a
		 * device error (the token answers SELECT with 6A 82) */
		return pin->ulPinID >= 3 && pin->ulPinID <= 31 ?
				CKR_DEVICE_ERROR : CKR_ARGUMENTS_BAD;
	default:
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
}

CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
	int left = 0;
	size_t i;

	(void)pReserved;
	for (i = 0; i < DYNAMIC_OBJECTS; i++) {
		if (dynamic_objects[i].handle) {
			left = 1;
			release_dynamic(&dynamic_objects[i]);
		}
	}
	logged_in = 0;
	cms_verify_reset();
	/* a buffer returned by an extension function was not released or a
	 * created object was not destroyed */
	return allocated_buffers || left ? CKR_GENERAL_ERROR : CKR_OK;
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
	.C_GetTokenInfo = C_GetTokenInfo,
	.C_OpenSession = C_OpenSession,
	.C_CloseSession = C_CloseSession,
	.C_Login = C_Login,
	.C_Logout = C_Logout,
	.C_CreateObject = C_CreateObject,
	.C_DestroyObject = C_DestroyObject,
	.C_GetAttributeValue = C_GetAttributeValue,
	.C_FindObjectsInit = C_FindObjectsInit,
	.C_FindObjects = C_FindObjects,
	.C_FindObjectsFinal = C_FindObjectsFinal,
	.C_SignInit = C_SignInit,
	.C_Sign = C_Sign,
	.C_VerifyInit = C_VerifyInit,
	.C_Verify = C_Verify,
	.C_GenerateKeyPair = C_GenerateKeyPair
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
