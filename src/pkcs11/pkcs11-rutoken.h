/*
 * Rutoken PKCS #11 extension ABI.
 *
 * This is an independent declaration of the public ABI from rtPKCS11ECP
 * 2.19.0.0.  Versions up to 2.21.3.0 keep the same function table and only
 * add constants.  Applications still use the vendor headers; OpenSC only
 * needs matching types, values and function-table order to proxy and call
 * the extension.
 */

#ifndef OPENSC_PKCS11_RUTOKEN_H
#define OPENSC_PKCS11_RUTOKEN_H

#include "pkcs11.h"

#ifdef _WIN32
#pragma pack(push, rutoken, 1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CK_TOKEN_INFO_EXTENDED {
	CK_ULONG ulSizeofThisStructure;
	CK_ULONG ulTokenType;
	CK_ULONG ulProtocolNumber;
	CK_ULONG ulMicrocodeNumber;
	CK_ULONG ulOrderNumber;
	CK_FLAGS flags;
	CK_ULONG ulMaxAdminPinLen;
	CK_ULONG ulMinAdminPinLen;
	CK_ULONG ulMaxUserPinLen;
	CK_ULONG ulMinUserPinLen;
	CK_ULONG ulMaxAdminRetryCount;
	CK_ULONG ulAdminRetryCountLeft;
	CK_ULONG ulMaxUserRetryCount;
	CK_ULONG ulUserRetryCountLeft;
	CK_BYTE serialNumber[8];
	CK_ULONG ulTotalMemory;
	CK_ULONG ulFreeMemory;
	CK_BYTE ATR[64];
	CK_ULONG ulATRLen;
	CK_ULONG ulTokenClass;
	CK_ULONG ulBatteryVoltage;
	CK_ULONG ulBodyColor;
	CK_ULONG ulFirmwareChecksum;
	CK_ULONG ulBatteryPercentage;
	CK_ULONG ulBatteryFlags;
} CK_TOKEN_INFO_EXTENDED;
typedef CK_TOKEN_INFO_EXTENDED *CK_TOKEN_INFO_EXTENDED_PTR;

/* ulTokenType; the vendor deprecates it but still reports it. */
#define TOKEN_TYPE_UNKNOWN                       0xFFUL
#define TOKEN_TYPE_RUTOKEN_ECP                   0x01UL
#define TOKEN_TYPE_RUTOKEN_LITE                  0x02UL
#define TOKEN_TYPE_RUTOKEN                       0x03UL
#define TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY         0x04UL
#define TOKEN_TYPE_RUTOKEN_MIKRON                0x05UL
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_USB           0x09UL
#define TOKEN_TYPE_RUTOKEN_WEB                   0x23UL
#define TOKEN_TYPE_RUTOKEN_SC_JC                 0x41UL
#define TOKEN_TYPE_RUTOKEN_ECP_SC                TOKEN_TYPE_RUTOKEN_SC_JC
#define TOKEN_TYPE_RUTOKEN_LITE_SC_JC            0x42UL
#define TOKEN_TYPE_RUTOKEN_MIKRON_SC             0x45UL
#define TOKEN_TYPE_RUTOKEN_SCDUAL                0x49UL
#define TOKEN_TYPE_RUTOKEN_MIKRON_SCDUAL         0x4DUL
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_BT            0x69UL
#define TOKEN_TYPE_RUTOKEN_ECP_SD                0x81UL
#define TOKEN_TYPE_RUTOKEN_LITE_SD               0x82UL
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_UART          0xA9UL
#define TOKEN_TYPE_RUTOKEN_ECP_NFC               0xC1UL
#define TOKEN_TYPE_RUTOKEN_SCDUAL_NFC            0xC9UL
#define TOKEN_TYPE_RUTOKEN_MIKRON_SCDUAL_NFC     0xCDUL

/* ulTokenClass */
#define TOKEN_CLASS_S                            0x00UL
#define TOKEN_CLASS_ECP                          0x01UL
#define TOKEN_CLASS_LITE                         0x02UL
#define TOKEN_CLASS_WEB                          0x03UL
#define TOKEN_CLASS_PINPAD                       0x04UL
#define TOKEN_CLASS_ECPDUAL                      0x09UL
#define TOKEN_CLASS_ECP_BT                       TOKEN_CLASS_ECPDUAL
#define TOKEN_CLASS_UNKNOWN                      0xFFFFFFFFUL

/* ulBodyColor */
#define TOKEN_BODY_COLOR_UNKNOWN                 0UL
#define TOKEN_BODY_COLOR_WHITE                   1UL
#define TOKEN_BODY_COLOR_BLACK                   2UL

/* flags of CK_TOKEN_INFO_EXTENDED and ChangeUserPINPolicy of
 * CK_RUTOKEN_INIT_PARAM */
#define TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN        0x00000001UL
#define TOKEN_FLAGS_USER_CHANGE_USER_PIN         0x00000002UL
#define TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT        0x00000004UL
#define TOKEN_FLAGS_USER_PIN_NOT_DEFAULT         0x00000008UL
#define TOKEN_FLAGS_SUPPORT_FKN                  0x00000010UL
#define TOKEN_FLAGS_SUPPORT_FKC                  TOKEN_FLAGS_SUPPORT_FKN
#define TOKEN_FLAGS_SUPPORT_SM                   0x00000040UL
#define TOKEN_FLAGS_HAS_FLASH_DRIVE              0x00000080UL
#define TOKEN_FLAGS_SUPPORT_SECURE_MESSAGING     0x00000100UL
#define TOKEN_FLAGS_CAN_CHANGE_SM_MODE           TOKEN_FLAGS_SUPPORT_SECURE_MESSAGING
#define TOKEN_FLAGS_HAS_BUTTON                   0x00000200UL
#define TOKEN_FLAGS_SUPPORT_JOURNAL              0x00000400UL
#define TOKEN_FLAGS_USER_PIN_UTF8                0x00000800UL
#define TOKEN_FLAGS_ADMIN_PIN_UTF8               0x00001000UL
/* The vendor spells this constant "UNAVAILIBLE". */
#define TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE      0x40000000UL
#define TOKEN_FLAGS_FW_CHECKSUM_INVALID          0x80000000UL

/* Vendor return values */
#define CKR_CORRUPTED_MAPFILE                    (CKR_VENDOR_DEFINED + 1UL)
#define CKR_WRONG_VERSION_FIELD                  (CKR_VENDOR_DEFINED + 2UL)
#define CKR_WRONG_PKCS1_ENCODING                 (CKR_VENDOR_DEFINED + 3UL)
#define CKR_RTPKCS11_DATA_CORRUPTED              (CKR_VENDOR_DEFINED + 4UL)
#define CKR_RTPKCS11_RSF_DATA_CORRUPTED          (CKR_VENDOR_DEFINED + 5UL)
#define CKR_SM_PASSWORD_INVALID                  (CKR_VENDOR_DEFINED + 6UL)
#define CKR_LICENSE_READ_ONLY                    (CKR_VENDOR_DEFINED + 7UL)
#define CKR_VENDOR_EMITENT_KEY_BLOCKED           (CKR_VENDOR_DEFINED + 8UL)
/* Also a successful verification whose certificate chain was not checked. */
#define CKR_CERT_CHAIN_NOT_VERIFIED              (CKR_VENDOR_DEFINED + 9UL)
#define CKR_INAPPROPRIATE_PIN                    (CKR_VENDOR_DEFINED + 10UL)
#define CKR_PIN_IN_HISTORY                       (CKR_VENDOR_DEFINED + 11UL)
#define CKR_VENDOR_INTERFACE_NOT_INITIALIZED     (CKR_VENDOR_DEFINED + 12UL)

/* C_EX_InitToken: full reformat of the token memory. */
typedef struct CK_RUTOKEN_INIT_PARAM {
	CK_ULONG ulSizeofThisStructure;
	CK_ULONG UseRepairMode;
	CK_BYTE_PTR pNewAdminPin;
	CK_ULONG ulNewAdminPinLen;
	CK_BYTE_PTR pNewUserPin;
	CK_ULONG ulNewUserPinLen;
	CK_FLAGS ChangeUserPINPolicy;
	CK_ULONG ulMinAdminPinLen;
	CK_ULONG ulMinUserPinLen;
	CK_ULONG ulMaxAdminRetryCount;
	CK_ULONG ulMaxUserRetryCount;
	CK_BYTE_PTR pTokenLabel;
	CK_ULONG ulLabelLen;
	CK_ULONG ulSmMode;
} CK_RUTOKEN_INIT_PARAM;
typedef CK_RUTOKEN_INIT_PARAM *CK_RUTOKEN_INIT_PARAM_PTR;

/* C_EX_SlotManage modes and their pValue types */
#define MODE_GET_IMIT                            0x04UL
#define MODE_GET_LOCAL_PIN_INFO                  0x05UL
#define MODE_RESTORE_FACTORY_DEFAULTS            0x06UL
#define MODE_GET_PIN_SET_TO_BE_CHANGED           0x07UL

typedef struct CK_TOKEN_IMIT_DATA {
	CK_BYTE bMode;
	CK_BYTE pbGostSymmetricKey[32];
	CK_BYTE pbImit[8];
} CK_TOKEN_IMIT_DATA;
typedef CK_TOKEN_IMIT_DATA *CK_TOKEN_IMIT_DATA_PTR;

#define IMIT_MODE_MASK                           0x01U
#define IMIT_MODE_MASK_PATCH                     0x02U

typedef struct CK_LOCAL_PIN_INFO {
	CK_ULONG ulPinID;
	CK_ULONG ulMinSize;
	CK_ULONG ulMaxSize;
	CK_ULONG ulMaxRetryCount;
	CK_ULONG ulCurrentRetryCount;
	CK_FLAGS flags;
} CK_LOCAL_PIN_INFO;
typedef CK_LOCAL_PIN_INFO *CK_LOCAL_PIN_INFO_PTR;

#define LOCAL_PIN_FLAGS_NOT_DEFAULT              0x00000001UL
#define LOCAL_PIN_FLAGS_FROM_SCREEN              0x00000002UL
#define LOCAL_PIN_FLAGS_IS_UTF8                  0x00000004UL

typedef struct CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS {
	CK_ULONG ulSizeofThisStructure;
	CK_BYTE_PTR pAdminPin;
	CK_ULONG ulAdminPinLen;
	CK_RUTOKEN_INIT_PARAM_PTR pInitParam;
	CK_BYTE_PTR pNewEmitentKey;
	CK_ULONG ulNewEmitentKeyLen;
	CK_ULONG ulNewEmitentKeyRetryCount;
	CK_KEY_TYPE newEmitentKeyType;
} CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS;
typedef CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS
		*CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS_PTR;

/* C_EX_TokenManage modes and their pValue types */
#define MODE_SET_BLUETOOTH_POWEROFF_TIMEOUT      0x01UL
#define MODE_SET_CHANNEL_TYPE                    0x02UL
#define MODE_RESET_CUSTOM_PIN_TO_STANDARD        0x03UL
#define MODE_RESET_PIN_TO_DEFAULT                0x04UL
#define MODE_CHANGE_DEFAULT_PIN                  0x05UL
#define MODE_FORCE_USER_TO_CHANGE_PIN            0x06UL

#define BLUETOOTH_POWEROFF_TIMEOUT_DEFAULT       0x00UL
#define BLUETOOTH_POWEROFF_TIMEOUT_MAX           0x46UL
#define CHANNEL_TYPE_USB                         0x00UL
#define CHANNEL_TYPE_BLUETOOTH                   0x01UL

typedef struct CK_VENDOR_PIN_PARAMS {
	CK_USER_TYPE userType;
	CK_UTF8CHAR_PTR pPinValue;
	CK_ULONG ulPinLength;
} CK_VENDOR_PIN_PARAMS;
typedef CK_VENDOR_PIN_PARAMS *CK_VENDOR_PIN_PARAMS_PTR;

/* Flash drive: C_EX_GetVolumesInfo, C_EX_FormatDrive and
 * C_EX_ChangeVolumeAttributes.  Owners are CKU_SO, CKU_USER or a local
 * PIN identifier. */
typedef CK_ULONG CK_VOLUME_ID_EXTENDED;
typedef CK_ULONG CK_ACCESS_MODE_EXTENDED;
typedef CK_ULONG CK_OWNER_EXTENDED;

#define ACCESS_MODE_HIDDEN                       0x00UL
#define ACCESS_MODE_RO                           0x01UL
#define ACCESS_MODE_RW                           0x03UL
#define ACCESS_MODE_CD                           0x05UL
/* Deprecated volume flag */
#define CKF_ENCRYPTION                           0x01000000UL

typedef struct CK_VOLUME_INFO_EXTENDED {
	CK_VOLUME_ID_EXTENDED idVolume;
	CK_ULONG ulVolumeSize;
	CK_ACCESS_MODE_EXTENDED accessMode;
	CK_OWNER_EXTENDED volumeOwner;
	CK_FLAGS flags;
} CK_VOLUME_INFO_EXTENDED;
typedef CK_VOLUME_INFO_EXTENDED *CK_VOLUME_INFO_EXTENDED_PTR;

typedef struct CK_VOLUME_FORMAT_INFO_EXTENDED {
	CK_ULONG ulVolumeSize;
	CK_ACCESS_MODE_EXTENDED accessMode;
	CK_OWNER_EXTENDED volumeOwner;
	CK_FLAGS flags;
} CK_VOLUME_FORMAT_INFO_EXTENDED;
typedef CK_VOLUME_FORMAT_INFO_EXTENDED *CK_VOLUME_FORMAT_INFO_EXTENDED_PTR;

/* C_EX_PKCS7Sign flags */
#define PKCS7_DETACHED_SIGNATURE                 0x01UL
#define USE_HARDWARE_HASH                        0x02UL

/* C_EX_PKCS7Verify*: every buffer the library returns, including the
 * signer certificate array and each of its elements, is released with
 * C_EX_FreeBuffer. */
typedef struct CK_VENDOR_BUFFER {
	CK_BYTE_PTR pData;
	CK_ULONG ulSize;
} CK_VENDOR_BUFFER;
typedef CK_VENDOR_BUFFER *CK_VENDOR_BUFFER_PTR;
typedef CK_VENDOR_BUFFER_PTR *CK_VENDOR_BUFFER_PTR_PTR;

typedef struct CK_VENDOR_X509_STORE {
	CK_VENDOR_BUFFER_PTR pTrustedCertificates;
	CK_ULONG ulTrustedCertificateCount;
	CK_VENDOR_BUFFER_PTR pCertificates;
	CK_ULONG ulCertificateCount;
	CK_VENDOR_BUFFER_PTR pCrls;
	CK_ULONG ulCrlCount;
} CK_VENDOR_X509_STORE;
typedef CK_VENDOR_X509_STORE *CK_VENDOR_X509_STORE_PTR;

typedef CK_ULONG CK_VENDOR_CRL_MODE;
typedef CK_BYTE_PTR *CK_BYTE_PTR_PTR;

#define OPTIONAL_CRL_CHECK                       0UL
#define LEAF_CRL_CHECK                           1UL
#define ALL_CRL_CHECK                            2UL

#define CKF_VENDOR_DO_NOT_USE_INTERNAL_CMS_CERTS 0x01UL
#define CKF_VENDOR_ALLOW_PARTIAL_CHAINS          0x02UL
#define CKF_VENDOR_CHECK_SIGNATURE_ONLY          0x04UL
#define CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN  0x08UL

/* Deprecated C_EX_GenerateActivationPassword arguments */
#define GENERATE_NEXT_PASSWORD                   0x00UL
#define CAPS_AND_DIGITS                          0x00UL
#define CAPS_ONLY                                0x01UL

/* Authentication objects used by C_EX_Authenticate, C_EX_Deauthenticate and
 * C_EX_UnblockAuthenticator */
typedef CK_ULONG CK_VENDOR_AUTHENTICATION_FACTOR_TYPE;

#define CKVAF_BIO_FP_CONVOLUTION                 1UL
#define CKO_VENDOR_AUTHENTICATION_FACTOR         (CKO_VENDOR_DEFINED + 0x01UL)
#define CKA_VENDOR_AUTHENTICATION_FACTOR_TYPE    (CKA_VENDOR_DEFINED | 0x3300UL)
#define CKA_VENDOR_FP_CONVOLUTIONS_COUNT         (CKA_VENDOR_DEFINED | 0x3301UL)
#define CKA_VENDOR_FP_CONVOLUTIONS \
	(CKA_VENDOR_DEFINED | CKF_ARRAY_ATTRIBUTE | 0x3302UL)
#define CKA_VENDOR_FINGERPRINT_CONVOLUTIONS_ID   (CKA_VENDOR_DEFINED | 0x3304UL)
#define CKA_VENDOR_MAX_RETRY_COUNT               (CKA_VENDOR_DEFINED | 0x3305UL)
#define CKA_VENDOR_RETRY_COUNT_LEFT              (CKA_VENDOR_DEFINED | 0x3306UL)
#define CKA_VENDOR_BIO_DATA_ID                   (CKA_VENDOR_DEFINED | 0x3307UL)

/* Private key attributes, CK_BBOOL.  CKA_VENDOR_KEY_JOURNAL marks the GOST
 * key pair that signs the journal; with CKA_VENDOR_CONFIRM_BY_TOUCH a token
 * with a button (TOKEN_FLAGS_HAS_BUTTON, Rutoken Touch) signs only after
 * the button is pressed.  PIN_ENTER and CONFIRM_OP are deprecated. */
#define CKA_VENDOR_KEY_PIN_ENTER                 (CKA_VENDOR_DEFINED | 0x2000UL)
#define CKA_VENDOR_KEY_CONFIRM_OP                (CKA_VENDOR_DEFINED | 0x2001UL)
#define CKA_VENDOR_KEY_JOURNAL                   (CKA_VENDOR_DEFINED | 0x2002UL)
#define CKA_VENDOR_CONFIRM_BY_TOUCH              (CKA_VENDOR_DEFINED | 0x2003UL)

/* Emitent key types of MODE_RESTORE_FACTORY_DEFAULTS, from the TC 26 range
 * of pkcs11.h; CKA_VENDOR_SUPPORTED_EMITENT_KEY_ALGS lists those a token
 * accepts. */
#ifndef CKK_KUZNECHIK
#define CKK_KUZNECHIK                            (NSSCK_VENDOR_PKCS11_RU_TEAM | 0x004UL)
#endif
#ifndef CKK_MAGMA
#define CKK_MAGMA                                (NSSCK_VENDOR_PKCS11_RU_TEAM | 0x005UL)
#endif

typedef struct CK_FUNCTION_LIST_EXTENDED CK_FUNCTION_LIST_EXTENDED;
typedef CK_FUNCTION_LIST_EXTENDED *CK_FUNCTION_LIST_EXTENDED_PTR;
typedef CK_FUNCTION_LIST_EXTENDED_PTR *CK_FUNCTION_LIST_EXTENDED_PTR_PTR;

#define CK_RUTOKEN_FUNCTION(name, args) typedef CK_RV (*CK_ ## name) args

CK_RUTOKEN_FUNCTION(C_EX_GetFunctionListExtended,
		(CK_FUNCTION_LIST_EXTENDED_PTR_PTR));
CK_RUTOKEN_FUNCTION(C_EX_InitToken,
		(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_RUTOKEN_INIT_PARAM_PTR));
CK_RUTOKEN_FUNCTION(C_EX_GetTokenInfoExtended,
		(CK_SLOT_ID, CK_TOKEN_INFO_EXTENDED_PTR));
CK_RUTOKEN_FUNCTION(C_EX_UnblockUserPIN, (CK_SESSION_HANDLE));
CK_RUTOKEN_FUNCTION(C_EX_SetTokenName,
		(CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_SetLicense,
		(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_GetLicense,
		(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_GetCertificateInfoText,
		(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_CHAR_PTR *, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_PKCS7Sign,
		(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE,
		 CK_BYTE_PTR *, CK_ULONG_PTR, CK_OBJECT_HANDLE,
		 CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_CreateCSR,
		(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_CHAR_PTR *, CK_ULONG,
		 CK_BYTE_PTR *, CK_ULONG_PTR, CK_OBJECT_HANDLE, CK_CHAR_PTR *,
		 CK_ULONG, CK_CHAR_PTR *, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_FreeBuffer, (CK_BYTE_PTR));
CK_RUTOKEN_FUNCTION(C_EX_GetTokenName,
		(CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_SetLocalPIN,
		(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR,
		 CK_ULONG, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_LoadActivationKey,
		(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_SetActivationPassword,
		(CK_SLOT_ID, CK_UTF8CHAR_PTR));
CK_RUTOKEN_FUNCTION(C_EX_GetVolumesInfo,
		(CK_SLOT_ID, CK_VOLUME_INFO_EXTENDED_PTR, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_GetDriveSize, (CK_SLOT_ID, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_ChangeVolumeAttributes,
		(CK_SLOT_ID, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG,
		 CK_VOLUME_ID_EXTENDED, CK_ACCESS_MODE_EXTENDED, CK_BBOOL));
CK_RUTOKEN_FUNCTION(C_EX_FormatDrive,
		(CK_SLOT_ID, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG,
		 CK_VOLUME_FORMAT_INFO_EXTENDED_PTR, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_TokenManage,
		(CK_SESSION_HANDLE, CK_ULONG, CK_VOID_PTR));
CK_RUTOKEN_FUNCTION(C_EX_GenerateActivationPassword,
		(CK_SESSION_HANDLE, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG_PTR,
		 CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_GetJournal,
		(CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_SignInvisibleInit,
		(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE));
CK_RUTOKEN_FUNCTION(C_EX_SignInvisible,
		(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
		 CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_SlotManage,
		(CK_SLOT_ID, CK_ULONG, CK_VOID_PTR));
CK_RUTOKEN_FUNCTION(C_EX_WrapKey,
		(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
		 CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_MECHANISM_PTR,
		 CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR));
CK_RUTOKEN_FUNCTION(C_EX_UnwrapKey,
		(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
		 CK_MECHANISM_PTR, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR,
		 CK_ULONG, CK_OBJECT_HANDLE_PTR));
CK_RUTOKEN_FUNCTION(C_EX_PKCS7VerifyInit,
		(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
		 CK_VENDOR_X509_STORE_PTR, CK_VENDOR_CRL_MODE, CK_FLAGS));
CK_RUTOKEN_FUNCTION(C_EX_PKCS7Verify,
		(CK_SESSION_HANDLE, CK_BYTE_PTR_PTR, CK_ULONG_PTR,
		 CK_VENDOR_BUFFER_PTR_PTR, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_PKCS7VerifyUpdate,
		(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_PKCS7VerifyFinal,
		(CK_SESSION_HANDLE, CK_VENDOR_BUFFER_PTR_PTR, CK_ULONG_PTR));
CK_RUTOKEN_FUNCTION(C_EX_Authenticate,
		(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG));
CK_RUTOKEN_FUNCTION(C_EX_Deauthenticate,
		(CK_SESSION_HANDLE, CK_OBJECT_HANDLE));
CK_RUTOKEN_FUNCTION(C_EX_UnblockAuthenticator,
		(CK_SESSION_HANDLE, CK_OBJECT_HANDLE));

#undef CK_RUTOKEN_FUNCTION

struct CK_FUNCTION_LIST_EXTENDED {
	CK_VERSION version;
	CK_C_EX_GetFunctionListExtended C_EX_GetFunctionListExtended;
	CK_C_EX_InitToken C_EX_InitToken;
	CK_C_EX_GetTokenInfoExtended C_EX_GetTokenInfoExtended;
	CK_C_EX_UnblockUserPIN C_EX_UnblockUserPIN;
	CK_C_EX_SetTokenName C_EX_SetTokenName;
	CK_C_EX_SetLicense C_EX_SetLicense;
	CK_C_EX_GetLicense C_EX_GetLicense;
	CK_C_EX_GetCertificateInfoText C_EX_GetCertificateInfoText;
	CK_C_EX_PKCS7Sign C_EX_PKCS7Sign;
	CK_C_EX_CreateCSR C_EX_CreateCSR;
	CK_C_EX_FreeBuffer C_EX_FreeBuffer;
	CK_C_EX_GetTokenName C_EX_GetTokenName;
	CK_C_EX_SetLocalPIN C_EX_SetLocalPIN;
	CK_C_EX_LoadActivationKey C_EX_LoadActivationKey;
	CK_C_EX_SetActivationPassword C_EX_SetActivationPassword;
	CK_C_EX_GetVolumesInfo C_EX_GetVolumesInfo;
	CK_C_EX_GetDriveSize C_EX_GetDriveSize;
	CK_C_EX_ChangeVolumeAttributes C_EX_ChangeVolumeAttributes;
	CK_C_EX_FormatDrive C_EX_FormatDrive;
	CK_C_EX_TokenManage C_EX_TokenManage;
	CK_C_EX_GenerateActivationPassword C_EX_GenerateActivationPassword;
	CK_C_EX_GetJournal C_EX_GetJournal;
	CK_C_EX_SignInvisibleInit C_EX_SignInvisibleInit;
	CK_C_EX_SignInvisible C_EX_SignInvisible;
	CK_C_EX_SlotManage C_EX_SlotManage;
	CK_C_EX_WrapKey C_EX_WrapKey;
	CK_C_EX_UnwrapKey C_EX_UnwrapKey;
	CK_C_EX_PKCS7VerifyInit C_EX_PKCS7VerifyInit;
	CK_C_EX_PKCS7Verify C_EX_PKCS7Verify;
	CK_C_EX_PKCS7VerifyUpdate C_EX_PKCS7VerifyUpdate;
	CK_C_EX_PKCS7VerifyFinal C_EX_PKCS7VerifyFinal;
	CK_C_EX_Authenticate C_EX_Authenticate;
	CK_C_EX_Deauthenticate C_EX_Deauthenticate;
	CK_C_EX_UnblockAuthenticator C_EX_UnblockAuthenticator;
};

CK_RV CK_SPEC C_EX_GetFunctionListExtended(
		CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList);

#ifdef __cplusplus
}
#endif

#ifdef _WIN32
#pragma pack(pop, rutoken)
#endif

#endif
