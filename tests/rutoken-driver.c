#include "pkcs11/pkcs11-rutoken.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define ABI_ASSERT(name, expression) \
	typedef char abi_assert_ ## name[(expression) ? 1 : -1]

#ifdef _WIN32
ABI_ASSERT(ck_ulong_width, sizeof(CK_ULONG) == 4);
ABI_ASSERT(token_info_size, sizeof(CK_TOKEN_INFO_EXTENDED) == 164);
ABI_ASSERT(function_list_size,
		sizeof(CK_FUNCTION_LIST_EXTENDED) == 2 + 34 * sizeof(void *));
ABI_ASSERT(function_list_info_offset,
		offsetof(CK_FUNCTION_LIST_EXTENDED, C_EX_GetTokenInfoExtended) ==
		2 + 2 * sizeof(void *));
#else
ABI_ASSERT(ck_ulong_width, sizeof(CK_ULONG) == 8);
ABI_ASSERT(token_info_size, sizeof(CK_TOKEN_INFO_EXTENDED) == 256);
ABI_ASSERT(function_list_size, sizeof(CK_FUNCTION_LIST_EXTENDED) == 280);
ABI_ASSERT(function_list_info_offset,
		offsetof(CK_FUNCTION_LIST_EXTENDED, C_EX_GetTokenInfoExtended) == 24);
#endif

#undef ABI_ASSERT

#define EXPECT_VENDOR(call, number) \
do { \
	CK_RV checked_rv = (call); \
	if (checked_rv != CKR_VENDOR_DEFINED + (number)) { \
		fprintf(stderr, "%s returned 0x%lx, expected 0x%lx\n", #call, \
				(unsigned long)checked_rv, \
				(unsigned long)(CKR_VENDOR_DEFINED + (number))); \
		return 1; \
	} \
} while (0)

#define REQUIRE_POINTER(name) \
do { \
	if (!functions->name) { \
		fprintf(stderr, #name " is null\n"); \
		return 1; \
	} \
} while (0)

static void *
load_symbol(void *module, const char *name)
{
#ifdef _WIN32
	return (void *)GetProcAddress((HMODULE)module, name);
#else
	return dlsym(module, name);
#endif
}

int
main(int argc, char **argv)
{
	void *module;
	void *symbol;
	CK_C_EX_GetFunctionListExtended get_functions = NULL;
	CK_FUNCTION_LIST_EXTENDED_PTR functions = NULL;
	CK_TOKEN_INFO_EXTENDED info;
	CK_ULONG name_len = 0;
	CK_CHAR name[32];
	CK_RV rv;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <spy module> <stub module> <spy log>\n", argv[0]);
		return 2;
	}
#ifdef _WIN32
	if (_putenv_s("PKCS11SPY", argv[2]) || _putenv_s("PKCS11SPY_OUTPUT", argv[3]))
		return 2;
	module = (void *)LoadLibraryA(argv[1]);
#else
	if (setenv("PKCS11SPY", argv[2], 1) || setenv("PKCS11SPY_OUTPUT", argv[3], 1))
		return 2;
	module = dlopen(argv[1], RTLD_NOW);
#endif
	if (!module) {
		fprintf(stderr, "cannot load spy module\n");
		return 2;
	}
	symbol = load_symbol(module, "C_EX_GetFunctionListExtended");
	if (!symbol) {
		fprintf(stderr, "C_EX_GetFunctionListExtended is not exported\n");
		return 1;
	}
	memcpy(&get_functions, &symbol, sizeof(get_functions));
	if (get_functions(NULL) != CKR_ARGUMENTS_BAD) {
		fprintf(stderr, "null function-list request was not rejected\n");
		return 1;
	}
	rv = get_functions(&functions);
	if (rv != CKR_OK || !functions) {
		fprintf(stderr, "cannot get extended function list: 0x%lx\n",
				(unsigned long)rv);
		return 1;
	}
	if (functions->version.major != 2 || functions->version.minor != 40) {
		fprintf(stderr, "extended table version was not preserved: %u.%u\n",
				(unsigned int)functions->version.major,
				(unsigned int)functions->version.minor);
		return 1;
	}

	REQUIRE_POINTER(C_EX_GetFunctionListExtended);
	REQUIRE_POINTER(C_EX_InitToken);
	REQUIRE_POINTER(C_EX_GetTokenInfoExtended);
	REQUIRE_POINTER(C_EX_UnblockUserPIN);
	REQUIRE_POINTER(C_EX_SetTokenName);
	REQUIRE_POINTER(C_EX_SetLicense);
	REQUIRE_POINTER(C_EX_GetLicense);
	REQUIRE_POINTER(C_EX_GetCertificateInfoText);
	REQUIRE_POINTER(C_EX_PKCS7Sign);
	REQUIRE_POINTER(C_EX_CreateCSR);
	REQUIRE_POINTER(C_EX_FreeBuffer);
	REQUIRE_POINTER(C_EX_GetTokenName);
	REQUIRE_POINTER(C_EX_SetLocalPIN);
	REQUIRE_POINTER(C_EX_LoadActivationKey);
	REQUIRE_POINTER(C_EX_SetActivationPassword);
	REQUIRE_POINTER(C_EX_GetVolumesInfo);
	REQUIRE_POINTER(C_EX_GetDriveSize);
	REQUIRE_POINTER(C_EX_ChangeVolumeAttributes);
	REQUIRE_POINTER(C_EX_FormatDrive);
	REQUIRE_POINTER(C_EX_TokenManage);
	REQUIRE_POINTER(C_EX_GenerateActivationPassword);
	REQUIRE_POINTER(C_EX_GetJournal);
	REQUIRE_POINTER(C_EX_SignInvisibleInit);
	REQUIRE_POINTER(C_EX_SignInvisible);
	REQUIRE_POINTER(C_EX_SlotManage);
	REQUIRE_POINTER(C_EX_WrapKey);
	REQUIRE_POINTER(C_EX_UnwrapKey);
	REQUIRE_POINTER(C_EX_PKCS7VerifyInit);
	REQUIRE_POINTER(C_EX_PKCS7Verify);
	REQUIRE_POINTER(C_EX_PKCS7VerifyUpdate);
	REQUIRE_POINTER(C_EX_PKCS7VerifyFinal);
	REQUIRE_POINTER(C_EX_Authenticate);
	REQUIRE_POINTER(C_EX_Deauthenticate);
	REQUIRE_POINTER(C_EX_UnblockAuthenticator);

	EXPECT_VENDOR(functions->C_EX_InitToken(7, NULL, 0, NULL), 1);
	memset(&info, 0, sizeof(info));
	info.ulSizeofThisStructure = sizeof(info);
	if (functions->C_EX_GetTokenInfoExtended(7, &info) != CKR_OK ||
			info.ulTokenType != 1 || info.ulTokenClass != 1)
		return 1;
	EXPECT_VENDOR(functions->C_EX_UnblockUserPIN(23), 3);
	EXPECT_VENDOR(functions->C_EX_SetTokenName(23, NULL, 0), 4);
	EXPECT_VENDOR(functions->C_EX_SetLicense(23, 1, NULL, 0), 5);
	EXPECT_VENDOR(functions->C_EX_GetLicense(23, 1, NULL, NULL), 6);
	EXPECT_VENDOR(functions->C_EX_GetCertificateInfoText(23, 1, NULL, NULL), 7);
	EXPECT_VENDOR(functions->C_EX_PKCS7Sign(23, NULL, 0, 1, NULL, NULL, 2,
			NULL, 0, 0), 8);
	EXPECT_VENDOR(functions->C_EX_CreateCSR(23, 1, NULL, 0, NULL, NULL, 2,
			NULL, 0, NULL, 0), 9);
	EXPECT_VENDOR(functions->C_EX_FreeBuffer(NULL), 10);
	if (functions->C_EX_GetTokenName(23, NULL, &name_len) != CKR_OK ||
			name_len != 12)
		return 1;
	memset(name, 0, sizeof(name));
	if (functions->C_EX_GetTokenName(23, name, &name_len) != CKR_OK ||
			name_len != 12 || memcmp(name, "Test Rutoken", 12))
		return 1;
	EXPECT_VENDOR(functions->C_EX_SetLocalPIN(7, NULL, 0, NULL, 0, 1), 12);
	EXPECT_VENDOR(functions->C_EX_LoadActivationKey(23, NULL, 0), 13);
	EXPECT_VENDOR(functions->C_EX_SetActivationPassword(7, NULL), 14);
	EXPECT_VENDOR(functions->C_EX_GetVolumesInfo(7, NULL, NULL), 15);
	EXPECT_VENDOR(functions->C_EX_GetDriveSize(7, NULL), 16);
	EXPECT_VENDOR(functions->C_EX_ChangeVolumeAttributes(7, CKU_USER, NULL, 0,
			1, 1, CK_FALSE), 17);
	EXPECT_VENDOR(functions->C_EX_FormatDrive(7, CKU_USER, NULL, 0, NULL, 0), 18);
	EXPECT_VENDOR(functions->C_EX_TokenManage(23, 1, NULL), 19);
	EXPECT_VENDOR(functions->C_EX_GenerateActivationPassword(23, 1, NULL,
			NULL, 0), 20);
	EXPECT_VENDOR(functions->C_EX_GetJournal(7, NULL, NULL), 21);
	EXPECT_VENDOR(functions->C_EX_SignInvisibleInit(23, NULL, 1), 22);
	EXPECT_VENDOR(functions->C_EX_SignInvisible(23, NULL, 0, NULL, NULL), 23);
	EXPECT_VENDOR(functions->C_EX_SlotManage(7, 1, NULL), 24);
	EXPECT_VENDOR(functions->C_EX_WrapKey(23, NULL, NULL, 0, NULL, 1, NULL,
			NULL, NULL, NULL), 25);
	EXPECT_VENDOR(functions->C_EX_UnwrapKey(23, NULL, 1, NULL, NULL, 0, NULL,
			0, NULL), 26);
	EXPECT_VENDOR(functions->C_EX_PKCS7VerifyInit(23, NULL, 0, NULL, 0, 0), 27);
	EXPECT_VENDOR(functions->C_EX_PKCS7Verify(23, NULL, NULL, NULL, NULL), 28);
	EXPECT_VENDOR(functions->C_EX_PKCS7VerifyUpdate(23, NULL, 0), 29);
	EXPECT_VENDOR(functions->C_EX_PKCS7VerifyFinal(23, NULL, NULL), 30);
	EXPECT_VENDOR(functions->C_EX_Authenticate(23, 1, NULL, 0), 31);
	EXPECT_VENDOR(functions->C_EX_Deauthenticate(23, 1), 32);
	EXPECT_VENDOR(functions->C_EX_UnblockAuthenticator(23, 1), 33);

	puts("PASS: all Rutoken extended spy wrappers preserve table order and return values");
	return 0;
}
