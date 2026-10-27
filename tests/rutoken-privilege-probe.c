/* Narrow companion to privilege_scenarios.py for calls the pkcs11-tool CLI
 * deliberately does not expose. No Flash, BIO, legacy or issuer-key calls.
 * Build: cc -I src tests/rutoken-privilege-probe.c -o probe -ldl
 * Usage: probe MODULE SLOT OPERATION ROLE ro|rw PIN_ENV|- [VALUE]
 * OPERATION: reset-user-pin, set-license, set-name, token-label,
 *            module-info, object-count.
 */
#include "pkcs11/pkcs11-rutoken.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

static const char *
rv_name(CK_RV rv)
{
	switch (rv) {
	case CKR_OK: return "CKR_OK";
	case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
	default: return "OTHER_CKR";
	}
}

static void
print_hex(const CK_BYTE *value, size_t length)
{
	size_t i;
	for (i = 0; i < length; i++)
		printf("%02x", value[i]);
}

static void
result(const char *stage, CK_RV rv, const CK_TOKEN_INFO *info)
{
	printf("{\"stage\":\"%s\",\"rv\":\"%s\",\"code\":%lu",
		stage, rv_name(rv), (unsigned long)rv);
	if (info) {
		fputs(",\"label_hex\":\"", stdout);
		print_hex(info->label, sizeof(info->label));
		fputs("\",\"model_hex\":\"", stdout);
		print_hex(info->model, sizeof(info->model));
		printf("\",\"hardware\":\"%u.%u\",\"firmware\":\"%u.%u\"",
			(unsigned int)info->hardwareVersion.major,
			(unsigned int)info->hardwareVersion.minor,
			(unsigned int)info->firmwareVersion.major,
			(unsigned int)info->firmwareVersion.minor);
	}
	puts("}");
}

static void *
open_module(const char *path)
{
#ifdef _WIN32
	return (void *)LoadLibraryA(path);
#else
	return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void *
find_symbol(void *handle, const char *name)
{
#ifdef _WIN32
	return (void *)GetProcAddress((HMODULE)handle, name);
#else
	return dlsym(handle, name);
#endif
}

static void
close_module(void *handle)
{
#ifdef _WIN32
	FreeLibrary((HMODULE)handle);
#else
	dlclose(handle);
#endif
}

int
main(int argc, char **argv)
{
	void *module, *symbol;
	CK_C_GetFunctionList get_standard = NULL;
	CK_C_EX_GetFunctionListExtended get_extended = NULL;
	CK_FUNCTION_LIST_PTR standard = NULL;
	CK_FUNCTION_LIST_EXTENDED_PTR extended = NULL;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS flags = CKF_SERIAL_SESSION;
	CK_USER_TYPE role = CKU_USER, target = CKU_USER;
	CK_TOKEN_INFO token_info;
	CK_INFO module_info;
	CK_OBJECT_HANDLE objects[32];
	CK_ULONG found, object_count = 0;
	CK_BYTE license[72];
	CK_RV rv, final_rv;
	const char *pin = NULL, *stage = "arguments";
	char *end;
	unsigned long parsed;
	int initialized = 0, opened = 0, status = 1;

	if (argc < 7 || argc > 8) {
		fprintf(stderr, "usage: %s MODULE SLOT OPERATION ROLE ro|rw PIN_ENV|- [VALUE]\n", argv[0]);
		return 2;
	}
	errno = 0;
	parsed = strtoul(argv[2], &end, 0);
	if (errno || *end || end == argv[2]) {
		fputs("invalid slot\n", stderr);
		return 2;
	}
	slot = (CK_SLOT_ID)parsed;
	if (!strcmp(argv[5], "rw"))
		flags |= CKF_RW_SESSION;
	else if (strcmp(argv[5], "ro"))
		return 2;
	if (!strcmp(argv[4], "so"))
		role = CKU_SO;
	else if (strcmp(argv[4], "user") && strcmp(argv[4], "none"))
		return 2;
	if (strcmp(argv[4], "none")) {
		pin = getenv(argv[6]);
		if (!pin || !*pin) {
			fputs("PIN environment variable is missing\n", stderr);
			return 2;
		}
	}
	if ((!strcmp(argv[3], "set-license") ||
			!strcmp(argv[3], "set-name")) != (argc == 8) ||
			(strcmp(argv[3], "reset-user-pin") &&
			 strcmp(argv[3], "set-license") &&
			 strcmp(argv[3], "set-name") &&
			 strcmp(argv[3], "token-label") &&
			 strcmp(argv[3], "module-info") &&
			 strcmp(argv[3], "object-count")))
		return 2;
	module = open_module(argv[1]);
	if (!module) {
		fputs("cannot load module\n", stderr);
		return 1;
	}
	symbol = find_symbol(module, "C_GetFunctionList");
	if (!symbol)
		goto done;
	memcpy(&get_standard, &symbol, sizeof(get_standard));
	rv = get_standard(&standard);
	if (rv != CKR_OK || !standard)
		goto done;
	symbol = find_symbol(module, "C_EX_GetFunctionListExtended");
	if (!symbol)
		goto done;
	memcpy(&get_extended, &symbol, sizeof(get_extended));
	rv = get_extended(&extended);
	if (rv != CKR_OK || !extended)
		goto done;
	stage = "C_Initialize";
	rv = standard->C_Initialize(NULL);
	if (rv != CKR_OK) {
		result(stage, rv, NULL);
		goto done;
	}
	initialized = 1;
	if (!strcmp(argv[3], "module-info")) {
		stage = "C_GetInfo";
		rv = standard->C_GetInfo(&module_info);
		printf("{\"stage\":\"%s\",\"rv\":\"%s\",\"code\":%lu",
			stage, rv_name(rv), (unsigned long)rv);
		if (rv == CKR_OK)
			printf(",\"module_version\":\"%u.%u\"",
				(unsigned int)module_info.libraryVersion.major,
				(unsigned int)module_info.libraryVersion.minor);
		puts("}");
		status = 0;
		goto done;
	}
	if (!strcmp(argv[3], "token-label")) {
		stage = "C_GetTokenInfo";
		rv = standard->C_GetTokenInfo(slot, &token_info);
		result(stage, rv, rv == CKR_OK ? &token_info : NULL);
		status = 0;
		goto done;
	}
	stage = "C_OpenSession";
	rv = standard->C_OpenSession(slot, flags, NULL, NULL, &session);
	if (rv != CKR_OK) {
		result(stage, rv, NULL);
		status = 0;
		goto done;
	}
	opened = 1;
	if (pin) {
		stage = "C_Login";
		rv = standard->C_Login(session, role, (CK_UTF8CHAR_PTR)pin,
			(CK_ULONG)strlen(pin));
		if (rv != CKR_OK) {
			result(stage, rv, NULL);
			status = 0;
			goto done;
		}
	}
	if (!strcmp(argv[3], "object-count")) {
		stage = "C_FindObjectsInit";
		rv = standard->C_FindObjectsInit(session, NULL, 0);
		if (rv == CKR_OK) {
			stage = "C_FindObjects";
			do {
				rv = standard->C_FindObjects(session, objects,
					32, &found);
				if (rv == CKR_OK)
					object_count += found;
			} while (rv == CKR_OK && found == 32);
			final_rv = standard->C_FindObjectsFinal(session);
			if (final_rv != CKR_OK && rv == CKR_OK) {
				stage = "C_FindObjectsFinal";
				rv = final_rv;
			}
		}
		printf("{\"stage\":\"%s\",\"rv\":\"%s\",\"code\":%lu",
			stage, rv_name(rv), (unsigned long)rv);
		if (rv == CKR_OK)
			printf(",\"object_count\":%lu", (unsigned long)object_count);
		puts("}");
		status = 0;
		goto done;
	}
	if (!strcmp(argv[3], "reset-user-pin")) {
		stage = "C_EX_TokenManage";
		rv = extended->C_EX_TokenManage ?
			extended->C_EX_TokenManage(session,
				MODE_RESET_PIN_TO_DEFAULT, &target) : CKR_FUNCTION_NOT_SUPPORTED;
	} else if (!strcmp(argv[3], "set-license")) {
		errno = 0;
		parsed = strtoul(argv[7], &end, 10);
		if (errno || *end || end == argv[7] || parsed < 1 || parsed > 4) {
			fputs("license number must be 1..4\n", stderr);
			goto done;
		}
		memset(license, 'P', sizeof(license));
		stage = "C_EX_SetLicense";
		rv = extended->C_EX_SetLicense ?
			extended->C_EX_SetLicense(session, (CK_ULONG)parsed,
				license, sizeof(license)) : CKR_FUNCTION_NOT_SUPPORTED;
	} else {
		stage = "C_EX_SetTokenName";
		rv = extended->C_EX_SetTokenName ?
			extended->C_EX_SetTokenName(session, (CK_CHAR_PTR)argv[7],
				(CK_ULONG)strlen(argv[7])) : CKR_FUNCTION_NOT_SUPPORTED;
	}
	result(stage, rv, NULL);
	status = 0;
done:
	if (opened)
		standard->C_CloseSession(session);
	if (initialized)
		standard->C_Finalize(NULL);
	close_module(module);
	return status;
}
