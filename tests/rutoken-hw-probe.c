/*
 * Read-only hardware probe for the Rutoken PKCS #11 extension.
 *
 * The probe loads rtPKCS11ECP, directly or through pkcs11-spy, and records
 * what the library returns for every extension function that only reads
 * token state, including buffer-size edge cases.  It never calls functions
 * that format the token or change PINs, names, licenses, volumes or token
 * modes.  The optional --pkcs7 check signs fixed test data with an existing
 * key only after typed confirmation.
 *
 * Build on Linux from the OpenSC source tree:
 *   cc -I src -o rutoken-hw-probe tests/rutoken-hw-probe.c -ldl
 */

#define _POSIX_C_SOURCE 200809L

#include "pkcs11/pkcs11-rutoken.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>

#define PROBE_VERSION 1
#define SENTINEL 0xA5
#define MAX_OBJECTS 64
#define EXTENDED_FUNCTIONS 34
#define CKH_VENDOR_TOKEN_INFO (CKH_VENDOR_DEFINED + 0x01UL)
#define CKA_VENDOR_KEY_JOURNAL (CKA_VENDOR_DEFINED | 0x2002UL)

/* The loop in probe_extended_table() relies on this layout. */
typedef char probe_table_layout[
		sizeof(CK_FUNCTION_LIST_EXTENDED) ==
		offsetof(CK_FUNCTION_LIST_EXTENDED, C_EX_GetFunctionListExtended) +
		EXTENDED_FUNCTIONS * sizeof(CK_C_EX_FreeBuffer) ? 1 : -1];

static const char test_data[] = "OpenSC Rutoken hardware probe test data\n";

static struct {
	const char *module;
	CK_SLOT_ID slot;
	int have_slot;
	int login;
	long pause_ms;
	int show_text;
	const char *pkcs7_id;
	const char *save_dir;
} opt = { NULL, 0, 0, 0, 1000, 0, NULL, NULL };

static void *module;
static CK_FUNCTION_LIST_PTR f;
static CK_FUNCTION_LIST_EXTENDED_PTR fx;
static unsigned int step_number;
static CK_TOKEN_INFO_EXTENDED token_info;
static int have_token_info;
static CK_OBJECT_HANDLE seen_certificates[MAX_OBJECTS];
static CK_ULONG seen_certificate_count;

static const char *const extended_names[EXTENDED_FUNCTIONS] = {
	"C_EX_GetFunctionListExtended", "C_EX_InitToken",
	"C_EX_GetTokenInfoExtended", "C_EX_UnblockUserPIN", "C_EX_SetTokenName",
	"C_EX_SetLicense", "C_EX_GetLicense", "C_EX_GetCertificateInfoText",
	"C_EX_PKCS7Sign", "C_EX_CreateCSR", "C_EX_FreeBuffer",
	"C_EX_GetTokenName", "C_EX_SetLocalPIN", "C_EX_LoadActivationKey",
	"C_EX_SetActivationPassword", "C_EX_GetVolumesInfo", "C_EX_GetDriveSize",
	"C_EX_ChangeVolumeAttributes", "C_EX_FormatDrive", "C_EX_TokenManage",
	"C_EX_GenerateActivationPassword", "C_EX_GetJournal",
	"C_EX_SignInvisibleInit", "C_EX_SignInvisible", "C_EX_SlotManage",
	"C_EX_WrapKey", "C_EX_UnwrapKey", "C_EX_PKCS7VerifyInit",
	"C_EX_PKCS7Verify", "C_EX_PKCS7VerifyUpdate", "C_EX_PKCS7VerifyFinal",
	"C_EX_Authenticate", "C_EX_Deauthenticate", "C_EX_UnblockAuthenticator"
};

#define RV_NAME(name) { name, #name }
static const struct {
	CK_RV rv;
	const char *name;
} rv_names[] = {
	RV_NAME(CKR_OK), RV_NAME(CKR_CANCEL), RV_NAME(CKR_HOST_MEMORY),
	RV_NAME(CKR_SLOT_ID_INVALID), RV_NAME(CKR_GENERAL_ERROR),
	RV_NAME(CKR_FUNCTION_FAILED), RV_NAME(CKR_ARGUMENTS_BAD),
	RV_NAME(CKR_ATTRIBUTE_SENSITIVE), RV_NAME(CKR_ATTRIBUTE_TYPE_INVALID),
	RV_NAME(CKR_ATTRIBUTE_VALUE_INVALID), RV_NAME(CKR_DATA_INVALID),
	RV_NAME(CKR_DATA_LEN_RANGE), RV_NAME(CKR_DEVICE_ERROR),
	RV_NAME(CKR_DEVICE_MEMORY), RV_NAME(CKR_DEVICE_REMOVED),
	RV_NAME(CKR_FUNCTION_CANCELED), RV_NAME(CKR_FUNCTION_NOT_SUPPORTED),
	RV_NAME(CKR_KEY_HANDLE_INVALID), RV_NAME(CKR_KEY_TYPE_INCONSISTENT),
	RV_NAME(CKR_KEY_FUNCTION_NOT_PERMITTED), RV_NAME(CKR_MECHANISM_INVALID),
	RV_NAME(CKR_OBJECT_HANDLE_INVALID), RV_NAME(CKR_OPERATION_ACTIVE),
	RV_NAME(CKR_OPERATION_NOT_INITIALIZED), RV_NAME(CKR_PIN_INCORRECT),
	RV_NAME(CKR_PIN_INVALID), RV_NAME(CKR_PIN_LEN_RANGE),
	RV_NAME(CKR_PIN_EXPIRED), RV_NAME(CKR_PIN_LOCKED),
	RV_NAME(CKR_SESSION_CLOSED), RV_NAME(CKR_SESSION_HANDLE_INVALID),
	RV_NAME(CKR_SESSION_READ_ONLY), RV_NAME(CKR_SESSION_EXISTS),
	RV_NAME(CKR_SIGNATURE_INVALID), RV_NAME(CKR_SIGNATURE_LEN_RANGE),
	RV_NAME(CKR_TEMPLATE_INCOMPLETE), RV_NAME(CKR_TOKEN_NOT_PRESENT),
	RV_NAME(CKR_TOKEN_NOT_RECOGNIZED), RV_NAME(CKR_TOKEN_WRITE_PROTECTED),
	RV_NAME(CKR_USER_ALREADY_LOGGED_IN), RV_NAME(CKR_USER_NOT_LOGGED_IN),
	RV_NAME(CKR_USER_PIN_NOT_INITIALIZED), RV_NAME(CKR_USER_TYPE_INVALID),
	RV_NAME(CKR_BUFFER_TOO_SMALL), RV_NAME(CKR_CRYPTOKI_NOT_INITIALIZED),
	RV_NAME(CKR_CRYPTOKI_ALREADY_INITIALIZED),
	RV_NAME(CKR_CORRUPTED_MAPFILE), RV_NAME(CKR_WRONG_VERSION_FIELD),
	RV_NAME(CKR_WRONG_PKCS1_ENCODING), RV_NAME(CKR_RTPKCS11_DATA_CORRUPTED),
	RV_NAME(CKR_RTPKCS11_RSF_DATA_CORRUPTED), RV_NAME(CKR_SM_PASSWORD_INVALID),
	RV_NAME(CKR_LICENSE_READ_ONLY), RV_NAME(CKR_VENDOR_EMITENT_KEY_BLOCKED),
	RV_NAME(CKR_CERT_CHAIN_NOT_VERIFIED), RV_NAME(CKR_INAPPROPRIATE_PIN),
	RV_NAME(CKR_PIN_IN_HISTORY), RV_NAME(CKR_VENDOR_INTERFACE_NOT_INITIALIZED)
};
#undef RV_NAME

static const char *
rv_name(CK_RV rv)
{
	static char unknown[48];
	size_t i;

	for (i = 0; i < sizeof(rv_names) / sizeof(rv_names[0]); i++)
		if (rv_names[i].rv == rv)
			return rv_names[i].name;
	if (rv >= CKR_VENDOR_DEFINED)
		snprintf(unknown, sizeof(unknown), "CKR_VENDOR_DEFINED+%lu",
				(unsigned long)(rv - CKR_VENDOR_DEFINED));
	else
		snprintf(unknown, sizeof(unknown), "unknown");
	return unknown;
}

static void
line(const char *format, ...)
{
	va_list args;

	fputs("  ", stdout);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	fputc('\n', stdout);
	fflush(stdout);
}

static void
show_rv(const char *call, CK_RV rv)
{
	line("%s -> %s (0x%lx)", call, rv_name(rv), (unsigned long)rv);
}

static void
step(const char *format, ...)
{
	struct timespec now = { 0, 0 };
	struct timespec delay;
	struct tm local;
	char stamp[16] = "--:--:--";
	va_list args;

	if (step_number > 0 && opt.pause_ms > 0) {
		delay.tv_sec = opt.pause_ms / 1000;
		delay.tv_nsec = (opt.pause_ms % 1000) * 1000000L;
		while (nanosleep(&delay, &delay) && errno == EINTR)
			;
	}
	step_number++;
	if (!clock_gettime(CLOCK_REALTIME, &now) &&
			localtime_r(&now.tv_sec, &local))
		strftime(stamp, sizeof(stamp), "%H:%M:%S", &local);
	printf("\n[%s.%03ld] STEP %02u ", stamp, now.tv_nsec / 1000000L,
			step_number);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	fputc('\n', stdout);
	fflush(stdout);
}

static int
available(const void *table, int present, const char *name)
{
	if (table && present)
		return 1;
	line("%s is not provided by the module", name);
	return 0;
}

#define HAVE(table, name) available((table), (table) && (table)->name, #name)

static void
print_hex(const char *label, const CK_BYTE *data, size_t length, size_t limit)
{
	size_t i;

	printf("  %s (%zu bytes):", label, length);
	for (i = 0; i < length && i < limit; i++)
		printf("%s%02x", i % 32 ? "" : "\n    ", data[i]);
	if (length > limit)
		printf("\n    ...");
	printf("\n");
	fflush(stdout);
}

static void
print_padded(const char *label, const CK_UTF8CHAR *text, size_t size)
{
	while (size > 0 && (text[size - 1] == ' ' || text[size - 1] == '\0'))
		size--;
	line("%s: \"%.*s\"", label, (int)size, (const char *)text);
}

static size_t
changed_bytes(const void *buffer, size_t from, size_t to)
{
	const CK_BYTE *bytes = buffer;
	size_t count = 0;

	for (; from < to; from++)
		if (bytes[from] != SENTINEL)
			count++;
	return count;
}

static void
wipe(void *data, size_t size)
{
	volatile CK_BYTE *bytes = data;

	while (size--)
		*bytes++ = 0;
}

static void
save_file(const char *name, const CK_BYTE *data, CK_ULONG length)
{
	char path[4096];
	FILE *file;
	int ok;

	if (!opt.save_dir)
		return;
	if (snprintf(path, sizeof(path), "%s/%s", opt.save_dir, name) >=
			(int)sizeof(path))
		return;
	file = fopen(path, "wb");
	if (!file) {
		line("cannot save %s: %s", path, strerror(errno));
		return;
	}
	ok = fwrite(data, 1, length, file) == length;
	if (fclose(file))
		ok = 0;
	line(ok ? "saved %s" : "cannot write %s", path);
}

static const char *
token_type_name(CK_ULONG type)
{
	switch (type) {
	case TOKEN_TYPE_RUTOKEN_ECP: return "Rutoken ECP";
	case TOKEN_TYPE_RUTOKEN_LITE: return "Rutoken Lite";
	case TOKEN_TYPE_RUTOKEN: return "Rutoken S";
	case TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY: return "Rutoken PINPad family";
	case TOKEN_TYPE_RUTOKEN_MIKRON: return "Rutoken Mikron";
	case TOKEN_TYPE_RUTOKEN_ECPDUAL_USB: return "Rutoken ECP Dual USB";
	case TOKEN_TYPE_RUTOKEN_WEB: return "Rutoken WEB";
	case TOKEN_TYPE_RUTOKEN_SC_JC: return "Rutoken ECP SC";
	case TOKEN_TYPE_RUTOKEN_LITE_SC_JC: return "Rutoken Lite SC";
	case TOKEN_TYPE_RUTOKEN_MIKRON_SC: return "Rutoken Mikron SC";
	case TOKEN_TYPE_RUTOKEN_SCDUAL: return "Rutoken SC Dual";
	case TOKEN_TYPE_RUTOKEN_MIKRON_SCDUAL: return "Rutoken Mikron SC Dual";
	case TOKEN_TYPE_RUTOKEN_ECPDUAL_BT: return "Rutoken ECP Dual Bluetooth";
	case TOKEN_TYPE_RUTOKEN_ECP_SD: return "Rutoken ECP SD";
	case TOKEN_TYPE_RUTOKEN_LITE_SD: return "Rutoken Lite SD";
	case TOKEN_TYPE_RUTOKEN_ECPDUAL_UART: return "Rutoken ECP Dual UART";
	case TOKEN_TYPE_RUTOKEN_ECP_NFC: return "Rutoken ECP NFC";
	case TOKEN_TYPE_RUTOKEN_SCDUAL_NFC: return "Rutoken SC Dual NFC";
	case TOKEN_TYPE_RUTOKEN_MIKRON_SCDUAL_NFC: return "Rutoken Mikron SC Dual NFC";
	case TOKEN_TYPE_UNKNOWN: return "unknown";
	default: return "not in the 2.21 header";
	}
}

static const char *
token_class_name(CK_ULONG token_class)
{
	switch (token_class) {
	case TOKEN_CLASS_S: return "S";
	case TOKEN_CLASS_ECP: return "ECP";
	case TOKEN_CLASS_LITE: return "Lite";
	case TOKEN_CLASS_WEB: return "WEB";
	case TOKEN_CLASS_PINPAD: return "PINPad";
	case TOKEN_CLASS_ECPDUAL: return "ECP Dual";
	case TOKEN_CLASS_UNKNOWN: return "unknown";
	default: return "not in the 2.21 header";
	}
}

static const char *
access_mode_name(CK_ULONG mode)
{
	switch (mode) {
	case ACCESS_MODE_HIDDEN: return "hidden";
	case ACCESS_MODE_RO: return "read-only";
	case ACCESS_MODE_RW: return "read-write";
	case ACCESS_MODE_CD: return "CD-ROM";
	default: return "unknown";
	}
}

static void
print_token_flags(CK_FLAGS flags)
{
	static const struct {
		CK_FLAGS flag;
		const char *name;
	} names[] = {
		{ TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN, "ADMIN_CHANGE_USER_PIN" },
		{ TOKEN_FLAGS_USER_CHANGE_USER_PIN, "USER_CHANGE_USER_PIN" },
		{ TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT, "ADMIN_PIN_NOT_DEFAULT" },
		{ TOKEN_FLAGS_USER_PIN_NOT_DEFAULT, "USER_PIN_NOT_DEFAULT" },
		{ TOKEN_FLAGS_SUPPORT_FKN, "SUPPORT_FKN" },
		{ TOKEN_FLAGS_SUPPORT_SM, "SUPPORT_SM" },
		{ TOKEN_FLAGS_HAS_FLASH_DRIVE, "HAS_FLASH_DRIVE" },
		{ TOKEN_FLAGS_SUPPORT_SECURE_MESSAGING, "SUPPORT_SECURE_MESSAGING" },
		{ TOKEN_FLAGS_HAS_BUTTON, "HAS_BUTTON" },
		{ TOKEN_FLAGS_SUPPORT_JOURNAL, "SUPPORT_JOURNAL" },
		{ TOKEN_FLAGS_USER_PIN_UTF8, "USER_PIN_UTF8" },
		{ TOKEN_FLAGS_ADMIN_PIN_UTF8, "ADMIN_PIN_UTF8" },
		{ TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE, "FW_CHECKSUM_UNAVAILABLE" },
		{ TOKEN_FLAGS_FW_CHECKSUM_INVALID, "FW_CHECKSUM_INVALID" }
	};
	size_t i;

	printf("  flags = 0x%lx:", (unsigned long)flags);
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (flags & names[i].flag) {
			printf(" %s", names[i].name);
			flags &= ~names[i].flag;
		}
	if (flags)
		printf(" unknown 0x%lx", (unsigned long)flags);
	printf("\n");
	fflush(stdout);
}

static void
print_token_info_extended(const CK_TOKEN_INFO_EXTENDED *info)
{
	line("ulSizeofThisStructure = %lu", info->ulSizeofThisStructure);
	line("ulTokenType = 0x%lx (%s)", info->ulTokenType,
			token_type_name(info->ulTokenType));
	line("ulTokenClass = 0x%lx (%s)", info->ulTokenClass,
			token_class_name(info->ulTokenClass));
	line("protocol %lu, microcode %lu, order %lu", info->ulProtocolNumber,
			info->ulMicrocodeNumber, info->ulOrderNumber);
	print_token_flags(info->flags);
	line("admin PIN length %lu..%lu, retries left %lu of %lu",
			info->ulMinAdminPinLen, info->ulMaxAdminPinLen,
			info->ulAdminRetryCountLeft, info->ulMaxAdminRetryCount);
	line("user PIN length %lu..%lu, retries left %lu of %lu",
			info->ulMinUserPinLen, info->ulMaxUserPinLen,
			info->ulUserRetryCountLeft, info->ulMaxUserRetryCount);
	print_hex("serialNumber", info->serialNumber,
			sizeof(info->serialNumber), sizeof(info->serialNumber));
	line("memory %lu free of %lu bytes", info->ulFreeMemory,
			info->ulTotalMemory);
	print_hex("ATR", info->ATR,
			info->ulATRLen <= sizeof(info->ATR) ? info->ulATRLen : 0,
			sizeof(info->ATR));
	line("battery %lu mV, %lu%%, flags 0x%lx", info->ulBatteryVoltage,
			info->ulBatteryPercentage, info->ulBatteryFlags);
	line("body color %lu, firmware checksum 0x%lx", info->ulBodyColor,
			info->ulFirmwareChecksum);
}

static int
parse_options(int argc, char **argv)
{
	int i;
	char *end;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--login")) {
			opt.login = 1;
		} else if (!strcmp(argv[i], "--show-text")) {
			opt.show_text = 1;
		} else if (!strcmp(argv[i], "--slot") && i + 1 < argc) {
			errno = 0;
			opt.slot = strtoul(argv[++i], &end, 0);
			if (errno || *end)
				return 0;
			opt.have_slot = 1;
		} else if (!strcmp(argv[i], "--pause-ms") && i + 1 < argc) {
			errno = 0;
			opt.pause_ms = strtol(argv[++i], &end, 10);
			if (errno || *end || opt.pause_ms < 0 || opt.pause_ms > 60000)
				return 0;
		} else if (!strcmp(argv[i], "--pkcs7") && i + 1 < argc) {
			opt.pkcs7_id = argv[++i];
		} else if (!strcmp(argv[i], "--save-dir") && i + 1 < argc) {
			opt.save_dir = argv[++i];
		} else if (argv[i][0] == '-' || opt.module) {
			return 0;
		} else {
			opt.module = argv[i];
		}
	}
	if (opt.pkcs7_id && !opt.login)
		return 0;
	return opt.module != NULL;
}

static void
usage(const char *name)
{
	fprintf(stderr,
		"usage: %s [--slot ID] [--login] [--pause-ms N] [--show-text]\n"
		"          [--pkcs7 HEX_CKA_ID] [--save-dir DIR] MODULE\n\n"
		"Reads Rutoken extension data through MODULE (librtpkcs11ecp.so or\n"
		"pkcs11-spy.so) and never changes the token.\n"
		"  --slot ID        use this slot instead of the first one with a token\n"
		"  --login          ask for the user PIN (hidden, single attempt)\n"
		"  --pause-ms N     pause between steps, default 1000\n"
		"  --show-text      print certificate text instead of its outline\n"
		"  --pkcs7 ID       with --login: sign and verify fixed test data and\n"
		"                   create a CSR with the key pair and certificate\n"
		"                   whose CKA_ID is ID; asks for confirmation\n"
		"  --save-dir DIR   save the journal, signatures and CSR there\n",
		name);
}

static int
load_module(void)
{
	void *symbol;
	CK_C_GetFunctionList get_list = NULL;
	CK_RV rv;

	step("load %s", opt.module);
	module = dlopen(opt.module, RTLD_NOW | RTLD_LOCAL);
	if (!module) {
		line("dlopen failed: %s", dlerror());
		return 0;
	}
	symbol = dlsym(module, "C_GetFunctionList");
	if (!symbol) {
		line("C_GetFunctionList is not exported");
		return 0;
	}
	memcpy(&get_list, &symbol, sizeof(get_list));
	rv = get_list(&f);
	show_rv("C_GetFunctionList", rv);
	if (rv != CKR_OK || !f)
		return 0;
	line("standard table version %u.%u", f->version.major, f->version.minor);
	return 1;
}

static void
probe_extended_table(const char *when)
{
	void *symbol;
	CK_C_EX_GetFunctionListExtended get_extended = NULL;
	CK_FUNCTION_LIST_EXTENDED_PTR table = NULL;
	const CK_BYTE *pointers;
	CK_C_EX_FreeBuffer pointer;
	size_t i, present = 0;
	CK_RV rv;

	step("C_EX_GetFunctionListExtended %s", when);
	symbol = dlsym(module, "C_EX_GetFunctionListExtended");
	if (!symbol) {
		line("the module does not export C_EX_GetFunctionListExtended");
		return;
	}
	memcpy(&get_extended, &symbol, sizeof(get_extended));
	rv = get_extended(&table);
	show_rv("C_EX_GetFunctionListExtended", rv);
	if (rv != CKR_OK || !table)
		return;
	fx = table;
	line("extended table version %u.%u", table->version.major,
			table->version.minor);
	pointers = (const CK_BYTE *)table +
			offsetof(CK_FUNCTION_LIST_EXTENDED, C_EX_GetFunctionListExtended);
	for (i = 0; i < EXTENDED_FUNCTIONS; i++) {
		memcpy(&pointer, pointers + i * sizeof(pointer), sizeof(pointer));
		if (pointer)
			present++;
		else
			line("%s is NULL", extended_names[i]);
	}
	line("%zu of %d function pointers are set", present, EXTENDED_FUNCTIONS);
}

static void
probe_before_initialize(void)
{
	CK_TOKEN_INFO_EXTENDED info;
	CK_RV rv;

	step("C_EX_GetTokenInfoExtended before C_Initialize");
	if (!HAVE(fx, C_EX_GetTokenInfoExtended))
		return;
	memset(&info, 0, sizeof(info));
	info.ulSizeofThisStructure = sizeof(info);
	rv = fx->C_EX_GetTokenInfoExtended(0, &info);
	show_rv("C_EX_GetTokenInfoExtended(slot 0)", rv);
}

static int
initialize(void)
{
	CK_INFO info;
	CK_RV rv;

	step("C_Initialize and C_GetInfo");
	if (!HAVE(f, C_Initialize))
		return 0;
	rv = f->C_Initialize(NULL_PTR);
	show_rv("C_Initialize(NULL)", rv);
	if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return 0;
	if (!HAVE(f, C_GetInfo))
		return 1;
	rv = f->C_GetInfo(&info);
	show_rv("C_GetInfo", rv);
	if (rv == CKR_OK) {
		line("cryptoki %u.%u, library %u.%u", info.cryptokiVersion.major,
				info.cryptokiVersion.minor, info.libraryVersion.major,
				info.libraryVersion.minor);
		print_padded("manufacturerID", info.manufacturerID,
				sizeof(info.manufacturerID));
		print_padded("libraryDescription", info.libraryDescription,
				sizeof(info.libraryDescription));
	}
	return 1;
}

static int
select_slot(CK_SLOT_ID *slot)
{
	CK_SLOT_ID slots[32];
	CK_ULONG count = 32, i;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO info;
	CK_RV rv;

	step("slots with a token");
	if (!HAVE(f, C_GetSlotList))
		return 0;
	rv = f->C_GetSlotList(CK_TRUE, slots, &count);
	show_rv("C_GetSlotList(CK_TRUE)", rv);
	if (rv != CKR_OK)
		return 0;
	for (i = 0; i < count; i++) {
		line("slot %lu", slots[i]);
		if (f->C_GetSlotInfo &&
				f->C_GetSlotInfo(slots[i], &slot_info) == CKR_OK) {
			print_padded("  slotDescription", slot_info.slotDescription,
					sizeof(slot_info.slotDescription));
			line("  slot flags 0x%lx, hardware %u.%u, firmware %u.%u",
					slot_info.flags, slot_info.hardwareVersion.major,
					slot_info.hardwareVersion.minor,
					slot_info.firmwareVersion.major,
					slot_info.firmwareVersion.minor);
		}
		if (!f->C_GetTokenInfo)
			continue;
		rv = f->C_GetTokenInfo(slots[i], &info);
		show_rv("  C_GetTokenInfo", rv);
		if (rv != CKR_OK)
			continue;
		print_padded("  label", info.label, sizeof(info.label));
		print_padded("  manufacturerID", info.manufacturerID,
				sizeof(info.manufacturerID));
		print_padded("  model", info.model, sizeof(info.model));
		print_padded("  serialNumber", info.serialNumber,
				sizeof(info.serialNumber));
		line("  token flags 0x%lx, PIN length %lu..%lu, hardware %u.%u, "
				"firmware %u.%u", info.flags, info.ulMinPinLen,
				info.ulMaxPinLen, info.hardwareVersion.major,
				info.hardwareVersion.minor, info.firmwareVersion.major,
				info.firmwareVersion.minor);
	}
	if (opt.have_slot) {
		*slot = opt.slot;
	} else if (count > 0) {
		*slot = slots[0];
	} else {
		line("no slot with a token");
		return 0;
	}
	line("using slot %lu", *slot);
	return 1;
}

static void
probe_mechanisms(CK_SLOT_ID slot)
{
	CK_MECHANISM_TYPE mechanisms[256];
	CK_ULONG count = 256, i;
	CK_RV rv;

	step("mechanisms of slot %lu", slot);
	if (!HAVE(f, C_GetMechanismList))
		return;
	rv = f->C_GetMechanismList(slot, mechanisms, &count);
	show_rv("C_GetMechanismList", rv);
	if (rv != CKR_OK)
		return;
	printf("  %lu mechanisms:", count);
	for (i = 0; i < count; i++)
		printf("%s0x%08lx", i % 6 ? " " : "\n    ", mechanisms[i]);
	printf("\n");
	fflush(stdout);
}

static void
probe_token_info(CK_SLOT_ID slot)
{
	union {
		CK_TOKEN_INFO_EXTENDED info;
		CK_BYTE bytes[sizeof(CK_TOKEN_INFO_EXTENDED) + 64];
	} buffer;
	const size_t full = sizeof(CK_TOKEN_INFO_EXTENDED);
	const size_t shorter = offsetof(CK_TOKEN_INFO_EXTENDED, ulTokenClass);
	CK_RV rv;

	step("C_EX_GetTokenInfoExtended with ulSizeofThisStructure %zu", full);
	if (!HAVE(fx, C_EX_GetTokenInfoExtended))
		return;
	memset(buffer.bytes, SENTINEL, sizeof(buffer.bytes));
	buffer.info.ulSizeofThisStructure = full;
	rv = fx->C_EX_GetTokenInfoExtended(slot, &buffer.info);
	show_rv("C_EX_GetTokenInfoExtended", rv);
	if (rv == CKR_OK) {
		print_token_info_extended(&buffer.info);
		token_info = buffer.info;
		have_token_info = 1;
	}
	line("bytes written after the structure: %zu",
			changed_bytes(buffer.bytes, full, sizeof(buffer.bytes)));

	step("C_EX_GetTokenInfoExtended with ulSizeofThisStructure %zu "
			"(fields up to ulATRLen)", shorter);
	memset(buffer.bytes, SENTINEL, sizeof(buffer.bytes));
	buffer.info.ulSizeofThisStructure = shorter;
	rv = fx->C_EX_GetTokenInfoExtended(slot, &buffer.info);
	show_rv("C_EX_GetTokenInfoExtended", rv);
	line("returned ulSizeofThisStructure = %lu",
			buffer.info.ulSizeofThisStructure);
	line("bytes written from offset %zu to %zu: %zu", shorter, full,
			changed_bytes(buffer.bytes, shorter, full));

	step("C_EX_GetTokenInfoExtended with ulSizeofThisStructure %zu", full + 32);
	memset(buffer.bytes, SENTINEL, sizeof(buffer.bytes));
	buffer.info.ulSizeofThisStructure = full + 32;
	rv = fx->C_EX_GetTokenInfoExtended(slot, &buffer.info);
	show_rv("C_EX_GetTokenInfoExtended", rv);
	line("returned ulSizeofThisStructure = %lu",
			buffer.info.ulSizeofThisStructure);
	line("bytes written after offset %zu: %zu", full,
			changed_bytes(buffer.bytes, full, sizeof(buffer.bytes)));

	step("C_EX_GetTokenInfoExtended with ulSizeofThisStructure 0");
	memset(buffer.bytes, SENTINEL, sizeof(buffer.bytes));
	buffer.info.ulSizeofThisStructure = 0;
	rv = fx->C_EX_GetTokenInfoExtended(slot, &buffer.info);
	show_rv("C_EX_GetTokenInfoExtended", rv);
	line("returned ulSizeofThisStructure = %lu",
			buffer.info.ulSizeofThisStructure);
}

static void
probe_flash(CK_SLOT_ID slot, const char *when)
{
	CK_VOLUME_INFO_EXTENDED volumes[20];
	CK_ULONG size, count = 0, capacity, i;
	CK_RV rv;

	step("C_EX_GetDriveSize %s", when);
	if (HAVE(fx, C_EX_GetDriveSize)) {
		memset(&size, SENTINEL, sizeof(size));
		rv = fx->C_EX_GetDriveSize(slot, &size);
		show_rv("C_EX_GetDriveSize", rv);
		line("*pulDriveSize = %lu (0x%lx)", size, size);
	}

	step("C_EX_GetVolumesInfo count query %s", when);
	if (!HAVE(fx, C_EX_GetVolumesInfo))
		return;
	rv = fx->C_EX_GetVolumesInfo(slot, NULL_PTR, &count);
	show_rv("C_EX_GetVolumesInfo(NULL)", rv);
	line("*pulInfoCount = %lu", count);
	if (rv != CKR_OK || count == 0 || count > 16)
		return;
	capacity = count;

	step("C_EX_GetVolumesInfo with %lu entries %s", capacity, when);
	memset(volumes, SENTINEL, sizeof(volumes));
	count = capacity;
	rv = fx->C_EX_GetVolumesInfo(slot, volumes, &count);
	show_rv("C_EX_GetVolumesInfo", rv);
	line("*pulInfoCount = %lu", count);
	for (i = 0; rv == CKR_OK && i < count && i < capacity; i++)
		line("volume %lu: size %lu MB, access 0x%lx (%s), owner 0x%lx, "
				"flags 0x%lx", volumes[i].idVolume, volumes[i].ulVolumeSize,
				volumes[i].accessMode,
				access_mode_name(volumes[i].accessMode),
				volumes[i].volumeOwner, volumes[i].flags);
	line("bytes written after %lu entries: %zu", capacity,
			changed_bytes(volumes, capacity * sizeof(volumes[0]),
					sizeof(volumes)));
	if (capacity < 2)
		return;

	step("C_EX_GetVolumesInfo with %lu entries (one short) %s",
			capacity - 1, when);
	memset(volumes, SENTINEL, sizeof(volumes));
	count = capacity - 1;
	rv = fx->C_EX_GetVolumesInfo(slot, volumes, &count);
	show_rv("C_EX_GetVolumesInfo", rv);
	line("*pulInfoCount = %lu", count);
	line("bytes written after %lu entries: %zu", capacity - 1,
			changed_bytes(volumes, (capacity - 1) * sizeof(volumes[0]),
					sizeof(volumes)));
}

static int
read_tlv(const CK_BYTE *data, size_t end, size_t *position, unsigned int *tag,
		size_t *length)
{
	size_t p = *position, value_length;

	if (p + 2 > end)
		return 0;
	*tag = data[p++];
	value_length = data[p++];
	if (value_length == 0x81) {
		if (p + 1 > end)
			return 0;
		value_length = data[p++];
	} else if (value_length == 0x82) {
		if (p + 2 > end)
			return 0;
		value_length = ((size_t)data[p] << 8) | data[p + 1];
		p += 2;
	} else if (value_length > 0x7F) {
		return 0;
	}
	if (value_length > end - p)
		return 0;
	*position = p;
	*length = value_length;
	return 1;
}

static void
describe_journal(const CK_BYTE *data, size_t size)
{
	size_t position = 0, length, end, value;
	unsigned int tag;

	if (!read_tlv(data, size, &position, &tag, &length) || tag != 0x80) {
		line("the journal is not a 0x80 TLV");
		print_hex("journal", data, size, 512);
		return;
	}
	line("outer tag 0x80 with %zu bytes, record size %zu", length, size);
	end = position + length;
	while (position < end) {
		if (!read_tlv(data, end, &position, &tag, &length)) {
			line("malformed inner TLV at offset %zu", position);
			break;
		}
		value = position;
		if (tag == 0xAA) {
			line("tag 0xAA hash of the signed data: %zu bytes", length);
		} else if (tag == 0xB6) {
			line("tag 0xB6 signature: %zu bytes", length);
		} else if (tag == 0x85 && length == 12) {
			line("tag 0x85 operation 0x%02x, key type 0x%02x, key purpose "
					"0x%02x, operation flags 0x%02x, reserved %02x %02x",
					data[value], data[value + 1], data[value + 2],
					data[value + 3], data[value + 4], data[value + 5]);
			line("  key id 0x%04x, signature counter %lu",
					(unsigned int)(data[value + 6] << 8 | data[value + 7]),
					(unsigned long)data[value + 8] << 24 |
					(unsigned long)data[value + 9] << 16 |
					(unsigned long)data[value + 10] << 8 |
					(unsigned long)data[value + 11]);
		} else if (tag == 0x83) {
			print_hex("tag 0x83 device id", data + value, length, 32);
		} else {
			line("tag 0x%02x with %zu bytes", tag, length);
			print_hex("value", data + value, length, 64);
		}
		position = value + length;
	}
	if (end != size)
		line("%zu bytes follow the outer TLV", size - end);
}

static void
probe_journal(CK_SLOT_ID slot, const char *when)
{
	CK_BYTE *buffer;
	CK_ULONG length = 0, size;
	CK_RV rv;

	step("C_EX_GetJournal size query %s", when);
	if (!HAVE(fx, C_EX_GetJournal))
		return;
	rv = fx->C_EX_GetJournal(slot, NULL_PTR, &length);
	show_rv("C_EX_GetJournal(NULL)", rv);
	line("*pulJournalSize = %lu", length);
	if (rv != CKR_OK || length == 0 || length > 65536)
		return;
	size = length;
	buffer = malloc(size + 64);
	if (!buffer)
		return;

	step("C_EX_GetJournal with a %lu-byte buffer %s", size, when);
	memset(buffer, SENTINEL, size + 64);
	length = size;
	rv = fx->C_EX_GetJournal(slot, buffer, &length);
	show_rv("C_EX_GetJournal", rv);
	line("*pulJournalSize = %lu", length);
	if (rv == CKR_OK && length <= size) {
		describe_journal(buffer, length);
		save_file("journal.bin", buffer, length);
	}
	line("bytes written after the buffer: %zu",
			changed_bytes(buffer, size, size + 64));

	if (size > 1) {
		step("C_EX_GetJournal with a %lu-byte buffer %s", size - 1, when);
		memset(buffer, SENTINEL, size + 64);
		length = size - 1;
		rv = fx->C_EX_GetJournal(slot, buffer, &length);
		show_rv("C_EX_GetJournal", rv);
		line("*pulJournalSize = %lu", length);
		line("bytes written after %lu: %zu", size - 1,
				changed_bytes(buffer, size - 1, size + 64));
	}
	free(buffer);
}

static void
probe_forced_pin_change(CK_SLOT_ID slot)
{
	const CK_USER_TYPE users[] = { CKU_USER, CKU_SO };
	CK_USER_TYPE user;
	size_t i;
	CK_RV rv;

	for (i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
		step("C_EX_SlotManage(MODE_GET_PIN_SET_TO_BE_CHANGED, %s)",
				users[i] == CKU_USER ? "CKU_USER" : "CKU_SO");
		if (!HAVE(fx, C_EX_SlotManage))
			return;
		user = users[i];
		rv = fx->C_EX_SlotManage(slot, MODE_GET_PIN_SET_TO_BE_CHANGED, &user);
		show_rv("C_EX_SlotManage", rv);
		if (user != users[i])
			line("the library changed *pValue to 0x%lx", user);
	}
}

static CK_SESSION_HANDLE
open_session(CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv;

	step("C_OpenSession (read-only)");
	if (!HAVE(f, C_OpenSession))
		return CK_INVALID_HANDLE;
	rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL, &session);
	show_rv("C_OpenSession", rv);
	return rv == CKR_OK ? session : CK_INVALID_HANDLE;
}

static void
probe_token_name(CK_SESSION_HANDLE session)
{
	CK_BYTE buffer[512];
	CK_ULONG length = 0, needed;
	CK_RV rv;

	step("C_EX_GetTokenName size query");
	if (!HAVE(fx, C_EX_GetTokenName))
		return;
	rv = fx->C_EX_GetTokenName(session, NULL_PTR, &length);
	show_rv("C_EX_GetTokenName(NULL)", rv);
	line("*pulLabelLen = %lu", length);
	if (rv != CKR_OK || length == 0 || length > 256)
		return;
	needed = length;

	step("C_EX_GetTokenName with a %lu-byte buffer", needed);
	memset(buffer, SENTINEL, sizeof(buffer));
	rv = fx->C_EX_GetTokenName(session, buffer, &length);
	show_rv("C_EX_GetTokenName", rv);
	line("*pulLabelLen = %lu", length);
	if (rv == CKR_OK && length <= needed) {
		line("name: \"%.*s\"", (int)length, (const char *)buffer);
		line("last byte 0x%02x, NUL inside the length: %s",
				length ? buffer[length - 1] : 0,
				memchr(buffer, 0, length) ? "yes" : "no");
	}
	line("bytes written after the buffer: %zu",
			changed_bytes(buffer, needed, sizeof(buffer)));
	if (needed < 2)
		return;

	step("C_EX_GetTokenName with a %lu-byte buffer", needed - 1);
	memset(buffer, SENTINEL, sizeof(buffer));
	length = needed - 1;
	rv = fx->C_EX_GetTokenName(session, buffer, &length);
	show_rv("C_EX_GetTokenName", rv);
	line("*pulLabelLen = %lu", length);
	line("bytes written after %lu: %zu", needed - 1,
			changed_bytes(buffer, needed - 1, sizeof(buffer)));
}

static void
probe_license(CK_SESSION_HANDLE session, CK_ULONG number, int full)
{
	CK_BYTE buffer[256];
	CK_ULONG length = 0, used, i, nonzero = 0;
	CK_RV rv;

	step("C_EX_GetLicense(%lu) size query", number);
	if (!HAVE(fx, C_EX_GetLicense))
		return;
	rv = fx->C_EX_GetLicense(session, number, NULL_PTR, &length);
	show_rv("C_EX_GetLicense(NULL)", rv);
	line("*pulLicenseLen = %lu", length);
	if (!full)
		return;
	used = rv == CKR_OK && length > 0 && length <= 128 ? length : 72;

	step("C_EX_GetLicense(%lu) with a %lu-byte buffer", number, used);
	memset(buffer, SENTINEL, sizeof(buffer));
	length = used;
	rv = fx->C_EX_GetLicense(session, number, buffer, &length);
	show_rv("C_EX_GetLicense", rv);
	line("*pulLicenseLen = %lu", length);
	if (rv == CKR_OK) {
		for (i = 0; i < length && i < used; i++)
			if (buffer[i])
				nonzero++;
		line("%lu of %lu bytes are non-zero; the content is not printed",
				nonzero, length < used ? length : used);
	}
	line("bytes written after %lu: %zu", used,
			changed_bytes(buffer, used, sizeof(buffer)));

	step("C_EX_GetLicense(%lu) with an 8-byte buffer", number);
	memset(buffer, SENTINEL, sizeof(buffer));
	length = 8;
	rv = fx->C_EX_GetLicense(session, number, buffer, &length);
	show_rv("C_EX_GetLicense", rv);
	line("*pulLicenseLen = %lu", length);
	line("bytes written after 8: %zu", changed_bytes(buffer, 8, sizeof(buffer)));
}

static CK_ULONG
find_objects(CK_SESSION_HANDLE session, CK_ATTRIBUTE *pattern, CK_ULONG count,
		CK_OBJECT_HANDLE *objects, CK_ULONG max)
{
	CK_ULONG found = 0;
	CK_RV rv;

	if (!HAVE(f, C_FindObjectsInit) || !HAVE(f, C_FindObjects) ||
			!HAVE(f, C_FindObjectsFinal))
		return 0;
	rv = f->C_FindObjectsInit(session, pattern, count);
	if (rv != CKR_OK) {
		show_rv("C_FindObjectsInit", rv);
		return 0;
	}
	rv = f->C_FindObjects(session, objects, max, &found);
	if (rv != CKR_OK) {
		show_rv("C_FindObjects", rv);
		found = 0;
	}
	f->C_FindObjectsFinal(session);
	return found;
}

static int
printable(const CK_BYTE *value, CK_ULONG length)
{
	CK_ULONG i;

	for (i = 0; i < length; i++)
		if (value[i] < 0x20 && value[i] != '\t')
			return 0;
	return length > 0;
}

static void
print_attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
		CK_ATTRIBUTE_TYPE type, const char *name, int as_hex)
{
	CK_BYTE value[512];
	CK_ATTRIBUTE attribute = { type, NULL_PTR, 0 };
	CK_ULONG number, i;
	CK_RV rv;

	rv = f->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK || attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		line("%s: %s", name, rv_name(rv));
		return;
	}
	if (attribute.ulValueLen > sizeof(value)) {
		line("%s: %lu bytes, not read", name, attribute.ulValueLen);
		return;
	}
	attribute.pValue = value;
	rv = f->C_GetAttributeValue(session, object, &attribute, 1);
	if (rv != CKR_OK) {
		line("%s: %s", name, rv_name(rv));
		return;
	}
	if (as_hex) {
		print_hex(name, value, attribute.ulValueLen, sizeof(value));
	} else if (attribute.ulValueLen == 1) {
		line("%s: 0x%02x", name, value[0]);
	} else if (attribute.ulValueLen == sizeof(CK_ULONG)) {
		memcpy(&number, value, sizeof(number));
		line("%s: 0x%lx (%lu)", name, number, number);
	} else if (printable(value, attribute.ulValueLen)) {
		line("%s: \"%.*s\"", name, (int)attribute.ulValueLen,
				(const char *)value);
	} else if (attribute.ulValueLen % sizeof(CK_ULONG) == 0) {
		printf("  %s:", name);
		for (i = 0; i < attribute.ulValueLen / sizeof(CK_ULONG); i++) {
			memcpy(&number, value + i * sizeof(number), sizeof(number));
			printf(" 0x%lx", number);
		}
		printf("\n");
		fflush(stdout);
	} else {
		print_hex(name, value, attribute.ulValueLen, sizeof(value));
	}
}

static void
probe_hardware_features(CK_SESSION_HANDLE session)
{
	static const struct {
		CK_ULONG suffix;
		int array;
		const char *name;
	} attributes[] = {
		{ 0x3000, 0, "SECURE_MESSAGING_AVAILABLE" },
		{ 0x3001, 0, "CURRENT_SECURE_MESSAGING_MODE" },
		{ 0x3002, 0, "SUPPORTED_SECURE_MESSAGING_MODES" },
		{ 0x3003, 0, "CURRENT_TOKEN_INTERFACE" },
		{ 0x3004, 0, "SUPPORTED_TOKEN_INTERFACE" },
		{ 0x3005, 0, "EXTERNAL_AUTHENTICATION" },
		{ 0x3006, 0, "BIOMETRIC_AUTHENTICATION" },
		{ 0x3007, 0, "SUPPORT_CUSTOM_PIN" },
		{ 0x3008, 0, "CUSTOM_ADMIN_PIN" },
		{ 0x3009, 0, "CUSTOM_USER_PIN" },
		{ 0x300A, 0, "SUPPORT_INTERNAL_TRUSTED_CERTS" },
		{ 0x300B, 0, "SUPPORT_FKC2" },
		{ 0x300D, 0, "SUPPORT_HW_KDF_TREE" },
		{ 0x300E, 0, "SUPPORT_KIMP15" },
		{ 0x300F, 0, "FLASH_DRIVE_AVAILABLE" },
		{ 0x3010, 0, "MODEL_NAME" },
		{ 0x3011, 0, "SUPPORT_HW_AES_WRAP" },
		{ 0x3012, 0, "SUPPORT_REPAIR_FORMAT" },
		{ 0x3013, 1, "PROTECTION_FEATURES" },
		{ 0x3015, 1, "SUPPORTED_EMITENT_KEY_ALGS" }
	};
	CK_OBJECT_CLASS object_class = CKO_HW_FEATURE;
	CK_HW_FEATURE_TYPE feature = CKH_VENDOR_TOKEN_INFO;
	CK_ATTRIBUTE pattern[] = {
		{ CKA_CLASS, &object_class, sizeof(object_class) },
		{ CKA_HW_FEATURE_TYPE, &feature, sizeof(feature) }
	};
	CK_OBJECT_HANDLE objects[4];
	CK_ULONG count, i;
	size_t j;
	char name[64];

	step("vendor hardware feature object CKH_VENDOR_TOKEN_INFO");
	if (!HAVE(f, C_GetAttributeValue))
		return;
	count = find_objects(session, pattern, 2, objects, 4);
	line("%lu objects", count);
	for (i = 0; i < count; i++) {
		line("object %lu", objects[i]);
		for (j = 0; j < sizeof(attributes) / sizeof(attributes[0]); j++) {
			snprintf(name, sizeof(name), "  CKA_VENDOR_%s", attributes[j].name);
			print_attribute(session, objects[i], CKA_VENDOR_DEFINED |
					(attributes[j].array ? CKF_ARRAY_ATTRIBUTE : 0) |
					attributes[j].suffix, name, 0);
		}
	}
}

static void
describe_text(const CK_CHAR *text, CK_ULONG length)
{
	CK_ULONG i, start = 0, lines = 0, prefix;

	line("NUL bytes inside the length: %s, last byte 0x%02x",
			memchr(text, 0, length) ? "yes" : "no",
			length ? text[length - 1] : 0);
	if (opt.show_text) {
		printf("%.*s\n", (int)length, (const char *)text);
		fflush(stdout);
		return;
	}
	line("outline (text before ':' or '=' of each line; use --show-text "
			"to print everything):");
	for (i = 0; i <= length; i++) {
		if (i < length && text[i] != '\n' && text[i] != '\0')
			continue;
		for (prefix = start; prefix < i && text[prefix] != ':' &&
				text[prefix] != '='; prefix++)
			;
		if (prefix < i)
			line("  | %.*s ...", (int)(prefix - start > 48 ? 48 : prefix - start),
					(const char *)text + start);
		else if (i > start)
			line("  | <%lu characters without ':' or '='>", i - start);
		lines++;
		start = i + 1;
		if (i < length && text[i] == '\0')
			break;
	}
	line("%lu lines", lines);
}

static void
probe_certificate_text(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE certificate)
{
	CK_CHAR_PTR text = NULL;
	CK_ULONG length = 0;
	CK_RV rv;

	step("C_EX_GetCertificateInfoText(certificate %lu)", certificate);
	if (!HAVE(fx, C_EX_GetCertificateInfoText))
		return;
	rv = fx->C_EX_GetCertificateInfoText(session, certificate, &text, &length);
	show_rv("C_EX_GetCertificateInfoText", rv);
	line("*pInfo %s, *pulInfoLen = %lu", text ? "set" : "NULL", length);
	if (rv != CKR_OK || !text)
		return;
	describe_text(text, length);
	if (HAVE(fx, C_EX_FreeBuffer))
		show_rv("C_EX_FreeBuffer(info)", fx->C_EX_FreeBuffer(text));
}

static void
probe_certificates(CK_SESSION_HANDLE session, const char *when)
{
	CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE pattern[] = { { CKA_CLASS, &object_class, sizeof(object_class) } };
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	CK_ULONG count, i, j;
	CK_ATTRIBUTE value = { CKA_VALUE, NULL_PTR, 0 };

	step("certificates %s", when);
	if (!HAVE(f, C_GetAttributeValue))
		return;
	count = find_objects(session, pattern, 1, objects, MAX_OBJECTS);
	line("%lu certificates", count);
	for (i = 0; i < count; i++) {
		for (j = 0; j < seen_certificate_count; j++)
			if (seen_certificates[j] == objects[i])
				break;
		if (j < seen_certificate_count ||
				seen_certificate_count == MAX_OBJECTS)
			continue;
		seen_certificates[seen_certificate_count++] = objects[i];
		line("certificate %lu", objects[i]);
		print_attribute(session, objects[i], CKA_ID, "  CKA_ID", 1);
		print_attribute(session, objects[i], CKA_LABEL, "  CKA_LABEL", 0);
		print_attribute(session, objects[i], CKA_CERTIFICATE_TYPE,
				"  CKA_CERTIFICATE_TYPE", 0);
		value.ulValueLen = 0;
		if (f->C_GetAttributeValue(session, objects[i], &value, 1) == CKR_OK)
			line("  CKA_VALUE: %lu bytes, not printed", value.ulValueLen);
		probe_certificate_text(session, objects[i]);
	}
}

static void
probe_authenticators(CK_SESSION_HANDLE session, const char *when)
{
	CK_OBJECT_CLASS object_class = CKO_VENDOR_AUTHENTICATION_FACTOR;
	CK_ATTRIBUTE pattern[] = { { CKA_CLASS, &object_class, sizeof(object_class) } };
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	CK_ULONG count, i;

	step("authentication objects %s", when);
	if (!HAVE(f, C_GetAttributeValue))
		return;
	count = find_objects(session, pattern, 1, objects, MAX_OBJECTS);
	line("%lu objects", count);
	for (i = 0; i < count; i++) {
		line("object %lu", objects[i]);
		print_attribute(session, objects[i], CKA_ID, "  CKA_ID", 1);
		print_attribute(session, objects[i], CKA_LABEL, "  CKA_LABEL", 0);
		print_attribute(session, objects[i],
				CKA_VENDOR_AUTHENTICATION_FACTOR_TYPE,
				"  CKA_VENDOR_AUTHENTICATION_FACTOR_TYPE", 0);
		print_attribute(session, objects[i], CKA_VENDOR_FP_CONVOLUTIONS_COUNT,
				"  CKA_VENDOR_FP_CONVOLUTIONS_COUNT", 0);
		print_attribute(session, objects[i],
				CKA_VENDOR_FINGERPRINT_CONVOLUTIONS_ID,
				"  CKA_VENDOR_FINGERPRINT_CONVOLUTIONS_ID", 0);
		print_attribute(session, objects[i], CKA_VENDOR_MAX_RETRY_COUNT,
				"  CKA_VENDOR_MAX_RETRY_COUNT", 0);
		print_attribute(session, objects[i], CKA_VENDOR_RETRY_COUNT_LEFT,
				"  CKA_VENDOR_RETRY_COUNT_LEFT", 0);
		print_attribute(session, objects[i], CKA_VENDOR_BIO_DATA_ID,
				"  CKA_VENDOR_BIO_DATA_ID", 1);
	}
}

static void
probe_keys(CK_SESSION_HANDLE session)
{
	const CK_OBJECT_CLASS classes[] = { CKO_PRIVATE_KEY, CKO_PUBLIC_KEY };
	CK_OBJECT_CLASS object_class;
	CK_ATTRIBUTE pattern[] = { { CKA_CLASS, &object_class, sizeof(object_class) } };
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	CK_ULONG count, i;
	size_t c;

	step("key pairs after login");
	if (!HAVE(f, C_GetAttributeValue))
		return;
	for (c = 0; c < sizeof(classes) / sizeof(classes[0]); c++) {
		object_class = classes[c];
		count = find_objects(session, pattern, 1, objects, MAX_OBJECTS);
		line("%lu %s keys", count, c == 0 ? "private" : "public");
		for (i = 0; i < count; i++) {
			line("key %lu", objects[i]);
			print_attribute(session, objects[i], CKA_KEY_TYPE,
					"  CKA_KEY_TYPE", 0);
			print_attribute(session, objects[i], CKA_ID, "  CKA_ID", 1);
			print_attribute(session, objects[i], CKA_LABEL, "  CKA_LABEL", 0);
			if (c == 0)
				print_attribute(session, objects[i], CKA_VENDOR_KEY_JOURNAL,
						"  CKA_VENDOR_KEY_JOURNAL", 0);
		}
	}
}

static int
read_tty_line(const char *prompt, char *buffer, size_t size, int hidden)
{
	struct termios saved, quiet;
	FILE *tty;
	int ok = 0;

	tty = fopen("/dev/tty", "r+");
	if (!tty) {
		line("cannot open /dev/tty: %s", strerror(errno));
		return 0;
	}
	fputs(prompt, tty);
	fflush(tty);
	if (!hidden) {
		ok = fgets(buffer, (int)size, tty) != NULL;
	} else if (!tcgetattr(fileno(tty), &saved)) {
		quiet = saved;
		quiet.c_lflag &= ~(tcflag_t)ECHO;
		quiet.c_lflag |= ECHONL;
		if (!tcsetattr(fileno(tty), TCSAFLUSH, &quiet)) {
			ok = fgets(buffer, (int)size, tty) != NULL;
			tcsetattr(fileno(tty), TCSAFLUSH, &saved);
		}
	}
	fclose(tty);
	if (!ok)
		return 0;
	buffer[strcspn(buffer, "\r\n")] = '\0';
	return buffer[0] != '\0';
}

static int
login(CK_SESSION_HANDLE session)
{
	char pin[128];
	CK_RV rv;

	step("C_Login(CKU_USER)");
	if (!HAVE(f, C_Login))
		return 0;
	if (have_token_info && token_info.ulUserRetryCountLeft <= 1) {
		line("%lu user PIN attempts left: login skipped",
				token_info.ulUserRetryCountLeft);
		return 0;
	}
	if (!read_tty_line("User PIN (hidden, a single attempt is made): ", pin,
			sizeof(pin), 1)) {
		line("no PIN entered: login skipped");
		return 0;
	}
	rv = f->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin,
			(CK_ULONG)strlen(pin));
	wipe(pin, sizeof(pin));
	show_rv("C_Login(CKU_USER, PIN not printed)", rv);
	return rv == CKR_OK;
}

static int
hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t
parse_hex(const char *text, CK_BYTE *out, size_t max)
{
	size_t length = 0;
	int high, low;

	while (text[0] && length < max) {
		high = hex_digit(text[0]);
		low = text[1] ? hex_digit(text[1]) : -1;
		if (high < 0 || low < 0)
			return 0;
		out[length++] = (CK_BYTE)(high << 4 | low);
		text += 2;
	}
	return text[0] ? 0 : length;
}

static CK_OBJECT_HANDLE
find_by_id(CK_SESSION_HANDLE session, CK_OBJECT_CLASS object_class,
		CK_BYTE *id, CK_ULONG id_length)
{
	CK_ATTRIBUTE pattern[] = {
		{ CKA_CLASS, &object_class, sizeof(object_class) },
		{ CKA_ID, id, id_length }
	};
	CK_OBJECT_HANDLE objects[2];
	CK_ULONG count = find_objects(session, pattern, 2, objects, 2);

	if (count > 1)
		line("several objects of class 0x%lx share this CKA_ID; using the first",
				object_class);
	return count ? objects[0] : CK_INVALID_HANDLE;
}

static CK_BYTE_PTR
sign(CK_SESSION_HANDLE session, const char *title, CK_OBJECT_HANDLE certificate,
		CK_OBJECT_HANDLE key, CK_OBJECT_HANDLE_PTR chain, CK_ULONG chain_length,
		CK_ULONG flags, CK_ULONG *length, int keep)
{
	CK_BYTE data[sizeof(test_data)];
	CK_BYTE_PTR envelope = NULL;
	CK_RV rv;

	step("C_EX_PKCS7Sign: %s, flags 0x%lx", title, flags);
	memcpy(data, test_data, sizeof(data));
	*length = 0;
	rv = fx->C_EX_PKCS7Sign(session, data, sizeof(test_data) - 1, certificate,
			&envelope, length, key, chain, chain_length, flags);
	show_rv("C_EX_PKCS7Sign", rv);
	line("*ppEnvelope %s, *pEnvelopeLen = %lu", envelope ? "set" : "NULL",
			*length);
	if (rv != CKR_OK || !envelope)
		return NULL;
	if (keep)
		return envelope;
	show_rv("C_EX_FreeBuffer(envelope)", fx->C_EX_FreeBuffer(envelope));
	return NULL;
}

static void
release_verify_outputs(CK_RV rv, CK_BYTE_PTR data, CK_VENDOR_BUFFER_PTR signers,
		CK_ULONG count)
{
	CK_ULONG i;

	if (rv != CKR_OK && rv != CKR_CERT_CHAIN_NOT_VERIFIED) {
		line("outputs after the error: data %s, signers %s, count %lu; "
				"not released", data ? "set" : "NULL",
				signers ? "set" : "NULL", count);
		return;
	}
	for (i = 0; signers && i < count && i < 16; i++) {
		line("signer certificate %lu: %lu bytes", i, signers[i].ulSize);
		if (signers[i].pData)
			show_rv("C_EX_FreeBuffer(signer certificate)",
					fx->C_EX_FreeBuffer(signers[i].pData));
	}
	if (signers)
		show_rv("C_EX_FreeBuffer(signer array)",
				fx->C_EX_FreeBuffer((CK_BYTE_PTR)signers));
	if (data)
		show_rv("C_EX_FreeBuffer(data)", fx->C_EX_FreeBuffer(data));
}

static void
verify_attached(CK_SESSION_HANDLE session, const char *title, CK_BYTE_PTR cms,
		CK_ULONG cms_length, CK_VENDOR_X509_STORE *store, CK_FLAGS flags)
{
	CK_BYTE_PTR data = NULL;
	CK_ULONG data_length = 0, count = 0;
	CK_VENDOR_BUFFER_PTR signers = NULL;
	CK_RV rv;

	step("C_EX_PKCS7VerifyInit and C_EX_PKCS7Verify: %s", title);
	if (!cms) {
		line("no attached signature to verify");
		return;
	}
	rv = fx->C_EX_PKCS7VerifyInit(session, cms, cms_length, store,
			OPTIONAL_CRL_CHECK, flags);
	show_rv("C_EX_PKCS7VerifyInit", rv);
	if (rv != CKR_OK)
		return;
	rv = fx->C_EX_PKCS7Verify(session, &data, &data_length, &signers, &count);
	show_rv("C_EX_PKCS7Verify", rv);
	line("data %lu bytes, %s; %lu signer certificates", data_length,
			data && data_length == sizeof(test_data) - 1 &&
			!memcmp(data, test_data, data_length) ?
			"equal to the signed data" : "not the signed data", count);
	release_verify_outputs(rv, data, signers, count);
}

static void
verify_detached(CK_SESSION_HANDLE session, const char *title, CK_BYTE_PTR cms,
		CK_ULONG cms_length, CK_VENDOR_X509_STORE *store, int modify)
{
	CK_BYTE data[sizeof(test_data)];
	CK_ULONG half = (sizeof(test_data) - 1) / 2, count = 0;
	CK_VENDOR_BUFFER_PTR signers = NULL;
	CK_RV rv;

	step("C_EX_PKCS7VerifyInit, two C_EX_PKCS7VerifyUpdate and "
			"C_EX_PKCS7VerifyFinal: %s", title);
	if (!cms) {
		line("no detached signature to verify");
		return;
	}
	memcpy(data, test_data, sizeof(data));
	if (modify)
		data[0] ^= 1;
	rv = fx->C_EX_PKCS7VerifyInit(session, cms, cms_length, store,
			OPTIONAL_CRL_CHECK, 0);
	show_rv("C_EX_PKCS7VerifyInit", rv);
	if (rv != CKR_OK)
		return;
	rv = fx->C_EX_PKCS7VerifyUpdate(session, data, half);
	show_rv("C_EX_PKCS7VerifyUpdate(first part)", rv);
	if (rv == CKR_OK) {
		rv = fx->C_EX_PKCS7VerifyUpdate(session, data + half,
				sizeof(test_data) - 1 - half);
		show_rv("C_EX_PKCS7VerifyUpdate(second part)", rv);
	}
	rv = fx->C_EX_PKCS7VerifyFinal(session, &signers, &count);
	show_rv("C_EX_PKCS7VerifyFinal", rv);
	release_verify_outputs(rv, NULL, signers, count);
}

static void
create_csr(CK_SESSION_HANDLE session, const char *title,
		CK_OBJECT_HANDLE public_key, CK_CHAR_PTR *dn, CK_ULONG dn_count,
		CK_CHAR_PTR *extensions, CK_ULONG extension_count, const char *file)
{
	CK_BYTE_PTR csr = NULL;
	CK_ULONG length = 0;
	CK_RV rv;

	step("C_EX_CreateCSR: %s", title);
	rv = fx->C_EX_CreateCSR(session, public_key, dn, dn_count, &csr, &length,
			CK_INVALID_HANDLE, NULL_PTR, 0, extensions, extension_count);
	show_rv("C_EX_CreateCSR", rv);
	line("*pCsr %s, *pulCsrLength = %lu", csr ? "set" : "NULL", length);
	if (rv != CKR_OK || !csr)
		return;
	if (file)
		save_file(file, csr, length);
	show_rv("C_EX_FreeBuffer(csr)", fx->C_EX_FreeBuffer(csr));
}

static void
probe_pkcs7(CK_SESSION_HANDLE session)
{
	static CK_CHAR cn_type[] = "CN";
	static CK_CHAR cn_value[] = "OpenSC Rutoken probe";
	static CK_CHAR key_usage[] = "keyUsage";
	static CK_CHAR key_usage_value[] = "digitalSignature";
	CK_CHAR_PTR dn[] = { cn_type, cn_value };
	CK_CHAR_PTR extensions[] = { key_usage, key_usage_value };
	CK_BYTE id[128], *certificate_value = NULL;
	CK_ULONG id_length, attached_length = 0, detached_length = 0, length;
	CK_OBJECT_HANDLE certificate, private_key, public_key;
	CK_BYTE_PTR attached, detached;
	CK_ATTRIBUTE value = { CKA_VALUE, NULL_PTR, 0 };
	CK_VENDOR_BUFFER trusted;
	CK_VENDOR_X509_STORE store, empty;
	CK_BYTE_PTR data = NULL;
	CK_VENDOR_BUFFER_PTR signers = NULL;
	CK_ULONG count = 0;
	char answer[16];
	CK_RV rv;

	step("--pkcs7: objects with CKA_ID %s", opt.pkcs7_id);
	if (!HAVE(f, C_GetAttributeValue) || !HAVE(fx, C_EX_PKCS7Sign) ||
			!HAVE(fx, C_EX_FreeBuffer) || !HAVE(fx, C_EX_PKCS7VerifyInit) ||
			!HAVE(fx, C_EX_PKCS7Verify) || !HAVE(fx, C_EX_PKCS7VerifyUpdate) ||
			!HAVE(fx, C_EX_PKCS7VerifyFinal) || !HAVE(fx, C_EX_CreateCSR))
		return;
	id_length = parse_hex(opt.pkcs7_id, id, sizeof(id));
	if (!id_length) {
		line("--pkcs7 needs an even number of hexadecimal digits");
		return;
	}
	certificate = find_by_id(session, CKO_CERTIFICATE, id, id_length);
	private_key = find_by_id(session, CKO_PRIVATE_KEY, id, id_length);
	public_key = find_by_id(session, CKO_PUBLIC_KEY, id, id_length);
	line("certificate %lu, private key %lu, public key %lu", certificate,
			private_key, public_key);
	if (certificate == CK_INVALID_HANDLE || private_key == CK_INVALID_HANDLE) {
		line("a certificate and a private key with this CKA_ID are required");
		return;
	}
	print_attribute(session, private_key, CKA_KEY_TYPE, "CKA_KEY_TYPE", 0);
	if (f->C_GetAttributeValue(session, certificate, &value, 1) == CKR_OK &&
			value.ulValueLen > 0 && value.ulValueLen < 65536)
		certificate_value = malloc(value.ulValueLen);
	value.pValue = certificate_value;
	if (!certificate_value ||
			f->C_GetAttributeValue(session, certificate, &value, 1) != CKR_OK) {
		line("cannot read the certificate value");
		free(certificate_value);
		return;
	}
	if (!read_tty_line("The probe will sign fixed test data with this key "
			"five times. This replaces\nthe journal record and increases the "
			"signature counter. Type SIGN to continue: ",
			answer, sizeof(answer), 0) || strcmp(answer, "SIGN")) {
		line("not confirmed: PKCS #7 and CSR checks skipped");
		free(certificate_value);
		return;
	}

	attached = sign(session, "attached, software hash, key found by the "
			"certificate", certificate, CK_INVALID_HANDLE, NULL_PTR, 0, 0,
			&attached_length, 1);
	detached = sign(session, "detached, software hash", certificate,
			CK_INVALID_HANDLE, NULL_PTR, 0, PKCS7_DETACHED_SIGNATURE,
			&detached_length, 1);
	sign(session, "attached, hardware hash", certificate, CK_INVALID_HANDLE,
			NULL_PTR, 0, USE_HARDWARE_HASH, &length, 0);
	sign(session, "attached, explicit private key handle", certificate,
			private_key, NULL_PTR, 0, 0, &length, 0);
	sign(session, "attached, the certificate passed as chain", certificate,
			CK_INVALID_HANDLE, &certificate, 1, 0, &length, 0);
	if (attached)
		save_file("pkcs7-attached.der", attached, attached_length);
	if (detached)
		save_file("pkcs7-detached.der", detached, detached_length);

	trusted.pData = certificate_value;
	trusted.ulSize = value.ulValueLen;
	memset(&store, 0, sizeof(store));
	store.pTrustedCertificates = &trusted;
	store.ulTrustedCertificateCount = 1;
	memset(&empty, 0, sizeof(empty));
	verify_attached(session, "signer certificate trusted", attached,
			attached_length, &store, 0);
	verify_attached(session, "empty store, CKF_VENDOR_CHECK_SIGNATURE_ONLY",
			attached, attached_length, &empty, CKF_VENDOR_CHECK_SIGNATURE_ONLY);
	verify_detached(session, "original data", detached, detached_length,
			&store, 0);
	verify_detached(session, "modified data", detached, detached_length,
			&store, 1);

	step("C_EX_PKCS7Verify without C_EX_PKCS7VerifyInit");
	rv = fx->C_EX_PKCS7Verify(session, &data, &length, &signers, &count);
	show_rv("C_EX_PKCS7Verify", rv);
	release_verify_outputs(rv, data, signers, count);

	if (attached)
		show_rv("C_EX_FreeBuffer(attached)", fx->C_EX_FreeBuffer(attached));
	if (detached)
		show_rv("C_EX_FreeBuffer(detached)", fx->C_EX_FreeBuffer(detached));
	free(certificate_value);

	if (public_key == CK_INVALID_HANDLE) {
		line("no public key object with this CKA_ID: CSR checks skipped");
		return;
	}
	create_csr(session, "CN only", public_key, dn, 2, NULL_PTR, 0, "csr.der");
	create_csr(session, "CN and keyUsage extension", public_key, dn, 2,
			extensions, 2, "csr-key-usage.der");
	create_csr(session, "odd DN string count", public_key, dn, 1, NULL_PTR, 0,
			NULL);
}

static void
probe_local_pins(CK_SLOT_ID slot)
{
	CK_LOCAL_PIN_INFO pins[32], expected;
	size_t i, changed = 0;
	CK_RV rv;

	step("C_EX_SlotManage(MODE_GET_LOCAL_PIN_INFO) with 32 entries, "
			"ulPinID 0x03..0x22");
	if (!HAVE(fx, C_EX_SlotManage))
		return;
	line("the buffer semantics are undocumented; if the probe stops here, "
			"this step is the answer");
	memset(pins, SENTINEL, sizeof(pins));
	for (i = 0; i < 32; i++)
		pins[i].ulPinID = 0x03 + i;
	rv = fx->C_EX_SlotManage(slot, MODE_GET_LOCAL_PIN_INFO, pins);
	show_rv("C_EX_SlotManage", rv);
	for (i = 0; i < 32; i++) {
		memset(&expected, SENTINEL, sizeof(expected));
		expected.ulPinID = 0x03 + i;
		if (!memcmp(&pins[i], &expected, sizeof(expected)))
			continue;
		changed++;
		line("entry %zu: ulPinID 0x%lx, size 0x%lx..0x%lx, retries 0x%lx of "
				"0x%lx, flags 0x%lx", i, pins[i].ulPinID, pins[i].ulMinSize,
				pins[i].ulMaxSize, pins[i].ulCurrentRetryCount,
				pins[i].ulMaxRetryCount, pins[i].flags);
	}
	line("%zu of 32 entries changed", changed);
}

int
main(int argc, char **argv)
{
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_RV rv;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!parse_options(argc, argv)) {
		usage(argv[0]);
		return 2;
	}
	printf("OpenSC Rutoken hardware probe %d\n", PROBE_VERSION);
	printf("module %s, pause %ld ms, login %s, pkcs7 %s\n", opt.module,
			opt.pause_ms, opt.login ? "yes" : "no",
			opt.pkcs7_id ? opt.pkcs7_id : "no");
	printf("Only reading functions are called; nothing that formats the "
			"token or\nchanges PINs, names, licenses, volumes or modes.\n");

	if (!load_module())
		return 1;
	probe_extended_table("before C_Initialize");
	probe_before_initialize();
	if (!initialize())
		return 1;
	probe_extended_table("after C_Initialize");
	if (select_slot(&slot)) {
		probe_mechanisms(slot);
		probe_token_info(slot);
		probe_flash(slot, "without login");
		probe_journal(slot, "without login");
		probe_forced_pin_change(slot);
		session = open_session(slot);
		if (session != CK_INVALID_HANDLE) {
			probe_token_name(session);
			probe_license(session, 1, 1);
			probe_license(session, 2, 1);
			probe_license(session, 0, 0);
			probe_license(session, 3, 0);
			probe_hardware_features(session);
			probe_certificates(session, "without login");
			probe_authenticators(session, "without login");
			if (opt.login && login(session)) {
				probe_journal(slot, "after login");
				probe_flash(slot, "after login");
				probe_keys(session);
				probe_certificates(session, "after login");
				probe_authenticators(session, "after login");
				if (opt.pkcs7_id)
					probe_pkcs7(session);
				step("C_Logout");
				if (HAVE(f, C_Logout))
					show_rv("C_Logout", f->C_Logout(session));
			}
			step("C_CloseSession");
			if (HAVE(f, C_CloseSession))
				show_rv("C_CloseSession", f->C_CloseSession(session));
		}
		probe_local_pins(slot);
	}
	step("C_Finalize");
	if (HAVE(f, C_Finalize)) {
		rv = f->C_Finalize(NULL_PTR);
		show_rv("C_Finalize", rv);
	}
	printf("\nPROBE COMPLETE after %u steps\n", step_number);
	return 0;
}
