#pragma once
#include <map>

#pragma region MACROS

// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define LOCAL_64
#else
#define LOCAL32
#endif
#endif

// Check GCC
#if __GNUC__
#if __x86_64__ || __ppc64__
#define LOCAL_64
#else
#define LOCAL_32
#endif
#endif

#define MAX_QUERY_TRIES 5
#define RESET_ERR() last_err = ERROR_SUCCESS;error_comment = "";
#define MAX_STR_READ_LEN 260
#define File_read(addr, size, buff) file_stream.seekg(addr); file_stream.read((char*)buff, size)
#define INIT_USTRING(string) string.Buffer = string.str; string.Length = 0; string.MaximumLength = sizeof(string.str);

#pragma endregion


#pragma region STRUCTS

struct UNICODE_STRING_CUSTOM
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
	WCHAR str[MAX_PATH];
};

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	UINT64 MappedBase;
	UINT64 ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

struct Import_functions
{
	std::string function_name;
	UINT64 use_location;
};

struct Import_module
{
	std::string module_name;
	std::vector<Import_functions> imported_functions_list;
};

struct Import_info
{
	UINT64 module_count;
	UINT64 function_count;
	UINT64 import_count;
	std::vector<Import_module> module_list;
};


struct Export_info
{
	UINT64 export_count;
	std::map<std::string, UINT64> export_list;
};


struct Reloc_info
{
	UINT64 reloc_count;
	std::vector<UINT64> relocations;
};

#pragma endregion

#pragma region ENUMS


enum class Calling_covention
{
	call_cdecl,
	call_stdcall,
	call_fastcall,
	call_thiscall,
	call_vectorcall
};

enum class Directory_type
{
	import_dir,
	export_dir,
	reloc_dir
};


enum class Pe_type
{
	pe_unknown,
	pe_file,
	pe_foreign,
	pe_local,
	pe_driver
};

enum class Execution_enviornment
{
	invalid,
	unknown,
	Alpha_AXP32,
	Alpha_64,
	Matsushita_AM33,
	x64,
	ARM_little_endian,
	ARM64_little_endian,
	ARM_Thumb_2_little_endian,
	AXP_64,
	EFI_byte_code,
	Intel_386,
	Intel_Itanium_processor_family,
	LoongArch_32_bit,
	LoongArch_64_bit,
	Mitsubishi_M32R_little_endian,
	MIPS16,
	MIPS_with_FPU,
	MIPS16_with_FPU,
	Power_PC_little_endian,
	Power_PC_with_floating_point_support,
	MIPS_little_endian,
	RISCV_32,
	RISCV_64,
	RISCV_128,
	Hitachi_SH3,
	Hitachi_SH3_DSP,
	Hitachi_SH4,
	Hitachi_SH5,
	Thumb,
	MIPS_little_endian_WCE_v2
};


enum class Subsystem_target
{
	invalid,
	unknown,
	native,
	gui,
	character,
	os2_character,
	posix_character,
	native_win9,
	ce_gui,
	efi,
	boot_efi,
	runtime_efi,
	rom_efi,
	xbox,
	boot
};
#pragma endregion