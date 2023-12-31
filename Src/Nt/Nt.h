#pragma once
#include "..\Util\Error.h"
#include "..\Util\Copy.h"
#include <vector>

class Pe;

#include "..\Util\TypesAndClasses.h"


class Nt
{
public:
	Nt(Error_struct* error_handeling, Pe* executable);

	PIMAGE_SECTION_HEADER Get_section_from_address(UINT64 addr);
	PIMAGE_SECTION_HEADER Get_section(const char* name);

	bool Get_import_dir(Import_info* info);
	bool Get_export_dir(Export_info* info);
	bool Get_reloc_dir(Reloc_info* info);

	UINT64 Get_dir_ptr(DWORD dir_idx);


	bool Is_driver() { return Has_characteristics(IMAGE_FILE_SYSTEM); };
	bool Is_dll() { return Has_characteristics(IMAGE_FILE_DLL); };
	bool Is_missing_relocs() { return Has_characteristics(IMAGE_FILE_RELOCS_STRIPPED); };
	bool Is_large_address_aware() { return Has_characteristics(IMAGE_FILE_LARGE_ADDRESS_AWARE); };
	bool Is_debug_stripped() { return Has_characteristics(IMAGE_FILE_DEBUG_STRIPPED); };

	UINT64 Get_virt_base()
	{
		if (is_32_bit)
			return nt_32_headers->OptionalHeader.ImageBase;
		else
			return nt_64_headers->OptionalHeader.ImageBase;
	}

	UINT64 Get_image_size()
	{
		if (is_32_bit)
			return nt_32_headers->OptionalHeader.SizeOfImage;
		else
			return nt_64_headers->OptionalHeader.SizeOfImage;
	}

	UINT64 Get_entry_routine()
	{
		if (is_32_bit)
			return nt_32_headers->OptionalHeader.AddressOfEntryPoint;
		else
			return nt_64_headers->OptionalHeader.AddressOfEntryPoint;
	}

	Execution_enviornment Get_execution_enviornment();
	Subsystem_target Get_subsystem_target();

	bool Is_32_bit() { return is_32_bit; };
private:

	Pe* pe;
	Error_struct* error;

	bool is_32_bit;
	bool is_unmapped;
	UINT64 real_base;

	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS32 nt_32_headers;
	PIMAGE_NT_HEADERS64 nt_64_headers;


	bool Parse_module_imports(Import_module* mod, DWORD function_thunk_ptr, DWORD name_thunk_ptr);


	bool Has_characteristics(DWORD flag);
	UINT64 Translate_addr(UINT64 rva);
	PIMAGE_SECTION_HEADER Get_first_section_ptr(OPTIONAL DWORD* sec_count);
	bool Set_os_platform(UINT64 nt_addr);
};

