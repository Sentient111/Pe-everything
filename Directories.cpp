#include "Pe.h"


UINT64 Nt::Get_dir_ptr(DWORD dir_idx)
{
	UINT64 dir_addr = 0;
	if (is_32_bit)
		dir_addr = nt_32_headers->OptionalHeader.DataDirectory[dir_idx].VirtualAddress;
	else
		dir_addr = nt_64_headers->OptionalHeader.DataDirectory[dir_idx].VirtualAddress;

	return dir_addr;
}

bool Nt::Parse_module_imports(Import_module* mod, DWORD function_thunk_ptr, DWORD name_thunk_ptr)
{
	if (is_32_bit)
	{
		PIMAGE_THUNK_DATA32 function_thunk = (PIMAGE_THUNK_DATA32)pe->Read(Translate_addr(function_thunk_ptr), sizeof(IMAGE_THUNK_DATA32));
		PIMAGE_THUNK_DATA32 name_thunk = (PIMAGE_THUNK_DATA32)pe->Read(Translate_addr(name_thunk_ptr), sizeof(IMAGE_THUNK_DATA32));
		if (!function_thunk || !name_thunk)
			return false;

		while (function_thunk->u1.AddressOfData && name_thunk->u1.AddressOfData)
		{
			UINT64 import_name_ptr = Translate_addr(name_thunk->u1.AddressOfData) + sizeof(WORD);
			char* import_name = pe->Read_string((char*)import_name_ptr);
			if (!import_name)
				return false;

			mod->imported_functions_list.push_back({ import_name , function_thunk->u1.Function });


			function_thunk_ptr += sizeof(IMAGE_THUNK_DATA32);
			name_thunk_ptr += sizeof(IMAGE_THUNK_DATA32);
			function_thunk = (PIMAGE_THUNK_DATA32)pe->Read(Translate_addr(function_thunk_ptr ), sizeof(IMAGE_THUNK_DATA32));
			name_thunk = (PIMAGE_THUNK_DATA32)pe->Read(Translate_addr(name_thunk_ptr), sizeof(IMAGE_THUNK_DATA32));
			if (!function_thunk || !name_thunk)
				return false;
		}
	}
	else
	{
		PIMAGE_THUNK_DATA64 function_thunk = (PIMAGE_THUNK_DATA64)pe->Read(Translate_addr(function_thunk_ptr), sizeof(IMAGE_THUNK_DATA64));
		PIMAGE_THUNK_DATA64 name_thunk = (PIMAGE_THUNK_DATA64)pe->Read(Translate_addr(name_thunk_ptr), sizeof(IMAGE_THUNK_DATA64));
		if (!function_thunk || !name_thunk)
			return false;

		while (function_thunk->u1.AddressOfData && name_thunk->u1.AddressOfData)
		{
			UINT64 import_name_ptr = Translate_addr(name_thunk->u1.AddressOfData) + sizeof(WORD);
			char* import_name = pe->Read_string((char*)import_name_ptr);
			if (!import_name)
				return false;
			mod->imported_functions_list.push_back({ import_name , function_thunk->u1.Function });

			function_thunk_ptr += sizeof(IMAGE_THUNK_DATA64);
			name_thunk_ptr += sizeof(IMAGE_THUNK_DATA64);
			function_thunk = (PIMAGE_THUNK_DATA64)pe->Read(Translate_addr(function_thunk_ptr), sizeof(IMAGE_THUNK_DATA64));
			name_thunk = (PIMAGE_THUNK_DATA64)pe->Read(Translate_addr(name_thunk_ptr), sizeof(IMAGE_THUNK_DATA64));
			if (!function_thunk || !name_thunk)
				return false;
		}
	}

	return true;
}

bool Nt::Get_import_dir(Import_info* info)
{
	RESET_ERR();

	PIMAGE_IMPORT_DESCRIPTOR dir_ptr = (PIMAGE_IMPORT_DESCRIPTOR)Get_dir_ptr(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (!dir_ptr)
		return true;

	PIMAGE_IMPORT_DESCRIPTOR import_dir = (PIMAGE_IMPORT_DESCRIPTOR)pe->Read(Translate_addr(UINT64(dir_ptr)), sizeof(IMAGE_IMPORT_DESCRIPTOR));
	if (!import_dir)
		return false;

	while (import_dir->FirstThunk)
	{
		info->module_count++;
		Import_module mod_info;
		char* module_name = pe->Read_string((char*)Translate_addr(import_dir->Name));
		if (!module_name)
			return false;

		mod_info.module_name = module_name;

		if (!Parse_module_imports(&mod_info, import_dir->FirstThunk, import_dir->OriginalFirstThunk))
			break;
	
		info->module_list.push_back(mod_info);
		import_dir = (PIMAGE_IMPORT_DESCRIPTOR)pe->Read(Translate_addr((UINT64)++dir_ptr), sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (!import_dir)
			return false;
	}

	return true;
}

bool Nt::Get_export_dir(Export_info* info)
{
	RESET_ERR();

	PIMAGE_EXPORT_DIRECTORY export_dir_ptr = (PIMAGE_EXPORT_DIRECTORY)Get_dir_ptr(IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (!export_dir_ptr)
		return true;

	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)pe->Read(Translate_addr((UINT64)export_dir_ptr), sizeof IMAGE_EXPORT_DIRECTORY);
	if (!export_dir)
		return false;

	PDWORD function_table = (PDWORD)pe->Read(Translate_addr((UINT64)export_dir->AddressOfFunctions), sizeof(PDWORD) * export_dir->NumberOfFunctions);
	WORD* ordinal_table = (WORD*)pe->Read(Translate_addr((UINT64)export_dir->AddressOfNameOrdinals), sizeof(WORD*) * export_dir->NumberOfFunctions);
	DWORD* name_table = (DWORD*)pe->Read(Translate_addr((UINT64)export_dir->AddressOfNames), sizeof(char*) * export_dir->NumberOfNames);

	if (!function_table || !ordinal_table || !name_table)
		return false;

	for (unsigned int i = 0; i < export_dir->NumberOfFunctions; i++) 
	{
		info->export_count++;
		char* export_name = pe->Read_string((char*)Translate_addr(name_table[i]));
		if (!export_name)
			return false;

		UINT64 export_addr = Translate_addr(function_table[ordinal_table[i]]);
		info->export_list.insert(std::make_pair(export_name, export_addr));
	}

	return true;
}

struct Reloc_entry
{
	WORD offset : 12;
	WORD type : 4;
};


bool Nt::Get_reloc_dir(Reloc_info* info)
{
	RESET_ERR();

	PIMAGE_DATA_DIRECTORY reloc_dir_ptr = (PIMAGE_DATA_DIRECTORY)Get_dir_ptr(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (!reloc_dir_ptr)
		return true;

	PIMAGE_DATA_DIRECTORY reloc_dir = (PIMAGE_DATA_DIRECTORY)pe->Read(Translate_addr((UINT64)reloc_dir_ptr), sizeof IMAGE_DATA_DIRECTORY);
	if (!reloc_dir)
		return false;

	while (reloc_dir->VirtualAddress)
	{
		size_t curr_reloc_count = (reloc_dir->Size - sizeof(IMAGE_DATA_DIRECTORY)) / sizeof(Reloc_entry);
		Reloc_entry* first_reloc_addr = (Reloc_entry*)(++reloc_dir_ptr);
		Reloc_entry* curr_reloc_list = (Reloc_entry*)pe->Read(Translate_addr((UINT64)first_reloc_addr), curr_reloc_count * sizeof(Reloc_entry));
		if (!curr_reloc_list)
			return false;

		for (size_t i = 0; i < curr_reloc_count; i++)
		{
			if (curr_reloc_list[i].type == IMAGE_REL_BASED_DIR64)
			{
				info->reloc_count++;
				UINT64 addr_to_relocate = (UINT64)(reloc_dir->VirtualAddress + curr_reloc_list[i].offset); //mby we need to rva this
				info->relocations.push_back({ addr_to_relocate });
			}

		}

		reloc_dir_ptr = PIMAGE_DATA_DIRECTORY((UINT64)first_reloc_addr + curr_reloc_count * sizeof(Reloc_entry));
		reloc_dir = (PIMAGE_DATA_DIRECTORY)pe->Read(Translate_addr((UINT64)reloc_dir_ptr), sizeof IMAGE_DATA_DIRECTORY);
		if (!reloc_dir)
			return false;
	}

	return true;
}