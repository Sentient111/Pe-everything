#include "Pe.h"

UINT64 Nt::Relocate_image(UINT64 new_base)
{
	HANDLE file_hanle = CreateFileA(pe->Get_path().c_str(), FILE_ALL_ACCESS, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!file_hanle || file_hanle == INVALID_HANDLE_VALUE)
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to open file %s, err %X\n", pe->Get_path().c_str(), GetLastError());
		return 0;
	}

	UINT64 image_size = 0;
	if (!GetFileSizeEx(file_hanle, (PLARGE_INTEGER)&image_size))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to get file size %X\n", GetLastError());
		return 0;
	}

	UINT64 file_buffer = (UINT64)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!file_buffer)
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to allocate mem with size %i, err %X\n", image_size, GetLastError());
		return 0;
	}

	if (!ReadFile(file_hanle, (PVOID)file_buffer, image_size, NULL, NULL))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to read file %X\n", GetLastError());
		return 0;
	}

	Reloc_info reloc_info = { 0 };
	if (!Get_reloc_dir(&reloc_info))
		return 0;

	UINT64 delta = new_base - Get_virt_base();
	for (UINT64& curr_reloc : reloc_info.relocations)
	{
		UINT64 reloc_addr = file_buffer + curr_reloc;
		if(is_32_bit)
			*(UINT32*)reloc_addr += delta;
		else
			*(UINT64*)reloc_addr += delta;
	}

	return file_buffer;
}

bool Nt::Resolve_imports(UINT64 base, Pe* target)
{
	Import_info imp_info = { 0 };
	if (!Get_import_dir(&imp_info))
		return 0;

	for (size_t i = 0; i < imp_info.module_count; i++)
	{
		Import_module* mod = &imp_info.module_list[i];
		Pe* import_mod = target->Get_module(mod->module_name);
		if (!import_mod)
		{
			//load with remote load libary call I guess
			return false;
		}
		

		Export_info export_info = { 0 };
		if (!import_mod->Get_nt()->Get_export_dir(&export_info))
			return false;
		
		for (Import_functions& import_fn: mod->imported_functions_list)
		{
			UINT64 export_addr = export_info.export_list[import_fn.function_name];
			if (!export_addr)
			{
				error->last_err = ERROR_NOT_FOUND;
				error->error_comment = CREATE_ERROR("Failed to find export %s ind module %s\n", import_fn.function_name.c_str(), mod->module_name.c_str());
				return false;
			}

			export_addr += import_mod->Get_real_base();
			if (is_32_bit)
				*(UINT32*)(base + import_fn.use_location) = export_addr;
			else
				*(UINT64*)(base + import_fn.use_location) = export_addr;
		}

		delete import_mod;
	}

	return true;
}