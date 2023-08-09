#include "Pe.h"

UINT64 Nt::Relocate_image(UINT64 new_base)
{
	std::ifstream& fstream = pe->Get_file_stream();
	fstream.seekg(0, std::ios::end);
	UINT64 image_size = fstream.tellg();
	fstream.seekg(0, std::ios::beg);

	if (0 >= image_size)
	{
		error->last_err = ERROR_FILE_NOT_FOUND;
		error->error_comment = CREATE_ERROR("failed to get file size\n",);
		return 0;
	}

	UINT64 file_buffer = (UINT64)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!file_buffer)
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to allocate mem with size %i, err %X\n", image_size, GetLastError());
		return 0;
	}

	fstream.read((char*)file_buffer, image_size);
	if (!fstream)
	{
		error->last_err = ERROR_READ_FAULT;
		error->error_comment = CREATE_ERROR("failed to read file to buff\n");
		return 0;
	}

	Reloc_info reloc_info = { 0 };
	if (!Get_reloc_dir(&reloc_info))
		return 0;

	UINT64 delta = new_base - Get_virt_base();
	for (Relocation_entry& curr_reloc : reloc_info.relocations)
	{
		UINT64* reloc_addr = (UINT64*)(file_buffer + curr_reloc.relocation_location);
		switch (curr_reloc.type)
		{
			case IMAGE_REL_BASED_DIR64:
			{
				*reloc_addr += delta;
				break;
			}

			case IMAGE_REL_BASED_HIGHLOW:
			{
				*reloc_addr = *reloc_addr + (delta & 0xFFFFFFFF);
				break;
			}

			case IMAGE_REL_BASED_LOW:
			{
				*(USHORT*)reloc_addr = *(USHORT*)reloc_addr + LOWORD(delta & 0xFFFF);
				break;
			}

			case IMAGE_REL_BASED_HIGH:
			{
				*(USHORT*)reloc_addr = HIWORD(MAKELONG(0, *(USHORT*)reloc_addr) + (delta & 0xFFFFFFFF));
				break;
			}

		case IMAGE_REL_BASED_ABSOLUTE:
		case IMAGE_REL_BASED_HIGHADJ:
		case IMAGE_REL_BASED_MIPS_JMPADDR:
		default:
			break;
		}
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
		if (!error->Success())
		{
			//load with remote load libary call I guess

			Export_info exports = { 0 };
			if (!target->Get_nt()->Get_export_dir(&exports))
				return false;

			UINT64 load_lib_addr = exports.export_list["LoadLibraryA"];
			if (!load_lib_addr)
				return false;

			UINT64 mod_name = target->Get_proc()->Copy_data((UINT64)mod->module_name.c_str(), mod->module_name.size());
			if (!mod_name)
				return false;
			
			target->Get_proc()->Call_function<HMODULE>(Calling_covention::call_stdcall, load_lib_addr, mod_name);

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