#include "Pe.h"

bool Process::Get_mod_infoEx(const std::string& module_name, OPTIONAL UINT64* base, OPTIONAL std::string* path)
{
	RESET_ERR();

	HMODULE mod_list[1024];
	DWORD found_mod_size;
	if (!K32EnumProcessModules(process_handle, mod_list, sizeof(mod_list), &found_mod_size))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed enum process modules %X\n", GetLastError());
		return false;
	}

	for (int i = 0; i < (found_mod_size / sizeof(HMODULE)); i++)
	{
		char curr_mod_name[MAX_PATH];

		if (K32GetModuleFileNameExA(process_handle, mod_list[i], curr_mod_name, sizeof(curr_mod_name)))
		{
			std::string mod_exe_name = curr_mod_name;
			mod_exe_name = mod_exe_name.substr(mod_exe_name.find_last_of("\\") + 1);


			if (strcmp(mod_exe_name.c_str(), module_name.c_str()) == 0)
			{
				if (base)
					*base = (UINT64)mod_list[i];
				if (path)
					*path = curr_mod_name;

				return true;
			}
		}
	}

	error->last_err = ERROR_MOD_NOT_FOUND;
	error->error_comment = CREATE_ERROR("Failed to find module\n");
	return false;
}
