#include "Pe.h"

std::string Pe::Get_full_module_name(const std::string& name)
{
	RESET_ERR();

	char full_module_path[260] = { 0 };

	if (name.length() == 0)
	{
		if (!GetModuleFileNameA(NULL, (LPSTR)&full_module_path, sizeof(full_module_path)))
		{
			last_err = GetLastError();
			error_comment = CREATE_ERROR("Failed to get full path for local process with err %X\n", last_err);
			return "";
		}
	}
	else
	{
		if (!GetModuleFileNameA(LoadLibraryA(name.c_str()), (LPSTR)&full_module_path, sizeof(full_module_path)))
		{
			last_err = GetLastError();
			error_comment = CREATE_ERROR("Failed to get full path for local module %s with err %X\n", name.c_str(), last_err);
			return "";
		}
	}


	return full_module_path;
}


void Pe::Init_local_pe(const std::string& module_name)
{
	pe_type = Pe_type::pe_local;

	proc = new Process();
	if (!proc->Success()) //copy error from process to Pe
		return;

	source_file_path = Get_full_module_name(module_name);
	file_name = module_name;

	base_adress = (UINT64)GetModuleHandleA(module_name.c_str());
	if (!base_adress)
	{
		last_err = GetLastError();
		error_comment = CREATE_ERROR("failed to get module base for %s, err %X\n", module_name.c_str(), last_err);
		return;
	}

	last_err = ERROR_SUCCESS;
}

void Pe::Init_file_pe(const std::string& file_path)
{
	pe_type = Pe_type::pe_file;

	source_file_path = file_path;
	file_name = source_file_path.substr(source_file_path.find_last_of("\\") + 1);

	file_stream.open(file_path, std::ios::binary);
	if (!file_stream.is_open())
	{
		last_err = ERROR_FILE_NOT_FOUND;
		error_comment = CREATE_ERROR("failed to open file stream\n");
		return;
	}

	base_adress = 0;
	last_err = ERROR_SUCCESS;
}

void Pe::Init_foreign_pe(const std::string& process_name, const std::string& module_name)
{
	pe_type = Pe_type::pe_foreign;

	proc = new Process(process_name);
	if (!proc->Success()) //copy error from process to Pe
		return;

	if (!proc->Get_mod_infoEx(module_name, &base_adress, &source_file_path))
		return;

	file_name = module_name;
	last_err = ERROR_SUCCESS;
}

Pe::Pe(const std::string& pe_identifier, const std::string& owner_process_name, bool loaded_driver)
{
	RESET_ERR();

	if (loaded_driver)
	{
		std::string path = "";
		ULONGLONG base = 0;
		if (!Get_driver_info(pe_identifier, &path, &base))
			return;

		Init_file_pe(path);
		pe_type = Pe_type::pe_driver;
		real_base_address = base;
	}

	if (pe_identifier.length() == 0)
	{
		std::string local_name = Get_full_module_name("");
		if (local_name.length() == 0)
			return;

		Init_local_pe(local_name);
	}

	else if (pe_identifier.find("\\") != std::string::npos) //path to file
		Init_file_pe(pe_identifier);

	else if (owner_process_name.length() == 0) //local module or process
		Init_local_pe(pe_identifier);
	
	else //other process or process module 
		Init_foreign_pe(owner_process_name, pe_identifier);

}

Pe::~Pe()
{
	RESET_ERR();
	if (pe_type == Pe_type::pe_file)
		file_stream.close();

	if(nt)
		delete nt;
	if(proc)
		delete proc;
}