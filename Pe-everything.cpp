#include "Pe.h"

//todo
/*
	add bound checks to read/write operations for more robust code
	fix driver relocs
 	improve import/export walking to support only getting a wanted import/export and not the whole dir.

 	remote call cannot be used without function arguments (blyat)
  	do some slight changed to error handeling so the error struct has a fixed size between architextures

   	I think targeting a x64 process while being in x86 will cause some problems because no wow64 win api is used (cba to test rn)
*/

bool Remote_load_libary(Error_struct* error, Pe* proc, const std::string& libary)
{
	Pe* kernel32_mod = proc->Get_module("Kernel32.dll");
	if (!error->Success())
	{
		printf("Failed to init Kernel32 %X, comment %s\n", error->last_err, error->error_comment.c_str());
		return false;
	}

	Export_info export_info = { 0 };
	if (!kernel32_mod->Get_nt()->Get_export_dir(&export_info))
	{
		printf("Failed to get export info %X, comment %s\n", error->last_err, error->error_comment.c_str());
		return false;
	}

	UINT64 load_lib_ptr = export_info.export_list["LoadLibraryA"];
	if (!load_lib_ptr)
	{
		printf("Failed to get load lib export %X, comment %s\n", error->last_err, error->error_comment.c_str());
		return 1;
	}

	Process* process = proc->Get_proc();

	UINT64 path_copy = process->Copy_data((PVOID)libary.c_str(), libary.size());
	UINT32 lib_base = process->Call_function<UINT32>(Calling_covention::call_stdcall, load_lib_ptr, path_copy);
	process->Free_data(path_copy);

	printf("Loadlibary ret %X\n", lib_base);

	return lib_base;
}

UINT64 Get_export(Pe* pe, const std::string& name)
{
	Export_info export_info = { 0 };
	pe->Get_nt()->Get_export_dir(&export_info);
	return export_info.export_list[name];
}


struct Error_info
{
	DWORD error;
	char error_comment[260];
};

int main()
{
	Error_struct error = { 0 };
	Pe steam{&error, "", "Steam.exe"};
	if (!error.Success())
	{
		printf("Failed to init steam %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return false;
	}

	if (!Remote_load_libary(&error, &steam, "C:\\Users\\sentient\\Documents\\GitHub\\Vac3SteamBypass\\Release\\Vac3SteamBypass.dll"))
		return false;
	
	Pe* bypass = steam.Get_module("Vac3SteamBypass.dll");
	if (!error.Success())
	{
		printf("Failed to get bypass %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return false;
	}

	UINT64 init_fn = Get_export(bypass, "Initialize");
	if (!error.Success())
	{
		printf("Failed to get init %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return false;
	}

	UINT32 erro = steam.Get_proc()->Call_function<UINT32>(Calling_covention::call_cdecl, init_fn, (DWORD)1);
	printf("erro %X\n", erro);

	return 0;
}

