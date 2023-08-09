#include "Pe.h"

//todo
/*
	add bound checks to read/write operations for more robust code
	rework import/export_info layout
	fix driver relocs
	out of bounds checks for read


	deep scan function (only code ignore data and follow complete control flow)
*/



int main()
{
	Error_struct error = { 0 };

	Pe steam{&error, "", "Steam.exe"};
	if (!error.Success())
	{
		printf("Failed to init steam %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return 1;
	}


	Pe dll(&error, "C:\\Users\\sentient\\Documents\\GitHub\\Vac3SteamBypass\\Release\\Vac3SteamBypass.dll");
	if (!error.Success())
	{
		printf("Failed to init dll %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return 1;
	}

	UINT64 needed_size = dll.Get_nt()->Get_image_size();
	if (!needed_size)
		return 0;
	UINT64 mmap_target = steam.Get_proc()->Allocate_mem(needed_size, PAGE_EXECUTE_READWRITE);
	if (!mmap_target)
		return 0;

	UINT64 relocated_image = dll.Get_nt()->Relocate_image(mmap_target);
	if (!mmap_target)
		return 0;
	if (!dll.Get_nt()->Resolve_imports(relocated_image, &steam))
		return 0;
	if (!steam.Get_proc()->Copy_data(relocated_image, mmap_target, needed_size))
		return 0;
	
	steam.Get_proc()->Call_function<int>(Calling_covention::call_stdcall, mmap_target + dll.Get_nt()->Get_entry_routine(), (UINT32)mmap_target, (UINT32)DLL_PROCESS_ATTACH, (UINT32)NULL);

	return 0;
}

