#include "..\Pe\Pe.h"

UINT64 Process::Read(UINT64 addr, size_t size)
{
	RESET_ERR();

	if (is_local_context)
		return addr;

	UINT64 preset_data = copies.Already_present_copy(addr, size);
	if (preset_data)
		return preset_data;

	UINT64 buff = copies.Create_copy(addr, size);

	SIZE_T process_read_size = 0;
	if (!ReadProcessMemory(process_handle, (PVOID)addr, (PVOID)buff, size, &process_read_size))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to read process memory %X\n", GetLastError());
		copies.Destroy_copy(buff);
		return 0;
	}
	return buff;
}


UINT64 Process::Copy_data(PVOID data, size_t size)
{
	if (is_local_context)
		return (UINT64)data;

	PVOID allocated_mem = VirtualAllocEx(process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!allocated_mem)
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to alloc mem %X\n", GetLastError());
		return 0;
	}

	if (!WriteProcessMemory(process_handle, allocated_mem, (LPVOID)data, size, NULL))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to copy mem %X\n", GetLastError());
		return 0;
	}

	return (UINT64)allocated_mem;
}

UINT64 Process::Allocate_mem(size_t size, DWORD prot)
{
	UINT64 base = (UINT64)VirtualAllocEx(process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, prot);
	if (!base)
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to alloc mem %X\n", GetLastError());
		return 0;
	}
	return base;
}

bool Process::Copy_data_to_dest(PVOID source, UINT64 dest, size_t size)
{
	if (!WriteProcessMemory(process_handle, (PVOID)dest, (PVOID)source, size, NULL))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to alloc mem %X\n", GetLastError());
		return false;
	}

	return true;
}

void Process::Free_data(UINT64 addr)
{
	VirtualFreeEx(process_handle, (PVOID)addr, NULL, MEM_RELEASE);
}