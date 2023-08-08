#include "Pe.h"

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


