#include "Pe.h"

UINT64 Pe::Read(UINT64 addr, size_t size)
{
	RESET_ERR();

	if (pe_type == Pe_type::pe_local)
		return addr;

	UINT64 preset_data = Already_present_copy(addr, size);
	if (preset_data)
		return preset_data;

	UINT64 buff = Create_copy(addr, size);

	if (pe_type == Pe_type::pe_foreign)
	{
		SIZE_T process_read_size = 0;
		if (!ReadProcessMemory(process_handle, (PVOID)addr, (PVOID)buff, size, &process_read_size))
		{
			last_err = GetLastError();
			error_comment = CREATE_ERROR("Failed to read process memory %X\n", GetLastError());
			Destroy_copy(buff);
			return 0;
		}
		return buff;
	}
	else
	{
		File_read(addr, size, (char*)buff);
		if (file_stream)
			return buff;
		else
		{
			last_err = ERROR_PARTIAL_COPY;
			error_comment = CREATE_ERROR("only managed to read %i bytes\n", file_stream.gcount());
			Destroy_copy(buff);
			return 0;
		}
	}
	return 0;
}


UINT64 Pe::Already_present_copy(UINT64 addr, size_t size, size_t* present_size)
{
	for (Local_copy_list& copy : copy_list)
	{
		if (IN_BOUNDS(addr, size, copy.orig_addr, copy.size))
		{
			UINT64 offset = addr - copy.orig_addr;
			if (present_size)
				*present_size = copy.size - offset;

			return copy.local_addr + offset;
		}
	}
	return 0;
}


UINT64 Pe::Create_copy(UINT64 addr, size_t size)
{
	Local_copy_list copy = { 0 };
	copy.local_addr = (UINT64)malloc(size);
	copy.orig_addr = addr;
	copy.size = size;

	copy_list.push_back(copy);
	return copy.local_addr;
}

void Pe::Destroy_copy(UINT64 addr)
{
	for (size_t i = 0; i < copy_list.size(); i++)
	{
		if (copy_list[i].local_addr == addr)
		{
			free((PVOID)copy_list[i].local_addr);
			copy_list.erase(copy_list.begin() + i);
			return;
		}
	}
}

void Pe::Free_copies()
{
	for (Local_copy_list& copy : copy_list)
	{
		free((PVOID)copy.local_addr);
	}
	copy_list.clear();
}

