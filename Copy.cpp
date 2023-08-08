#include "Copy.h"

UINT64 CopyContainer::Already_present_copy(UINT64 addr, size_t size, size_t* present_size)
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


UINT64 CopyContainer::Create_copy(UINT64 addr, size_t size)
{
	Local_copy_list copy = { 0 };
	copy.local_addr = (UINT64)malloc(size);
	copy.orig_addr = addr;
	copy.size = size;

	copy_list.push_back(copy);
	return copy.local_addr;
}

void CopyContainer::Destroy_copy(UINT64 addr)
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

void CopyContainer::Free_copies()
{
	for (Local_copy_list& copy : copy_list)
	{
		free((PVOID)copy.local_addr);
	}
	copy_list.clear();
}

