#pragma once
#include <vector>
#include <Windows.h>

struct Local_copy_list
{
	UINT64 orig_addr;
	UINT64 local_addr;
	size_t size;
};

#define IN_BOUNDS(s1,e1,s2,e2) s1 >= s2 && s2+e2 >= s1+e1

class CopyContainer
{
public:
	CopyContainer() = default;
	~CopyContainer() {Free_copies();};

	UINT64 Already_present_copy(UINT64 addr, size_t size, size_t* present_size = 0);
	UINT64 Create_copy(UINT64 addr, size_t size);
	void Destroy_copy(UINT64 addr);
	void Free_copies();
private:
	//copy 
	std::vector<Local_copy_list> copy_list;

};

