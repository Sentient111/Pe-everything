#include "Pe.h"




PIMAGE_SECTION_HEADER Nt::Get_first_section_ptr(OPTIONAL DWORD* sec_count)
{
	RESET_ERR();

	PIMAGE_SECTION_HEADER first_sec = nullptr;
	DWORD section_count = 0;

	UINT64 real_nt_header_ptr = pe->Get_real_base() + dos_header->e_lfanew;
	if (is_32_bit)
	{
		first_sec = (PIMAGE_SECTION_HEADER)(real_nt_header_ptr + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + nt_32_headers->FileHeader.SizeOfOptionalHeader);
		section_count = nt_32_headers->FileHeader.NumberOfSections;
	}
	else
	{
		first_sec = (PIMAGE_SECTION_HEADER)(real_nt_header_ptr + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt_64_headers->FileHeader.SizeOfOptionalHeader);
		section_count = nt_64_headers->FileHeader.NumberOfSections;
	}

	if(sec_count)
		*sec_count = section_count;

	return first_sec;
}

PIMAGE_SECTION_HEADER Nt::Get_section_from_address(UINT64 addr)
{
	RESET_ERR();

	DWORD section_count = 0;
	PIMAGE_SECTION_HEADER curr_section_ptr = Get_first_section_ptr(&section_count);

	if (!curr_section_ptr || 0>=section_count)
		return 0;

	for (size_t i = 0; i < section_count; i++)
	{
		PIMAGE_SECTION_HEADER curr_local_section = (PIMAGE_SECTION_HEADER)pe->Read((UINT64)curr_section_ptr, sizeof(IMAGE_SECTION_HEADER));
		if (!curr_local_section)
			return 0;

		if (addr >= curr_local_section->VirtualAddress && addr < curr_local_section->VirtualAddress + curr_local_section->Misc.VirtualSize)
			return curr_local_section;

		curr_section_ptr++;
	}


	error->last_err = ERROR_SECTOR_NOT_FOUND;
	error->error_comment = CREATE_ERROR("No section was found for address %X\n", addr);
	return NULL;
}


PIMAGE_SECTION_HEADER Nt::Get_section(const char* name)
{
	RESET_ERR();

	DWORD section_count = 0;
	PIMAGE_SECTION_HEADER curr_section_ptr = Get_first_section_ptr(&section_count);
	if (!curr_section_ptr)
		return 0;

	if (!name) //get first section
		return (PIMAGE_SECTION_HEADER)pe->Read((UINT64)curr_section_ptr, sizeof(IMAGE_SECTION_HEADER));

	for (size_t i = 0; i < section_count; i++)
	{
		PIMAGE_SECTION_HEADER curr_local_section = (PIMAGE_SECTION_HEADER)pe->Read((UINT64)curr_section_ptr, sizeof(IMAGE_SECTION_HEADER));
		if (!curr_local_section)
			return 0;

		if(strcmp(name, (const char*)curr_local_section->Name) == 0)
			return curr_local_section;

		curr_section_ptr++;
	}


	error->last_err = ERROR_SECTOR_NOT_FOUND;
	error->error_comment = CREATE_ERROR("No section by name %s was found.\n", name);
	return NULL;
}

