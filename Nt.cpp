#include "Pe.h"


Nt::Nt(Error_struct* error_handeling, Pe* executable)
{
	error = error_handeling;
	RESET_ERR();
	pe = executable;
	real_base = pe->Get_real_base();

	if (pe->Get_pe_type() == Pe_type::pe_file)
		is_unmapped = true;
	else
		is_unmapped = false;

	dos_header = (PIMAGE_DOS_HEADER)pe->Read(pe->Get_real_base(), sizeof(IMAGE_DOS_HEADER));
	if (!dos_header)
		return;
	
	if (dos_header->e_magic != 0x5A4D)
	{
		error->last_err = ERROR_INVALID_EXE_SIGNATURE;
		error->error_comment = CREATE_ERROR("dos header has wrong signature. Probably bad image base\n");
		return;
	}

	UINT64 nt_header_location = pe->Get_real_base() + dos_header->e_lfanew;
	if (!Set_os_platform(nt_header_location))
		return;

	if (is_32_bit)
	{
		nt_32_headers = (PIMAGE_NT_HEADERS32)pe->Read(nt_header_location, sizeof(IMAGE_NT_HEADERS32));
		if (!nt_32_headers)
			return;

		nt_64_headers = 0;
		if (nt_32_headers->Signature != 0x00004550)
		{
			error->last_err = ERROR_INVALID_EXE_SIGNATURE;
			error->error_comment = CREATE_ERROR("nt headers has wrong signature. Probably bad nt header offset\n");
			return;
		}
	}
	else
	{
		nt_64_headers = (PIMAGE_NT_HEADERS64)pe->Read(nt_header_location, sizeof(IMAGE_NT_HEADERS64));
		if (!nt_64_headers)
			return;

		nt_32_headers = 0;
		if (nt_64_headers->Signature != 0x00004550)
		{
			error->last_err = ERROR_INVALID_EXE_SIGNATURE;
			error->error_comment = CREATE_ERROR("nt headers has wrong signature. Probably bad nt header offset\n");
			return;
		}
	}
}


UINT64 Nt::Translate_addr(UINT64 rva)
{
	RESET_ERR();
	if (!is_unmapped)
	{
		if (real_base > rva)
			return real_base + rva;
		else
			return rva;
	}

	PIMAGE_SECTION_HEADER sec = Get_section_from_address(rva);

	if (!sec)//address is not in a section
		return rva + real_base;

	//in section. Turn into raw addr
	return rva - sec->VirtualAddress + real_base + sec->PointerToRawData;
}

