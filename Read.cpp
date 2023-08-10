#include "Pe.h"



UINT64 Pe::Read(UINT64 addr, size_t size)
{
	switch (pe_type)
	{
		case Pe_type::pe_file:
		{
			UINT64 preset = 0;
			if (preset = copies.Already_present_copy(addr, size))
				return preset;


			UINT64 buff = copies.Create_copy(addr, size);
			File_read(addr, size, (char*)buff);
			if (file_stream)
				return buff;
			else
			{
				error->last_err = ERROR_PARTIAL_COPY;
				error->error_comment = CREATE_ERROR("only managed to read %i bytes\n", file_stream.gcount());
				copies.Destroy_copy(buff);
				return 0;
			}
		}

		case Pe_type::pe_foreign:
			return proc->Read(addr, size);
		case Pe_type::pe_local:
			return addr;

		case Pe_type::pe_driver:
		case Pe_type::pe_unknown:
		default:
		{
			error->last_err = ERROR_INVALID_FUNCTION;
			error->error_comment = CREATE_ERROR("Read does not currently support drivers or other unknown pe types\n");
			return 0;
		}

	}

}
