#pragma once
#include "..\Nt\Nt.h"
#include "..\Proc\Process.h"

class Pe
{
public:
	//Pe.cpp
	~Pe();

	/// <summary>
	/// 	Pe() = local process
	/// 	Pe(module_name) = local module
	/// 	
	/// 	Pe(file_path) = file
	/// 	
	/// 	Pe("", process_name) = foreign process
	/// 	Pe(module_name, process_name) = foreign module
	/// 	
	/// 	Pe(driver_name, "", true) = system driver
	/// 	Pe(volume_serial, file_serial) = file
	/// </summary>
	Pe(Error_struct* error_handeling, const std::string& pe_identifier = "", const std::string& owner_process_name = "", bool loaded_driver = false);
	Pe(Error_struct* error_handeling, DWORD volume_serial, UINT64 file_serial) : Pe(error_handeling, Get_file_path_from_serial(volume_serial, file_serial)) {};

	template <typename char_type = char>
	char_type* Read_string(char_type* addr);

	UINT64 Read(UINT64 addr, size_t size);
	Pe* Get_module(const std::string& name, OPTIONAL Error_struct* error_handler = 0);


#pragma region Getters
	std::string Get_path() { return source_file_path; };
	std::string Get_name() { return file_name; };
	Nt* Get_nt() { if (!nt) nt = new Nt(error, this); return nt; };
	Process* Get_proc() { return proc; };
	Pe_type Get_pe_type() { return pe_type; };
	UINT64 Get_real_base() { return base_adress; };
	std::ifstream& Get_file_stream() { return file_stream; };

#pragma endregion

private:



	//general info 
	UINT64 base_adress;
	UINT64 real_base_address = 0;
	std::string source_file_path;
	std::string file_name;

	//pe type info
	Pe_type pe_type;

	bool Get_driver_info(IN const std::string& name, OPTIONAL std::string* path, OPTIONAL ULONGLONG* base);
	bool Get_system_dir(std::string* dir);
	std::string Get_full_module_name(const std::string& name);

	//file
	void Init_file_pe(const std::string& file_path);
	void Init_local_pe(const std::string& module_name);
	void Init_foreign_pe(const std::string& process_name, const std::string& module_name);

	std::ifstream file_stream;
	std::string Get_file_path_from_serial(DWORD volume_serial, UINT64 file_serial);

	//extra functionality
	Error_struct* error;
	Nt* nt = nullptr;
	Process* proc = nullptr;
	CopyContainer copies{};
};


template <typename char_type>
char_type* Pe::Read_string(char_type* addr)
{
	switch (pe_type)
	{
	case Pe_type::pe_file:
	{
		size_t present_size = 0;
		char_type* preset_data = (char_type*)copies.Already_present_copy((UINT64)addr, 0, &present_size);
		if (preset_data)
		{
			for (size_t i = present_size; i <= 0; i--) //walk the string backwards
			{
				if (preset_data[i] == 0) //copy contains full string
					return (char_type*)preset_data;
			}
		}

		std::vector<char_type> temp_string;
		char_type curr_char = { 0 };

		for (size_t i = 0; i < MAX_STR_READ_LEN; i+= sizeof(char_type))
		{
			File_read((UINT64)(addr + i), sizeof(char_type), &curr_char);
			if (!file_stream)
			{
				error->last_err = ERROR_PARTIAL_COPY;
				error->error_comment = CREATE_ERROR("only managed to read %i bytes\n", file_stream.gcount());
				return NULL;
			}

			temp_string.push_back(curr_char);

			if (curr_char == 0) //null term found
			{
				char_type* local_copy = (char_type*)copies.Create_copy((UINT64)addr, temp_string.size() * sizeof(char_type)); //alloc local buff
				memcpy(local_copy, &temp_string[0], temp_string.size() * sizeof(char_type));
				return local_copy;
			}
		}

		return NULL;
	}

	case Pe_type::pe_foreign:
		return proc->Read_string(addr);
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