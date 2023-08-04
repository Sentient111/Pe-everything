#pragma once
#include "Nt.h"


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
	Pe(const std::string& pe_identifier = "", const std::string& owner_process_name = "", bool loaded_driver = false);
	Pe(DWORD volume_serial, UINT64 file_serial) : Pe(Get_file_path_from_serial(volume_serial, file_serial)){};

	template <typename char_type = char>
	char_type* Read_string(char_type* addr);
	UINT64 Read(UINT64 addr, size_t size);

	bool Get_address_info(UINT64 addr, OPTIONAL std::string* module_path, OPTIONAL UINT64* offset = 0);

#pragma region Getters
	std::string Get_path() { return source_file_path; };
	std::string Get_name() { return file_name; };
	Nt* Get_nt() { if (!nt) nt = new Nt(this); return nt; };
	Pe_type Get_pe_type(){ return pe_type; };
	UINT64 Get_real_base() { return base_adress; };
	DWORD Get_error() { return last_err; };
	bool Success() { return  Get_error() == ERROR_SUCCESS; };
	std::string* Get_error_comment() { return &error_comment; };
#pragma endregion

private:

	DWORD last_err = ERROR_SUCCESS;
	std::string error_comment = "";

	
	//general info 
	UINT64 base_adress;
	UINT64 real_base_address = 0;
	std::string source_file_path;
	std::string file_name;
	std::string owner_process_path;
	std::string owner_process_name;

	//pe type info
	Pe_type pe_type;

	//process
	HANDLE process_handle = INVALID_HANDLE_VALUE;
	DWORD pid;

	DWORD Get_pid_by_name(const std::string& name); //Process.cpp
	std::string Get_full_module_name(const std::string& name);
	bool Get_mod_infoEx(const std::string& module_name, OPTIONAL UINT64* base = 0, OPTIONAL std::string* path = 0);
	bool Get_driver_info(IN const std::string& name,  OPTIONAL std::string* path, OPTIONAL ULONGLONG* base);
	bool Get_system_dir(std::string* dir);
	bool Get_drive_path_from_device_path(const std::string& device_path, std::string* drive_path);

	//copy 
	std::vector<Local_copy_list> copy_list;

	UINT64 Already_present_copy(UINT64 addr, size_t size, size_t* present_size = 0);
	UINT64 Create_copy(UINT64 addr, size_t size);
	void Destroy_copy(UINT64 addr);
	void Free_copies();

	//file
	void Init_file_pe(const std::string& file_path);
	void Init_local_pe(const std::string& module_name);
	void Init_foreign_pe(const std::string& process_name, const std::string& module_name);
	
	std::ifstream file_stream;
	std::string Get_file_path_from_serial(DWORD volume_serial, UINT64 file_serial);

	//extra functionality
	Nt* nt = nullptr;
};

template <typename char_type>
char_type* Pe::Read_string(char_type* addr)
{
	RESET_ERR();
	if (pe_type == Pe_type::pe_local)
		return (char_type*)addr;

	size_t present_size = 0;
	char_type* preset_data = (char_type*)Already_present_copy((UINT64)addr, 0, &present_size);
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

	for (size_t i = 0; i < MAX_STR_READ_LEN; i++)
	{
		if (pe_type == Pe_type::pe_file)
		{
			File_read((UINT64)(addr + i), sizeof(char), &curr_char);
			if (!file_stream)
			{
				last_err = ERROR_PARTIAL_COPY;
				error_comment = CREATE_ERROR("only managed to read %i bytes\n", file_stream.gcount());
				return NULL;
			}
		}
		else
		{
			SIZE_T process_read_size = 0;
			if (!ReadProcessMemory(process_handle, (PVOID)(addr + i), &curr_char, sizeof(char_type), &process_read_size))
			{
				last_err = GetLastError();
				return NULL;
			}
		}


		temp_string.push_back(curr_char);

		if (curr_char == 0) //null term found
		{
			char_type* local_copy = (char_type*)Create_copy((UINT64)addr, temp_string.size() * sizeof(char_type)); //alloc local buff
			memcpy(local_copy, &temp_string[0], temp_string.size() * sizeof(char_type));
			return local_copy;
		}
	}

	//string exeeded max string len so it is most likeley a invalid string
	return NULL;
}
