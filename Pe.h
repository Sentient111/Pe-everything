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
	//oh blyat



	template <typename Ret_type, typename ...Args>	
	Ret_type Call_shellcode(PVOID shellcode, Args... args);
	 

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


	//call
	inline void Encode_value(std::vector<BYTE>& shellcode, UINT32 val);
	inline void Encode_value(std::vector<BYTE>& shellcode, UINT64 val);
	inline void Create_push64(std::vector<BYTE>& shellcode, UINT64 val);
	inline void Create_push32(std::vector<BYTE>& shellcode, UINT32 val);
	inline void Create_call(std::vector<BYTE>& shellcode, UINT64 addr);

	template <typename ...Args>
	bool Create_call_shellcode(std::vector<BYTE>& shellcode, Calling_covention convention, UINT64 addr, Args... args);

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

template <typename Ret_type, typename ...Args>
Ret_type Pe::Call_shellcode(PVOID shellcode, Args... args)
{
	//create thread/create remotethread or some shit ree
}

template <typename ...Args>
bool Pe::Create_call_shellcode(std::vector<BYTE>& shellcode, Calling_covention convention, UINT64 addr, Args... args)
{
	int curr_arg = 1;
	DWORD stack_arg_size = 0;
	for (const auto arg : { args... })
	{
		switch (curr_arg)
		{
		case 1:
		{
			if (is_32_bit)
				if (convention == Calling_covention::call_stdcall || convention == Calling_covention::call_cdecl)
					goto NORMAL_PUSH;

			if (is_32_bit)
			{
				shellcode.push_back(0xb9); //mov ecx,
				Encode_value(shellcode, (UINT32)arg);
			}
			else
			{
				shellcode.push_back(0x48); shellcode.push_back(0xb9);//movabs rcx,
				Encode_value(shellcode, (UINT64)arg);
			}
			curr_arg++;
			continue;
		}
		case 2:
		{
			if (is_32_bit && convention == Calling_covention::call_fastcall)
			{
				shellcode.push_back(0xba);
				Encode_value(shellcode, (UINT32)arg);
				curr_arg++;
				continue;
			}

			if (is_32_bit)
				goto NORMAL_PUSH;

			shellcode.push_back(0x48); shellcode.push_back(0xba); //movabs rdx,
			Encode_value(shellcode, (UINT64)arg);
			curr_arg++;
			continue;

		}
		case 3:
		{
			if (is_32_bit)
				goto NORMAL_PUSH;

			shellcode.push_back(0x49); shellcode.push_back(0xb8); //movabs r8,
			Encode_value(shellcode, (UINT64)arg);
			curr_arg++;
			continue;
		}
		case 4:
		{
			if (is_32_bit)
				goto NORMAL_PUSH;
			shellcode.push_back(0x49); shellcode.push_back(0xb9); //movabs r9,
			Encode_value(shellcode, (UINT64)arg);
			curr_arg++;
			continue;
		}

		default:
		{
		NORMAL_PUSH:
			if (is_32_bit)
			{
				Create_push32(shellcode, (UINT32)arg);
				stack_arg_size += sizeof(UINT32);
			}
			else
			{
				Create_push64(shellcode, (UINT64)arg);
				stack_arg_size += sizeof(UINT64);
			}

			curr_arg++;
			continue;
		}
		}
	}


	Create_call(shellcode, is_32_bit, addr);

	if (stack_arg_size && convention == Calling_covention::call_cdecl) //caller needs to clean stack
	{
		if (!is_32_bit)
			shellcode.push_back(0x48); //REX.W

		shellcode.push_back(0x83); shellcode.push_back(0xc4); //add rsp, 
		shellcode.push_back(stack_arg_size);

	}

	shellcode.push_back(0xC3);//ret
	return true;
}

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
