#pragma once
#include <vector>
#include <Windows.h>
#include <string>

class Process
{
public:
	Process(Error_struct* error_handeling,  const OPTIONAL std::string& process_name = "");
	~Process() { CloseHandle(process_handle); copies.Free_copies(); }

	UINT64 Read(UINT64 addr, size_t size);
	template <typename char_type>
	char_type* Read_string(char_type* addr);

	bool Get_mod_infoEx(const std::string& module_name, OPTIONAL UINT64* base = 0, OPTIONAL std::string* path = 0);
	bool Get_address_info(UINT64 addr, OPTIONAL std::string* module_path, OPTIONAL UINT64* offset);

private:

	HANDLE process_handle;
	bool is_32_bit;
	bool is_local_context;
	DWORD pid;
	std::string process_path;
	std::string process_name;

	Error_struct* error;
	CopyContainer copies{};

	bool Get_drive_path_from_device_path(const std::string& device_path, std::string* drive_path);
	DWORD Get_pid_by_name(const std::string& name); //Process.cpp

	template <typename ...Args>
	bool Create_call_shellcode(std::vector<BYTE>& shellcode, Calling_covention convention, UINT64 addr, Args... args);

	inline void Encode_value(std::vector<BYTE>& shellcode, UINT32 val);
	inline void Encode_value(std::vector<BYTE>& shellcode, UINT64 val);
	inline void Create_push64(std::vector<BYTE>& shellcode, UINT64 val);
	inline void Create_push32(std::vector<BYTE>& shellcode, UINT32 val);
	inline void Create_call(std::vector<BYTE>& shellcode, UINT64 addr);
};


template <typename char_type>
char_type* Process::Read_string(char_type* addr)
{
	RESET_ERR();

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

	for (size_t i = 0; i < MAX_STR_READ_LEN; i++)
	{
		SIZE_T process_read_size = 0;
		if (!ReadProcessMemory(process_handle, (PVOID)(addr + i), &curr_char, sizeof(char_type), &process_read_size))
		{
			error->last_err = GetLastError();
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

	//string exeeded max string len so it is most likeley a invalid string
	return NULL;
}



template <typename ...Args>
bool Process::Create_call_shellcode(std::vector<BYTE>& shellcode, Calling_covention convention, UINT64 addr, Args... args)
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
