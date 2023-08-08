#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>

#include "Pe.h"

DWORD Process::Get_pid_by_name(const std::string& name)
{
	RESET_ERR();
	std::wstring proc_name(name.begin(), name.end());

	PROCESSENTRY32W current_entry = { 0 };
	current_entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE proc_list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!proc_list || proc_list == INVALID_HANDLE_VALUE)
	{
		error_comment = CREATE_ERROR("invalid snapshot %X\n", GetLastError());
		last_err = GetLastError();
		return 0;
	}

	if (!Process32FirstW(proc_list, &current_entry))
	{
		error_comment = CREATE_ERROR("no first process %X\n", GetLastError());
		last_err = GetLastError();

		CloseHandle(proc_list);
		return 0;
	}

	while (Process32NextW(proc_list, &current_entry))
	{
		if (!lstrcmpW(proc_name.c_str(), current_entry.szExeFile))
		{
			CloseHandle(proc_list);
			return current_entry.th32ProcessID;
		}
	}

	CloseHandle(proc_list);

	error_comment = CREATE_ERROR("failed to find process\n");
	last_err = ERROR_PROC_NOT_FOUND;
	return 0;
}

inline NTSTATUS Ud_NtQueryVirtualMemory(HANDLE procHandle, PVOID addr, ULONG infoClass, PVOID buff, ULONG buffSize, ULONG* retSize)
{
	const static PVOID NtQueryVirtualMemoryptr = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryVirtualMemory");
	return (*(NTSTATUS(__stdcall**)(HANDLE, PVOID, ULONG, PVOID, ULONG, ULONG*))(&NtQueryVirtualMemoryptr))(procHandle, addr, infoClass, buff, buffSize, retSize);
}


#define MemoryMappedFileInformation 2
bool Process::Get_address_info(UINT64 addr, OPTIONAL std::string* module_path, OPTIONAL UINT64* offset)
{
	RESET_ERR();
	std::string path;

	if (module_path)
	{
		UNICODE_STRING_CUSTOM mapped_file_name = { 0 };
		INIT_USTRING(mapped_file_name);
		
		NTSTATUS status = Ud_NtQueryVirtualMemory(process_handle, (PVOID)addr, (WIN32_MEMORY_INFORMATION_CLASS)2, &mapped_file_name, mapped_file_name.MaximumLength, NULL);
		if (status)
		{
			last_err = status;
			error_comment = CREATE_ERROR("Failed to query virtual memory (NTSTATUS) %X\n", status);
			return false;
		}

		std::wstring filenameW((WCHAR*)&mapped_file_name.str);
		
		if(!Get_drive_path_from_device_path(std::string(filenameW.begin(), filenameW.end()), &path))
			return false;

		*module_path = path;
	}

	if (offset)
	{
		//blyat
		if (path.length() == 0)
		{
			last_err = ERROR_MOD_NOT_FOUND;
			error_comment = CREATE_ERROR("no module for address found\n");
			return false;
		}
			
		UINT64 mod_base = 0;
		if (is_local_context)
		{
			mod_base = (UINT64)GetModuleHandleA(path.c_str());
			if(!mod_base)
			{
				last_err = GetLastError();
				error_comment = CREATE_ERROR("Failed to find module base %X\n", GetLastError());
				return false;
			}
		}
		else
		{
			if (!Get_mod_infoEx(path, &mod_base))
				return false;
		}
		*offset = addr - mod_base;
	}

	return true;
}


bool Process::Get_drive_path_from_device_path(const std::string& device_path, std::string* drive_path)
{
	static const char device_path_base[] = "\\Device\\HarddiskVolume";
	if (memcmp(device_path.c_str(), device_path_base, sizeof(device_path_base) - 1))
	{
		error_comment = CREATE_ERROR("path is not device path\n");
		last_err = ERROR_INVALID_NAME;
		return false;
	}

	char volume_name[MAX_PATH] = { 0 };
	HANDLE volume_enumerator = FindFirstVolumeA(volume_name, sizeof(volume_name));
	if (volume_enumerator == INVALID_HANDLE_VALUE)
	{
		error_comment = CREATE_ERROR("Failed to enum volumes %X\n", GetLastError());
		last_err = GetLastError();
		return false;
	}

	do
	{
		char volume_path[MAX_PATH] = { 0 };
		DWORD coverted_path_len = 0;
		if (!GetVolumePathNamesForVolumeNameA(volume_name, (LPCH)&volume_path, sizeof(volume_name), &coverted_path_len))
		{
			error_comment = CREATE_ERROR("Failed to find volume path for volume %s, err %X\n", volume_name, GetLastError());
			last_err = GetLastError();
			return false;
		}

		std::string volume_path_orig = volume_path;
		volume_path[volume_path_orig.find_first_of('\\')] = 0;

		char dos_device_name[MAX_PATH] = { 0 };
		DWORD device_path_len = QueryDosDeviceA(volume_path, dos_device_name, sizeof(dos_device_name));
		if (!device_path_len)
		{
			error_comment = CREATE_ERROR("failed to query dos device name for volume %s, err %X\n", volume_path, GetLastError());
			last_err = GetLastError();
			return false;
		}

		if (!memcmp(dos_device_name, device_path.c_str(), device_path_len - 2))
		{
			*drive_path = volume_path_orig + device_path.substr(device_path_len - 1);
			FindVolumeClose(volume_enumerator);
			return true;
		}

	} while (FindNextVolumeA(volume_enumerator, volume_name, sizeof(volume_name)));


	last_err = ERROR_PATH_NOT_FOUND;
	error_comment = CREATE_ERROR("Failed to find volume device in device path %s\n", device_path.c_str());
	FindVolumeClose(volume_enumerator);
	return false;
}