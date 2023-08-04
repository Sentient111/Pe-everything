#include "Pe.h"

bool Pe::Get_system_dir(std::string* dir)
{
	int dir_name_len = GetSystemDirectoryA(NULL, NULL);
	if (!dir_name_len)
	{
		last_err = GetLastError();
		error_comment = CREATE_ERROR("failed to get system dir length\n");
		return false;
	}

	char* dir_path = new char[dir_name_len];

	if (!GetSystemDirectoryA(dir_path, dir_name_len))
	{
		last_err = GetLastError();
		error_comment = CREATE_ERROR("Failed to query system root dir\n");
		return false;
	}

	std::string ret(dir_path);
	delete[] dir_path;

	const char system_32_str[] = "system32";
	*dir = ret.substr(0, ret.size() - sizeof(system_32_str));

	return true;
}

std::string Pe::Get_file_path_from_serial(DWORD volume_serial, UINT64 file_serial)
{
	RESET_ERR();

	char curr_volume_name[MAX_PATH] = { 0 };
	HANDLE volume_enumerator = FindFirstVolumeA(curr_volume_name, sizeof curr_volume_name);

	if (volume_enumerator == INVALID_HANDLE_VALUE || !volume_enumerator)
	{
		last_err = GetLastError();
		error_comment = CREATE_ERROR("failed to get volume enumerator %X\n", GetLastError());
		return "";
	}

	do
	{
		DWORD volumeSerialNumber = 0;
		if (!GetVolumeInformationA(curr_volume_name, 0, 0, &volumeSerialNumber, 0, 0, 0, 0)
			|| volumeSerialNumber != volume_serial)
			continue;
		
		FILE_ID_DESCRIPTOR file_id = { 0 };

		size_t volume_name_len = strlen(curr_volume_name);
		if (volume_name_len > 1)
			*(char*)&file_id.ObjectId.Data4[volume_name_len + 6] = '\0';

		HANDLE volume_handle = CreateFileA(curr_volume_name, GENERIC_READ, FILE_SHARE_WRITE| FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		if (volume_handle != INVALID_HANDLE_VALUE)
		{
			file_id.FileId.QuadPart = file_serial;
			memset(file_id.ObjectId.Data4, 0, sizeof(file_id.ObjectId.Data4));
			file_id.dwSize = sizeof(file_id);
			file_id.Type = FileIdType;
			
			HANDLE file_handle = OpenFileById(volume_handle, &file_id, 0x120089, 7, 0, 0x2000000);
			CloseHandle(volume_handle);
			FindVolumeClose(volume_enumerator);

			if (file_handle == INVALID_HANDLE_VALUE)
			{
				last_err = GetLastError();
				error_comment = CREATE_ERROR("Failed to open file by id %X\n", GetLastError());
				return "";
			}

			char file_path[MAX_PATH] = { 0 };
			if (!GetFinalPathNameByHandleA(file_handle, (LPSTR)&file_path, sizeof file_path, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS))
			{
				CloseHandle(file_handle);
				last_err = GetLastError();
				error_comment = CREATE_ERROR("Failed to get path %X\n", GetLastError());
				return "";
			}

			return std::string(file_path);
		}
	} while (FindNextVolumeA(volume_enumerator, curr_volume_name, sizeof curr_volume_name));

	FindVolumeClose(volume_enumerator);
	last_err = ERROR_FILE_NOT_FOUND;
	error_comment = CREATE_ERROR("Failed to find file with matching serials: vol %X file %X\n", volume_serial, file_serial);
	return "";
}


bool Pe::Get_drive_path_from_device_path(const std::string& device_path, std::string* drive_path)
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