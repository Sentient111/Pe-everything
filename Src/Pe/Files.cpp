#include "..\Pe\Pe.h"

bool Pe::Get_system_dir(std::string* dir)
{
	int dir_name_len = GetSystemDirectoryA(NULL, NULL);
	if (!dir_name_len)
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to get system dir length\n");
		return false;
	}

	char* dir_path = new char[dir_name_len];

	if (!GetSystemDirectoryA(dir_path, dir_name_len))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to query system root dir\n");
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
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to get volume enumerator %X\n", GetLastError());
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
				error->last_err = GetLastError();
				error->error_comment = CREATE_ERROR("Failed to open file by id %X\n", GetLastError());
				return "";
			}

			char file_path[MAX_PATH] = { 0 };
			if (!GetFinalPathNameByHandleA(file_handle, (LPSTR)&file_path, sizeof file_path, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS))
			{
				CloseHandle(file_handle);
				error->last_err = GetLastError();
				error->error_comment = CREATE_ERROR("Failed to get path %X\n", GetLastError());
				return "";
			}

			return std::string(file_path);
		}
	} while (FindNextVolumeA(volume_enumerator, curr_volume_name, sizeof curr_volume_name));

	FindVolumeClose(volume_enumerator);
	error->last_err = ERROR_FILE_NOT_FOUND;
	error->error_comment = CREATE_ERROR("Failed to find file with matching serials: vol %X file %X\n", volume_serial, file_serial);
	return "";
}


