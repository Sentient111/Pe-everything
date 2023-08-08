#include "Pe.h"
#include <Winnt.h>
#include <wow64apiset.h>

Process::Process(Error_struct* error_handeling, const OPTIONAL std::string& process)
{
	error = error_handeling;
	RESET_ERR();
	if (process.size() == 0)
	{
		pid = GetCurrentProcessId();
		process_handle = GetCurrentProcess();
		is_local_context = true;
	}
	else
	{
		is_local_context = false;
		pid = Get_pid_by_name(process);
		if (!pid)
			return;

		process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if (!process_handle || process_handle == INVALID_HANDLE_VALUE)
		{
			error->last_err = GetLastError();
			error->error_comment = CREATE_ERROR("Failed to open process %X\n", error->last_err);
			return;
		}
	}

	BOOL is_wow_64 = 0;
	if (!IsWow64Process(process_handle, &is_wow_64))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("Failed to query wow 64 %X\n", error->last_err);
		return;
	}
	is_32_bit = is_wow_64;

	char full_path[MAX_PATH] = { 0 };
	if (!K32GetModuleFileNameExA(process_handle, NULL, (LPSTR)&full_path, sizeof(full_path)))
	{
		error->last_err = GetLastError();
		error->error_comment = CREATE_ERROR("failed to get full process path %X\n", error->last_err);
		return;
	}
	process_path = full_path;
	process_name = process_path.substr(process_path.find_last_of('\\') + 1);
}
