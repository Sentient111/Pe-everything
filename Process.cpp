#include "Pe.h"
#include <Winnt.h>
#include <wow64apiset.h>

Process::Process(const OPTIONAL std::string& process)
{
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
			last_err = GetLastError();
			error_comment = CREATE_ERROR("Failed to open process %X\n", last_err);
			return;
		}
	}

	BOOL is_wow_64 = 0;

	if (!IsWow64Process(process_handle, &is_wow_64))
	{
		last_err = GetLastError();
		error_comment = CREATE_ERROR("Failed to query wow 64 %X\n", last_err);
		return;
	}

	is_32_bit = is_wow_64;


	if (!Get_mod_infoEx(process, 0, &process_path))
		return;

	process_name = process_path.substr(process_path.find_last_of('\\') + 1);
}
