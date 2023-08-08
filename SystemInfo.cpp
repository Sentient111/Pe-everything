#include "Pe.h"

inline NTSTATUS Ud_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    const static PVOID querySysInfo = (PVOID)GetProcAddress(LoadLibraryA("Ntdll.dll"), "NtQuerySystemInformation");
    return (*(NTSTATUS(__stdcall**)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))(&querySysInfo))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

template <typename Ret_struct>
DWORD QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, Ret_struct** ret)
{
    size_t try_num = 0;
    ULONG needed_size = 0;
    NTSTATUS status = ERROR_SUCCESS;

    Ud_NtQuerySystemInformation(SystemInfoClass, NULL, needed_size, &needed_size);
    if (!needed_size)
        return ERROR_BAD_LENGTH;
    
    do
    {
        Ret_struct* buff = (Ret_struct*)malloc(needed_size);
        status = Ud_NtQuerySystemInformation(SystemInfoClass, buff, needed_size, &needed_size);
        if (status != ERROR_SUCCESS) //STATUS_SUCESS is the same
        {
            free(buff);
            continue;
        }

        *ret = buff;
        return status;

    } while (MAX_QUERY_TRIES >= ++try_num);

    return ERROR_MOD_NOT_FOUND;
}



#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)11

bool Pe::Get_driver_info(IN const std::string& name, OPTIONAL std::string* path, OPTIONAL ULONGLONG* base)
{
    RESET_ERR();

    PSYSTEM_MODULE_INFORMATION module_information = 0;
    DWORD err = QuerySystemInformation(SystemModuleInformation, &module_information);
    if (err != ERROR_SUCCESS)
    {
        error->last_err = err;
        error->error_comment = CREATE_ERROR("Failed to query system module information %X\n", err);
        return false;
    }

    for (unsigned int i = 0; i < module_information->Count; i++)
    {
        if (!module_information->Module[i].FullPathName)
            continue;

        char* file_name = (char*)module_information->Module[i].FullPathName + module_information->Module[i].OffsetToFileName;
        if (strcmp(file_name, name.c_str()))
            continue;
        
        if (path)
        {
            std::string driver_path = (char*)module_information->Module[i].FullPathName;
            const char system_root_str[] = "\\SystemRoot";

            if (memcmp(driver_path.c_str(), system_root_str, sizeof(system_root_str) - 1) == 0)
            {
                std::string system_dir = "";
                if (Get_system_dir(&system_dir))
                    return false;

                driver_path = system_dir + "\\" + driver_path.substr(sizeof(system_root_str));
            }

            *path = driver_path;
        }
        if (base)
            *base = module_information->Module[i].ImageBase;

        free(module_information);
        return true;

    }

    free(module_information);
    error->last_err = ERROR_FILE_NOT_FOUND;
    error->error_comment = CREATE_ERROR("Failed to find driver by name %s\n", name.c_str());
    return false;
}