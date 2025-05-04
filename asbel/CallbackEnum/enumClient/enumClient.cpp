#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

namespace callbackEnum {
    namespace ioctl_codes {
        constexpr ULONG processCallbackEnum = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    struct REQUEST {
        HANDLE process; //process attached

        PVOID target; //Mem target addrr
        PVOID buffer; //Mem content

        SIZE_T buffer_size;
        SIZE_T return_size;
    };
}

DWORD get_process_id(const wchar_t* process_name)
{
    DWORD  pid = 0;
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap_shot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snap_shot, &entry) == TRUE)
    {
        do
        {
            if (_wcsicmp(process_name, entry.szExeFile) == 0) //wide string cmp
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap_shot, &entry) == TRUE);
    }
    else
    {
        printf("Process32FirstW failed (err=%lu)\n", GetLastError());
    }

    CloseHandle(snap_shot);
    return pid;
}

/* Renvoie l’adresse de base (DWORD_PTR) d’un module précis dans un process donné.
   0 → module introuvable / erreur. */
DWORD_PTR get_module_base(DWORD pid, const wchar_t* module_name)
{
    DWORD_PTR module_base = 0;

    /* snapshot limitée au process ciblé */
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snap_shot, &entry) == TRUE)
    {
        do
        {
            if (_wcsicmp(module_name, entry.szModule) == 0)
            {
                module_base = (DWORD_PTR)entry.modBaseAddr;   /* adresse de base   */
                break;
            }
        } while (Module32NextW(snap_shot, &entry) == TRUE);
    }
    else
    {
        printf("Module32FirstW failed (err=%lu)\n", GetLastError());
    }

    CloseHandle(snap_shot);
    return module_base;
}

int main() {

	return 0;
}