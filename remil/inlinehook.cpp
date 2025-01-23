#include <iostream>
#include <Windows.h>
#include <psapi.h>

typedef BOOL(WINAPI* Beep_t)(DWORD, DWORD); 
Beep_t OriginalBeep = NULL;

BOOL WINAPI HookedBeep(DWORD dwFreq, DWORD dwDuration) {
    std::cout << "Beep function hooked! Frequency: " << dwFreq << ", Duration: " << dwDuration << std::endl;
    return TRUE;
}

void ListDLL(DWORD processID) {
    // I get a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | 
                                  PROCESS_VM_READ, 
                                  FALSE, 
                                  processID);


    if (hProcess == NULL) {
        std::cout << "[X] - Error : Cannot get an handle to the process with process id : " << processID << std::endl;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        size_t numModules = cbNeeded / sizeof(HMODULE); // Number of DLL.

        for (size_t i = 0; i < numModules; i++) {
            CHAR szModName[MAX_PATH];

            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(CHAR))) {
                std::cout << "\t" << szModName << std::endl;
            }
        }

    }

    CloseHandle(hProcess);

}

void HookFunctionKernel32() {
  
    HMODULE hKernel32 = GetModuleHandleA("KERNEL32.DLL");
    
    if (hKernel32) {
        // I get the address of my Original Beep function.
        OriginalBeep = (Beep_t)GetProcAddress(hKernel32, "Beep");

        std::cout << OriginalBeep << std::endl;


        // I change in memory the permission
        // I want to change 14 bits so I overwrite OriginalBeep
        DWORD oldProtect;
        VirtualProtect((LPVOID)OriginalBeep, (SIZE_T)14, PAGE_EXECUTE_READWRITE, &oldProtect);

        // For 0x64 we use the opcode FF 25 (jmp[rip + offset])
        // Offset in my case is : 00 00 00 00

        BYTE patch[(SIZE_T)14] = { 0 };
        patch[0] = 0xFF;
        patch[1] = 0x25;
        patch[2] = 0x00;
        patch[3] = 0x00;
        patch[4] = 0x00;
        patch[5] = 0x00;
        // I go to the 6th byte because I want to jump my instruction (FF 25 00 00 00 00) then I put my new function
        *(void**)(patch + 6) = (void*)HookedBeep; 

        memcpy((LPVOID)OriginalBeep, patch, (SIZE_T)14);

        // I put back protection
        VirtualProtect((LPVOID) OriginalBeep, (SIZE_T)14, oldProtect, &oldProtect);


        std::cout << "Beep function hooked successfully!" << std::endl;
    }
    else {
        std::cout << "Failed to get handle for KERNEL32.DLL" << std::endl;
    }
   
}

int main() {

    DWORD actualPID = GetCurrentProcessId();

    std::cout << "Actual Process ID " << actualPID << std::endl;
    ListDLL(actualPID);
    HookFunctionKernel32();

    Beep(750, 300);
    return 0;
}