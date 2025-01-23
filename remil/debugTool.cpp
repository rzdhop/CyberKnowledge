#include "debugger.h"
#include "struct.h"

/**
* This function handle the debug
*/
void DebugLoop() {
    DEBUG_EVENT debugEvent;

    while (true) {
        if (WaitForDebugEvent(&debugEvent, INFINITE)) {
            switch (debugEvent.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                std::wcout << L"[+] - Process created. Base address: "
                    << debugEvent.u.CreateProcessInfo.lpBaseOfImage << std::endl;
                break;

            case EXIT_PROCESS_DEBUG_EVENT:
                std::wcout << L"[+] - Process exited. Exit code: "
                    << debugEvent.u.ExitProcess.dwExitCode << std::endl;
                return;

            case EXCEPTION_DEBUG_EVENT:
                std::wcout << L"[!] - Exception code: "
                    << std::hex << debugEvent.u.Exception.ExceptionRecord.ExceptionCode
                    << std::endl;
                break;

            default:
                std::wcout << L"[+] - Debug event code: "
                    << debugEvent.dwDebugEventCode << std::endl;
                break;
            }
			// We continue to the debug
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        }
        else {
            std::wcerr << L"[X] - WaitForDebugEvent failed. Error: " << GetLastError() << std::endl;
            break;
        }
    }
}


/**
* This function create a process in debug mode and disable the `isDebuggerPresent` in the target process
* 
* @param targetExecutable : Path of the target executable
* 
* return : true if the process is created and debugged, false otherwise
*/
bool CreateAndDebugProcess(const std::wstring& targetExecutable) {
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    si.cb = sizeof(STARTUPINFO);

    // https://learn.microsoft.com/fr-fr/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    if (CreateProcess(
        targetExecutable.c_str(),   // Name of the process
        NULL,                       // 
        NULL,                       //
        NULL,                       // 
        FALSE,                      //
        CREATE_SUSPENDED,           // 
        NULL,                       // 
        NULL,                       // 
		&si,                        // Startup information (like size windows)
		&pi                         // Process information
    )) {
        std::wcout << L"[+] - Process created successfully with PID: " << pi.dwProcessId << std::endl;


        if (!bypassIsDebuggerPresentInTarget(pi.hProcess)) {
			TerminateProcess(pi.hProcess, -1);
            CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

            return false;
        }

		ResumeThread(pi.hThread);
        std::wcout << L"[+] - Process resumed." << std::endl;

		if (DebugActiveProcess(pi.dwProcessId)) { // I attach the debugger to the process after the process is created
            DebugLoop();
        }
        else {
            std::wcerr << L"[X] - Failed to attach debugger. Error: " << GetLastError() << std::endl;
        }

        // I clean ressource of my process
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    
        return true;
    }
    else {
        std::wcerr << L"Échec de la création du processus (Erreur : " << GetLastError() << L")" << std::endl;
        return false;
    }
}


/**
* This function can bypass the `isDebuggerPresent` in the target process
* 
* @param hProcess : Handle of the target process
* 
* return : true if the bypass is successful, false otherwise
*/
bool bypassIsDebuggerPresentInTarget(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    /*
        NTSTATUS : Return type of the function
        NTAPI    : Calling Convention of the function (for arguments)


        I do this for the compiler for that I knows the correct signature
        of the function.

        Indeed doing a typedef in my case is for create like a "shortcut" for more complex type
        That allow me to not rewrite again and again the same definition everytime that I will use
        information about process

    */
    typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)(
        HANDLE,
        ULONG,
        PVOID,
        ULONG,
        PULONG
    );

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll"); // I get the module `ntdll.dll`

	if (!hNtdll) {
		std::cerr << "[X] - Failed to get ntdll.dll" << std::endl;
		return false;
	}

	// I get the address of the function `NtQueryInformationProcess` in the module `ntdll.dll`
	// NtQueryInformationProcess allow me to get information about a process
	PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (!NtQueryInformationProcess) {
		std::cerr << "[X] - Failed to get address of NtQueryInformationProcess" << std::endl;
		return false;
	}
       
    // Here I get information about the process
	NTSTATUS status = NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation, // I only need basic information
		&pbi, // Where I put information
		sizeof(PROCESS_BASIC_INFORMATION),
		&returnLength
	);

	if (status != 0) { // STATUS_SUCCESS == 0
		std::cerr << "[X] - Failed to get information about the process" << std::endl;
		return false;
	}

    BYTE beingDebugged = 0; // Writing
	BYTE readBeingDebugged = 0; // Reading
	LPVOID address = (LPVOID)((BYTE*)pbi.PebBaseAddress + PEB_OFFSET_BEING_DEBUGGED); // I get the address of the `BeingDebugged` field in the PEB

	// In my case useless because I didn't use yet ResumeThread
	if (!ReadProcessMemory(hProcess, address, &readBeingDebugged, sizeof(readBeingDebugged), nullptr)) {
        std::cerr << "[X] - Failed to read PEB from target process. Error: " << GetLastError() << std::endl;
        return false;
    }

	std::cout << "[+] - IsDebuggerPresent: " << (int)readBeingDebugged << std::endl;

    SIZE_T byteWritten;
	if (!WriteProcessMemory(hProcess, address, &beingDebugged, sizeof(beingDebugged), &byteWritten)) {
		std::cerr << "[X] - Failed to write PEB from target process. Error: " << GetLastError() << std::endl;
		return false;
	}


	std::cout << "[+] - Bypassed IsDebuggerPresent " << std::endl;

	return true;


}

int main() {
    std::wstring targetExecutable;

    std::wcout << L"[+] - Enter the path of the process that you want to debug : ";
    std::getline(std::wcin, targetExecutable);

    if (CreateAndDebugProcess(targetExecutable)) {
        std::wcout << L"[+] - You can debug " << std::endl;
    }
    else {
        std::wcerr << L"[X] - Cannot debug" << std::endl;
    }

    return 0;
}
