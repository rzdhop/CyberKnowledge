#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <tlhelp32.h>
#include <string>
#include <sstream>
#include <processthreadsapi.h>
#include <filesystem>

namespace fs = std::filesystem;
//CPL cmd > g++ .\mempatcher.cpp -lpsapi -o mempatcher.exe


void pretty_print(unsigned char* byte_buffer, size_t byte_buffer_len, uintptr_t startAddress) {
    for (size_t i = 0; i < byte_buffer_len; i++) {
        if (i % 16 == 0) {
            if (i != 0) {
                printf("  ");
                for (size_t j = i - 16; j < i; j++) {
                    if (isprint(byte_buffer[j])) {
                        printf("%c", byte_buffer[j]);
                    }
                    else {
                        printf(".");
                    }
                }
            }
            printf("\n%08lx  ", static_cast<unsigned long>(startAddress + i));
        }

        if (i % 4 == 0 && i % 16 != 0) {
            printf(" ");
        }
        printf("%02X ", byte_buffer[i]);
    }

    size_t remainder = byte_buffer_len % 16;
    if (remainder != 0) {
        for (size_t i = 0; i < (16 - remainder); i++) {
            printf("   ");
            if ((i + remainder) % 4 == 0) {
                printf(" ");
            }
        }
        printf("  ");
        for (size_t i = byte_buffer_len - remainder; i < byte_buffer_len; i++) {
            if (isprint(byte_buffer[i])) {
                printf("%c", byte_buffer[i]);
            }
            else {
                printf(".");
            }
        }
    }
    printf("\n");
}

int selectProcess() {
    DWORD processIDs[1024], bytesReturned, processCount;

    if (!EnumProcesses(processIDs, sizeof(processIDs), &bytesReturned)) {
        printf("Failed to enumerate processes. Error code: %lu\n", GetLastError());
        return -1;
    }

    processCount = bytesReturned / sizeof(DWORD);
    printf("\nNumber of running processes: %lu\n", processCount);

    for (size_t i = 0; i < processCount; i++) {
        if (processIDs[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIDs[i]);
            if (hProcess) {
                HMODULE hModule;
                DWORD cbNeeded;

                if (EnumProcessModulesEx(hProcess, &hModule, sizeof(hModule), &cbNeeded, LIST_MODULES_ALL)) {
                    char processPath[MAX_PATH] = { 0 };
                    if (GetModuleFileNameExA(hProcess, hModule, processPath, MAX_PATH)) {
                        printf("[+] pID: %lu\tPath: %s\n", processIDs[i], processPath);
                    }
                    else {
                        printf("[-] pID: %lu\tCould not retrieve path.\n", processIDs[i]);
                    }
                }
                else {
                    printf("[-] pID: %lu\tCould not retrieve process modules.\n", processIDs[i]);
                }
                CloseHandle(hProcess);
            }
        }
    }

    printf("Which process do you want to attach ? \n> ");
    int choice;
    std::cin >> choice;

    bool goodChoice = false;
    for (int i = 0; i < processCount && !goodChoice; i++) {
        if ((DWORD)choice == processIDs[i]) {
            goodChoice = true;
        }
    }

    return goodChoice ? choice : -1;
}

size_t _dump(DWORD pID, LPCVOID lpBaseAddress, LPVOID lpBuffer, size_t dumpSize) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return 0;
    }

    SIZE_T bytesRead = 0;
    BOOL status = ReadProcessMemory(hProcess,
        lpBaseAddress,
        lpBuffer,
        dumpSize,
        &bytesRead);
    CloseHandle(hProcess);

    if (!status) {
        std::cerr << "ReadProcessMemory failed: " << GetLastError() << std::endl;
        return 0;
    }
    return bytesRead;
}

void dumpMem(DWORD pID) {
    std::string startAddr_str;
    size_t dumpSize;

    printf("\nDump address (hex)   : ");
    std::cin >> startAddr_str;
    printf("\nDump size (in bytes) : ");
    std::cin >> dumpSize;

    if (startAddr_str.rfind("0x", 0) == 0 || startAddr_str.rfind("0X", 0) == 0) {
        startAddr_str.erase(0, 2);
    }

    uintptr_t startAddr = std::stoull(startAddr_str, nullptr, 16);
    LPCVOID lpBaseAddress = reinterpret_cast<LPCVOID>(startAddr);

    // Allocation du buffer
    std::vector<unsigned char> bytes_buffer(dumpSize, 0);

    // Lecture mémoire
    size_t actuallyRead = _dump(pID, lpBaseAddress, bytes_buffer.data(), dumpSize);
    if (actuallyRead > 0) {
        pretty_print(bytes_buffer.data(), actuallyRead, startAddr);
    }
}

void patchMem(DWORD pID) {
    std::string addr_str;
    std::string data_str;

    printf("\nPatch address (hex) : ");
    std::cin >> addr_str;
    if (addr_str.rfind("0x", 0) == 0 || addr_str.rfind("0X", 0) == 0) {
        addr_str.erase(0, 2);
    }
    uintptr_t patchAddr = std::stoull(addr_str, nullptr, 16);
    LPVOID lpBaseAddress = reinterpret_cast<LPVOID>(patchAddr);

    // Lecture des données à patcher (ex : "90 90 90")
    printf("Hex bytes to write (e.g. 90 90 90) : ");
    std::cin.ignore();

    std::string input;
    std::getline(std::cin, input);

    std::vector<unsigned char> patchBytes;
    {
        std::istringstream iss(input);
        std::string byte;
        while (iss >> byte) {
            patchBytes.push_back(static_cast<unsigned char>(std::stoul(byte, nullptr, 16)));
        }
    }

    // Ouverture du process
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return;
    }

    // -- Rendre la zone mémoire écrivable (PAGE_EXECUTE_READWRITE) --
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, lpBaseAddress, patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "VirtualProtectEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return;
    }

    SIZE_T bytesWritten = 0;
    BOOL status = WriteProcessMemory(hProcess,
        lpBaseAddress,
        patchBytes.data(),
        patchBytes.size(),
        &bytesWritten);

    // Restaurer la protection initiale
    DWORD temp = 0;
    VirtualProtectEx(hProcess, lpBaseAddress, patchBytes.size(), oldProtect, &temp);

    if (!status) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
    }
    else {
        printf("New Memory :\n");
        size_t dumpSize = 256;
        std::vector<unsigned char> bytes_buffer(dumpSize, 0);

        // Lire les nouvelles données pour les afficher
        size_t actuallyRead = _dump(pID, lpBaseAddress, bytes_buffer.data(), dumpSize);
        if (actuallyRead > 0) {
            pretty_print(bytes_buffer.data(), actuallyRead, static_cast<uintptr_t>(patchAddr));
        }
    }

    CloseHandle(hProcess);
}

bool ResumeProc(DWORD pID) {
    // https://www.pinvoke.net/default.aspx/ntdll/NtResumeProcess.html
    // Récupère la fonction NtResumeProcess de ntdll.dll
    /*
        NtResumeProcess_t défini par :
            - NTSTATUS WINAPI <function>(HANDLE){}
            - <retType> <function> <ArgType>
        
        NTSTATUS -> type de retour d'apres le reverse de la fonction
        WINAPI   -> macro pour __stdcall
        (WINAPI *) -> defini la fonction
    */

    using NtResumeProcess_t = NTSTATUS(WINAPI *)(HANDLE);
    NtResumeProcess_t NtResumeProcess = nullptr; //sera le ptr sur la fonction de ntdll.dll

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        NtResumeProcess = reinterpret_cast<NtResumeProcess_t>(GetProcAddress(hNtDll, "NtResumeProcess"));
    }
    if (!NtResumeProcess) {
        std::cerr << "Failed to locate NtResumeProcess in ntdll.dll" << std::endl;
        exit(1);
    }

    // Ouvrir un handle au processus cible
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pID);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Resumer tous les threads du processus
    BOOL status = NtResumeProcess(hProcess);
    CloseHandle(hProcess);

    if (status != 0) {
        std::cerr << "Failed to resume process. Error: " << GetLastError() << std::endl;
        return false;
    }

    printf("Process with PID %lu resumed successfully.\n", pID);
    return true;
}


int CreateProc() {
    printf("Enter path to executable : \n> ");
    std::cin.ignore();
    std::string input;
    std::getline(std::cin, input);

    printf("Enter args (optional | separated by space) : \n> ");
    std::cin.ignore();
    std::string args;
    std::getline(std::cin, args);
    
    // Maybe One day : option to use as another user (user token (e.g: runas...))
    // use of CreateProcessAsUserA & LogonUserA

    if (!fs::exists(input)) {
        return -1;
    }
    STARTUPINFOA si = { 0 }; 
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOA);

    // Combiner le chemin de l'exécutable et ses arguments
    std::string cmdLine = "\"" + input + "\" " + args;

    BOOL result = CreateProcessA(
        input.c_str(),                        
        cmdLine.data(),
        nullptr,          // Pas de sécurité pour le processus
        nullptr,          // Pas de sécurité pour le thread
        FALSE,            // Héritage des handles non permis
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        nullptr,          // Variables d'environnement (null = hérite)
        nullptr,          // Répertoire de travail courant
        &si,              // Informations sur la fenêtre
        &pi               // Informations sur le processus
    );

    if (!result) {
        std::cerr << "Failed to create process. Error: " << GetLastError() << std::endl;
        return -1;
    }

    printf("Process created in suspended mode. PID: %lu\n", pi.dwProcessId);

    // Close handles on processInfo
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return pi.dwProcessId;
}

int main(int argc, char** argv) {
    int choice;
    DWORD pID = -1;

    printf("+----vRdu's MemPatcher----+\n");
    printf("|                         |\n");
    printf("| Patch:                  |\n");
    printf("|    1) Create proces     |\n");
    printf("|    2) Attach proces     |\n");
    printf("|    0) Exit              |\n");
    printf("|                         |\n");
    printf("+-- Choice: ");
    std::cin >> choice;

    switch (choice) {
    case 1:
        pID = CreateProc();
        break;
    case 2:
        pID = selectProcess();
        break;
    case 0:
        printf("\n[-]Bye !");
        return 0;
    default:
        printf("Unknown choice!\n");
        break;
    }

    if (pID == -1) {
        return 0;
    }

    bool loop = true;

    while (loop) {
        printf("+----vRdu's MemPatcher----+\n");
        printf("|                         |\n");
        printf("| Menu (pID %lu):         |\n", pID);
        printf("|    1) dumMem            |\n");
        printf("|    2) patchMem          |\n");
        printf("|    3) ResumeProc        |\n");
        printf("|    0) Exit              |\n");
        printf("|                         |\n");
        printf("+-- Choice: ");
        std::cin >> choice;

        switch (choice) {
        case 1:
            dumpMem(pID);
            break;
        case 2:
            patchMem(pID);
            break;
        case 3:
            ResumeProc(pID);
            break;
        case 0:
            printf("\n[-]Bye !");
            loop = false;
            break;
        default:
            printf("Unknown choice!\n");
            break;
        }
    }

    return 0;
}
