#include "Helper.h"
#include "PatchActions.h"
#include <stdio.h>
#include <iostream>
#include <processthreadsapi.h>
#include <psapi.h>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

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
    for (unsigned int i = 0; i < processCount && !goodChoice; i++) {
        if ((DWORD)choice == processIDs[i]) {
            goodChoice = true;
        }
    }

    return goodChoice ? choice : -1;
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
    patch_action patch;
    patch.patchBytes = patchBytes;
    patch.patch_addr = lpBaseAddress;

    BOOL status = _patch(pID, patch);

    if (!status) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
    }
    else {
        printf("New Memory :\n");
        size_t dumpSize = 256;
        std::vector<unsigned char> bytes_buffer(dumpSize, 0);

        // Lire les nouvelles données pour les afficher
        size_t actuallyRead = _dump(pID, patch.patch_addr, bytes_buffer.data(), dumpSize);
        if (actuallyRead > 0) {
            pretty_print(bytes_buffer.data(), actuallyRead, static_cast<uintptr_t>(patchAddr));
        }
    }
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

    using NtResumeProcess_t = NTSTATUS(WINAPI*)(HANDLE);
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