#include "Helper.h"
#include "PatchActions.h"
#include <stdio.h>
#include <iostream>
#include <processthreadsapi.h>
#include <psapi.h>

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

bool _patch(DWORD pID, patch_action patch) {
    // Ouverture du process
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    // -- Rendre la zone mémoire écrivable (PAGE_EXECUTE_READWRITE) --
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, patch.patch_addr, patch.patchBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "VirtualProtectEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    SIZE_T bytesWritten = 0;
    BOOL status = WriteProcessMemory(hProcess,
        (LPVOID)patch.patch_addr,
        patch.patchBytes.data(),
        patch.patchBytes.size(),
        &bytesWritten);

    // Restaurer la protection initiale
    DWORD temp = 0;
    VirtualProtectEx(hProcess, patch.patch_addr, patch.patchBytes.size(), oldProtect, &temp);

    CloseHandle(hProcess);
    return true;
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