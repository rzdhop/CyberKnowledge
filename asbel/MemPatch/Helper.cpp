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

/*
   Les breakpoints peuvent être de deux types :

   1. Breakpoints logiciels :
      - Injection de l'instruction INT 3 (0xCC sur x86)
      - Déclenche une exception qui interrompt l'exécution
      - Inconvénient : modifie le code en mémoire

   2. Breakpoints matériels (Hardware breakpoints) :
      - Utilise les registres de débogage (DR0 à DR3 pour les adresses et DR7 pour le contrôle)
      - Permet de surveiller une adresse sans modifier le code
      - Limité à 4 breakpoints par processus
      - Procédure :
          a. Récupérer le contexte du thread avec GetThreadContext.
          b. Configurer un registre (ex. DR0) avec l'adresse cible.
          c. Activer le breakpoint en réglant DR7 (par exemple, activer le bit L0 pour DR0).
          d. Appliquer le nouveau contexte au thread avec SetThreadContext.


Throw exception de type EXCEPTION_SINGLE_STEP (code 0x80000004) 
 - Sofware exception : EXCEPTION_BREAKPOINT (code 0x80000003)


Exemple d'activation d'un breakpoint matériel sur DR0 :
       CONTEXT ctx = {0};
       ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
       if (GetThreadContext(hThread, &ctx)) {
           ctx.Dr0 = (DWORD_PTR)adresseX;  // Adresse à surveiller
           // Activation du breakpoint local 0 dans DR7 (bits L0).
           // Par défaut, les bits RW0 et LEN0 à 0 correspondent à un breakpoint d'exécution sur 1 octet.
           ctx.Dr7 |= 0x1;
           SetThreadContext(hThread, &ctx);
       }
*/

// Configure un breakpoint matériel sur l'adresse spécifiée dans le premier registre libre (DR0 à DR3).
bool sethwbp(HANDLE hThread, LPVOID address) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "GetThreadContext a échoué (erreur " << GetLastError() << ")" << std::endl;
        return false;
    }

    // Tableau de pointeurs sur les registres DR0 à DR3.
    DWORD_PTR* regs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
    // Bits correspondants dans DR7 pour activer localement chacun des breakpoints.
    DWORD enableBits[4] = { 0x1, 0x4, 0x10, 0x40 };

    int index = -1;
    for (int i = 0; i < 4; i++) {
        if (*regs[i] == 0) {  // Le registre est libre.
            index = i;
            break;
        }
    }
    if (index == -1) {
        std::cerr << "Aucun registre de breakpoint disponible." << std::endl;
        return false;
    }

    // Affecte l'adresse au registre libre trouvé.
    *regs[index] = reinterpret_cast<DWORD_PTR>(address);
    // Active le breakpoint en mettant le bit correspondant dans DR7.
    ctx.Dr7 |= enableBits[index];

    // Par défaut, les bits RW et LEN (qui déterminent le type et la taille) restent à 0,
    // ce qui correspond à un breakpoint d'exécution sur 1 octet.

    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "SetThreadContext a échoué (erreur " << GetLastError() << ")" << std::endl;
        return false;
    }
    return true;
}

// Supprime le breakpoint matériel sur l'adresse spécifiée en cherchant dans DR0 à DR3.
bool delhwbp(HANDLE hThread, LPVOID address) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "GetThreadContext a échoué (erreur " << GetLastError() << ")" << std::endl;
        return false;
    }

    DWORD_PTR* regs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
    DWORD enableBits[4] = { 0x1, 0x4, 0x10, 0x40 };

    bool found = false;
    for (int i = 0; i < 4; i++) {
        if (*regs[i] == reinterpret_cast<DWORD_PTR>(address)) {
            *regs[i] = 0; // Réinitialise le registre
            // Désactive le bit correspondant dans DR7.
            ctx.Dr7 &= ~enableBits[i];
            found = true;
            break;
        }
    }
    if (!found) {
        std::cerr << "Aucun breakpoint correspondant trouvé dans DR0-DR3." << std::endl;
        return false;
    }

    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "SetThreadContext a échoué (erreur " << GetLastError() << ")" << std::endl;
        return false;
    }
    return true;
}


