#include "Helper.h"
#include "PatchActions.h"
#include "Proc.h"

#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string>
#include <sstream>
#include <processthreadsapi.h>

//CPL cmd > g++ .\mempatcher.cpp -lpsapi -o mempatcher.exe

int main(int argc, char** argv) {
    int choice;
    DWORD pID = -1;
    std::vector<patch_action> patch_tasks;

    printf("+----rzdhop's MemPatcher----+\n");
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
        break;
    default:
        printf("Unknown choice!\n");
        break;
    }

    if (pID == -1) {
        return 0;
    }

    bool loop = true;

    while (loop) {
        printf("+----rzdhop's MemPatcher----+\n");
        printf("|                         |\n");
        printf("| Menu (pID %lu):         |\n", pID);
        printf("|    1) dumMem            |\n");
        printf("|    2) patchMem          |\n");
        printf("|                         |\n");
        printf("| (patch actions):        |\n");
        printf("|    3) [list]            |\n");
        printf("|    4) [add]             |\n");
        printf("|    5) [del]             |\n");
        printf("|                         |\n");
        printf("|    6) resumeProc        |\n");
        printf("|                         |\n");
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
            listPatchActions(patch_tasks);
            break;
        case 4:
            addPatchActions(&patch_tasks);
            break;
        case 5:
            delPatchActions(&patch_tasks);
            break;
        case 6:
            interceptBreakpoints(pID, &patch_tasks);
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
