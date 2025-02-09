#include "PatchActions.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <vector>

void listPatchActions(std::vector<patch_action> patch_tasks) {
	printf("+----asbel's MemPatcher----+\n");
	printf("| Total patchs : %zu        |\n", patch_tasks.size());
	for (int i = 0; i < patch_tasks.size(); i++) {
		
		printf("|  [%d] breakpoint : %p     \n", i, patch_tasks[i].hwbp_addr);
		printf("|   |__ patch addr : %p    \n", patch_tasks[i].patch_addr);
		printf("|   |__ patch data : %c... \n", patch_tasks[i].patchBytes.data()[0]);
	}
	printf("+--------------------------+\n");
}

void addPatchActions(std::vector<patch_action>* patch_tasks) {
    patch_action action;
    unsigned long long hwbpAddr, patchAddr;

    printf("Entrez l'adresse du hardware breakpoint (hex) : ");
    std::cin >> std::hex >> hwbpAddr;
    action.hwbp_addr = reinterpret_cast<LPVOID>(hwbpAddr);

    printf("Entrez l'adresse du patch (hex) : ");
    std::cin >> std::hex >> patchAddr;
    action.patch_addr = reinterpret_cast<LPVOID>(patchAddr);

    printf("Entrez les octets du patch (ex: '90 90 90') : ");
    std::cin.ignore(); // Nettoyer le saut de ligne restant
    std::string patchDataStr;
    std::getline(std::cin, patchDataStr);
    std::istringstream iss(patchDataStr);
    unsigned int byte;

    while (iss >> std::hex >> byte) {
        action.patchBytes.push_back(static_cast<unsigned char>(byte));
    }

    patch_tasks->push_back(action);
    printf("Patch action ajoutée.\n");
}

void delPatchActions(std::vector<patch_action>* patch_tasks) {
    if (patch_tasks->empty()) {
        printf("Aucune patch action à supprimer.\n");
        return;
    }
    
    listPatchActions(*patch_tasks);

    printf("Entrez l'index du patch à supprimer (0-%u) : ", patch_tasks->size() - 1);
    size_t index;
    std::cin >> index;
    if (index >= patch_tasks->size()) {
        printf("Index invalide.\n");
        return;
    }
    patch_tasks->erase(patch_tasks->begin() + index);
    printf("Patch action supprimée.\n");
}

