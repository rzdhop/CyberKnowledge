#include "PatchActions.h"
#include <windows.h>
#include <vector>

void listPatchActions(std::vector<patch_action> patch_tasks) {
	printf("+----asbel's MemPatcher----+\n");
	printf("| Total patchs : %zu        |\n", patch_tasks.size());
	for (int i = 0; i < patch_tasks.size(); i++) {
		
		printf("|  [*] breakpoint : %p     |\n", patch_tasks[i].hwbp_addr);
		printf("|   |__ patch addr : %p    |\n", patch_tasks[i].patch_addr);
		printf("|   |__ patch data : %c... |\n", patch_tasks[i].patchBytes.data()[0]);
	}
	printf("+--------------------------+\n");
}

void addPatchActions(std::vector<patch_action>* patch_tasks) {

}

void delPatchActions(std::vector<patch_action>* patch_tasks) {

}