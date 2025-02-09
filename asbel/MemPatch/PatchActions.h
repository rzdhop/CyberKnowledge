#pragma once
#include <windows.h>
#include <vector>

struct patch_action {
    LPVOID hwbp_addr = nullptr;
    LPVOID patch_addr = nullptr;
    std::vector<unsigned char> patchBytes;
};

void listPatchActions(std::vector<patch_action> patch_tasks);
void addPatchActions(std::vector<patch_action>* patch_tasks);
void delPatchActions(std::vector<patch_action>* patch_tasks);