#pragma once
#include "PatchActions.h"

void pretty_print(unsigned char* byte_buffer, size_t byte_buffer_len, uintptr_t startAddress);
bool _patch(DWORD pID, patch_action patch);
size_t _dump(DWORD pID, LPCVOID lpBaseAddress, LPVOID lpBuffer, size_t dumpSize);
bool sethwbp(HANDLE hThread, LPVOID address);
bool delhwbp(HANDLE hThread, LPVOID address);