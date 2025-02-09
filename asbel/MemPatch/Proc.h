#pragma once

void dumpMem(DWORD pID);
void patchMem(DWORD pID);
bool ResumeProc(DWORD pID);
void interceptBreakpoints(DWORD pID, std::vector<patch_action>* patch_tasks);
int CreateProc();
int selectProcess();