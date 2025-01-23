#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <tlhelp32.h>

// Function declarations
void DebugLoop();
bool CreateAndDebugProcess(const std::wstring& targetExecutable);
bool bypassIsDebuggerPresentInTarget(HANDLE hProcess);

#endif // DEBUGGER_H
