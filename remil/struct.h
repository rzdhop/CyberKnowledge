#include <windows.h>

#ifdef _WIN64
#define PEB_OFFSET_BEING_DEBUGGED 0x2
#else
#define PEB_OFFSET_BEING_DEBUGGED 0x2
#endif

#ifdef _WIN64
#define PEB_OFFSET_NT_GLOBAL_FLAG 0xBC
#else
#define PEB_OFFSET_NT_GLOBAL_FLAG 0x68
#endif
