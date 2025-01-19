#include <Windows.h>
#include <iostream>
#include <vector>
#include <psapi.h>

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPriv;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token. Error code: %ld\n", GetLastError());
        return false;
    }

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPriv.Privileges[0].Luid);
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Failed to adjust token privileges. Error code: %ld\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("Debug privilege is not assigned.\n");
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}


void ListProcessModules(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        printf("Failed to open process with ID %ld. Error code: %ld\n", processID, GetLastError());
        return;
    }

    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        printf("DLLs loaded by process %ld:\n", processID);
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char moduleName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hModules[i], moduleName, sizeof(moduleName) / sizeof(char))) {
                printf("  [%u] %s\n", i + 1, moduleName);
            }
        }
    } else {
        printf("Failed to enumerate modules. Error code: %ld\n", GetLastError());
    }

    CloseHandle(hProcess);
}

LPENUM_SERVICE_STATUS_PROCESSA EnumerateSystemServices(SC_HANDLE hSCManager, DWORD dwServiceType) {
    DWORD pcbBytesNeeded = 0;
    DWORD lpServicesReturned = 0;
    DWORD lpResumeHandle = 0;
    LPBYTE servicesHolder = NULL;

    // First call to get required size
    EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, dwServiceType, SERVICE_ACTIVE,
                          NULL, 0, &pcbBytesNeeded, &lpServicesReturned, &lpResumeHandle, NULL);
    DWORD errCode = GetLastError();
    if (errCode != ERROR_MORE_DATA) {
        printf("Cannot enumerate services (code: %ld)\n", errCode);
        return NULL;
    }

    servicesHolder = (LPBYTE)malloc(pcbBytesNeeded);
    if (!servicesHolder) {
        printf("Failed to allocate memory for services.\n");
        return NULL;
    }

    if (!EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, dwServiceType, SERVICE_ACTIVE,
                                servicesHolder, pcbBytesNeeded, &pcbBytesNeeded, &lpServicesReturned, &lpResumeHandle, NULL)) {
        printf("Cannot enumerate services. Error code: %ld\n", GetLastError());
        free(servicesHolder);
        return NULL;
    }

    printf("Found %ld Services:\n", lpServicesReturned);
    LPENUM_SERVICE_STATUS_PROCESSA services = (LPENUM_SERVICE_STATUS_PROCESSA)servicesHolder;

      if (lpServicesReturned >= (DWORD)10) {
        printf("Do you want to print all of them ? [y/n] (default : n) ");
        char choice = getchar();
        if ((choice == 'y')) {
            for (DWORD i = 0; i < lpServicesReturned; i++) {
                printf(" [%ld] %s (Display name: %s)\n", i, services[i].lpServiceName, services[i].lpDisplayName);
            }
        } else {
            printf("Here is a extract (10 first services) :\n");
            for (DWORD i = 0; i < 10; i++) {
                printf(" [%ld] %s (Display name: %s)\n", i, services[i].lpServiceName, services[i].lpDisplayName);
            }
        }
    }
    return services;
}

QUERY_SERVICE_CONFIGA* GetServiceInfo(SC_HANDLE hSCManager, LPCSTR lpServiceName) {
    SC_HANDLE hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_QUERY_CONFIG);
    if (!hService) {
        printf("Failed to open service. Error code: %ld\n", GetLastError());
        return NULL;
    }

    DWORD configSize = 0;
    QueryServiceConfigA(hService, NULL, 0, &configSize);

    QUERY_SERVICE_CONFIGA* serviceConfig = (QUERY_SERVICE_CONFIGA*)malloc(configSize);
    if (!serviceConfig) {
        printf("Failed to allocate memory for service configuration.\n");
        CloseServiceHandle(hService);
        return NULL;
    }

    if (!QueryServiceConfigA(hService, serviceConfig, configSize, &configSize)) {
        printf("Failed to query service configuration. Error code: %ld\n", GetLastError());
        free(serviceConfig);
        CloseServiceHandle(hService);
        return NULL;
    }

    CloseServiceHandle(hService);
    return serviceConfig;
}

bool IsServiceRunning(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD* processID) {
    SC_HANDLE hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        printf("Failed to open service. Error code: %ld\n", GetLastError());
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        printf("Failed to query service status. Error code: %ld\n", GetLastError());
        CloseServiceHandle(hService);
        return false;
    }

    CloseServiceHandle(hService);

    if (status.dwCurrentState == SERVICE_RUNNING) {
        *processID = status.dwProcessId;
        return true;
    }

    return false;
}

int main() {
    if (!EnableDebugPrivilege()) {
        printf("Failed to enable debug privileges. Some processes may not be accessible.\n");
    }

    printf("\nGetting Service Control Handle...\n");
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        printf("Cannot obtain handle on Service Control Manager. Error code: %ld\n", GetLastError());
        return 1;
    }

    LPENUM_SERVICE_STATUS_PROCESSA services = EnumerateSystemServices(hSCManager,SERVICE_WIN32);
    if (!services) {
        CloseServiceHandle(hSCManager);
        return 1;
    }

    printf("\nWhich service do you want to hook? (Enter ID): ");
    int choice;
    std::cin >> choice;

    if (choice < 0) {
        printf("Invalid choice.\n");
        free(services);
        CloseServiceHandle(hSCManager);
        return 1;
    }
    printf("Selecting %d : %s ...\n", choice, services[choice].lpServiceName);
    LPCSTR serviceName = services[choice].lpServiceName;
    QUERY_SERVICE_CONFIGA* serviceInfo = GetServiceInfo(hSCManager, serviceName);
    if (!serviceInfo) {
        free(services);
        CloseServiceHandle(hSCManager);
        return 1;
    }

    printf("Executable Path: %s\n", serviceInfo->lpBinaryPathName);

    DWORD processID;
    if (IsServiceRunning(hSCManager, serviceName, &processID)) {
        printf("Service is running. Process ID: %ld\n", processID);
        ListProcessModules(processID);
    } else {
        printf("Service is not running.\n");
    }

    free(serviceInfo);
    free(services);
    CloseServiceHandle(hSCManager);

    return 0;
}
