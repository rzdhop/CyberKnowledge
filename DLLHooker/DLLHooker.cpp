#include <Windows.h>
#include <iostream>
#include <vector>

int main()
{

    DWORD pcbBytesNeeded = 0; //Size needed for services
    DWORD lpServicesReturned = 0; //Number of services entries
    DWORD lpResumeHandle = 0; //start of function is the point of enum and on output is the point of end of enumeration
    LPBYTE servicesHolder = NULL;

    char choice;

    printf("\nGetting Service Controle Handle...\n");
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        printf("Cannot obtain handle on Service Control Manager\n");
        return 1;
    }


    //First call to get required size
    EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER, SERVICE_STATE_ALL, NULL, 0, &pcbBytesNeeded, &lpServicesReturned, &lpResumeHandle, NULL);
    DWORD errCode = GetLastError(); //https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes
    if (errCode != (0 | ERROR_MORE_DATA)) {
        printf("Cannot enumerate services (code: %ld)", errCode);
        CloseServiceHandle(hSCManager);
        return errCode;
    }

    servicesHolder = (LPBYTE)malloc(pcbBytesNeeded);
    if (!servicesHolder) {
        printf("Failed to allocate memory for services.\n");
        CloseServiceHandle(hSCManager);
        return 1;
    }

    if (!EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER, SERVICE_STATE_ALL, servicesHolder, pcbBytesNeeded, &pcbBytesNeeded, &lpServicesReturned, &lpResumeHandle, NULL)) {
        DWORD errCode = GetLastError();
        printf("Cannot enumerate services. Error code: %ld\n", errCode);
        free(servicesHolder);
        CloseServiceHandle(hSCManager);
        return errCode;
    }

    printf("Found %ld Services:\n", lpServicesReturned);
    LPENUM_SERVICE_STATUS_PROCESSA services = (LPENUM_SERVICE_STATUS_PROCESSA)servicesHolder;

    if (lpServicesReturned >= (DWORD)10) {
        printf("Do you want to print all of them ? [y/n] (default : n) ");
        choice = getchar();
        if ((choice == 'y')) {
            for (DWORD i = 0; i < lpServicesReturned; i++) {
                printf(" [%ld] %s (Display name: %s)\n", i, services[i].lpServiceName, services[i].lpDisplayName);
            }
        }
    }
    
    free(servicesHolder);
    CloseServiceHandle(hSCManager);

    return 0;
}