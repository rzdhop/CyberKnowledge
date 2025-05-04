#include <ntifs.h>
#include <intrin.h>
#pragma intrinsic(__readmsr)

#define LSTAR 0xC0000082

typedef struct _KSERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR ServiceTable;
    ULONG_PTR Reserved0;     // padding ? 
    ULONG ServiceLimit;
    PULONG_PTR ArgumentTable;
} KSDT, *PKSDT;


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[SSDT Enum] Bye !\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[SSDT Enum] Hi !\n");

    PUCHAR KiSystemCall64 = (PUCHAR)__readmsr(0xC0000082);
    DbgPrint("[SSDT Enum] LSTAR at : %p \n", KiSystemCall64);

    for (int i = 0; i < 0x500; i++) {
        if (*(KiSystemCall64 + i) == 0x4c && *(KiSystemCall64 + (i + 1)) == 0x8d && *(KiSystemCall64 + (i + 2)) == 0x15) {
            int offset = *(int*)(KiSystemCall64 + (i + 3));
            PKSDT KeServiceDescriptorTable = (PKSDT)(KiSystemCall64 + i + 7 + offset); //Post instruction's opcode
            DbgPrint("[SSDT Enum] KeServiceDescriptorTable at : %p \n", KeServiceDescriptorTable);

            PULONG_PTR KiServiceTable = KeServiceDescriptorTable->ServiceTable;
            ULONG NbEntry = KeServiceDescriptorTable->ServiceLimit;
            if (!MmIsAddressValid(KiServiceTable)) break;
            DbgPrint("[SSDT Enum] KiServiceTable at : %p \n", KiServiceTable);

            for (int x = 0; x < (int)NbEntry; x++) {
                UINT32 offset_SSDT = ((int*)KiServiceTable)[x];
                void* function = (PUCHAR)KiServiceTable + (offset_SSDT >> 4);
                DbgPrint("[SSDT Enum] Index %d : %p\n", x, function);
            }
            break;
        }
    }

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}