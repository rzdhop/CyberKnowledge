#include <ntifs.h>
 
#define IOCTL_ENUM_PROC_CB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_THRD_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x502, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_LIMG_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x503, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ENUM_CMRG_CB  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

//Define Unexported/Undocumented function from ntifs.h
extern "C" {
	//Implement the driver referencing (to create the DriverMain Entrypoint as driver entrypoint)
	NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

	/*
		//Implement R/W primitives for driver
		NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PUNICODE_STRING SourceProcess, PVOID SourceAddress,
												 PEPROCESS TargetProcess, PVOID TargetAddress,
												 SIZE_T BufferSize, KPROCESSOR_MODE PreviousM0de,
												 PSIZE_T ReturnSize);
	*/
}

typedef struct _CMREG_CALLBACK {
	LIST_ENTRY List;
	ULONG Unknown1;
	ULONG Unknown2;
	LARGE_INTEGER Cookie;
	PVOID Unknown3;
	PEX_CALLBACK_FUNCTION Function;
} CMREG_CALLBACK, * PCMREG_CALLBACK;

struct REQUEST {
	ULONG64 buffer[500];
	SIZE_T count;
};


REQUEST do_enumProcessCallbacks() {
	REQUEST ret_req = {};
	UNICODE_STRING us = RTL_CONSTANT_STRING(L"PsSetCreateProcessNotifyRoutine");
	PUCHAR psStub = (PUCHAR)MmGetSystemRoutineAddress(&us);
	PUCHAR pspStub = nullptr;
	if (!psStub) return ret_req;
	DbgPrint("[CallbackEnum] PsSetCreateProcessNotifyRoutine : %p", psStub);

	//De PsSetCreateProcessNotifyRoutine -> PspSetCreateProcessNotifyRoutine
	for (SIZE_T i = 0; i < 0x500; i++) {
		if (*(psStub + i) == 0xe8) {
			LONG offset = *(LONG*)(psStub + i + 1);
			pspStub = psStub + i + 5 + offset;
			break;
		}
	}
	if (!pspStub) return ret_req;
	DbgPrint("[CallbackEnum] PspSetCreateProcessNotifyRoutine : %p", pspStub);

	for (SIZE_T i = 0; i < 0x500; ++i) {
		if (*(pspStub + i) == 0x4C && *(pspStub + i + 1) == 0x8D && *(pspStub + i + 2) == 0x2D) {
			LONG offset = *(LONG*)(pspStub + i + 3);
			PUCHAR pTable = pspStub + i + 7 + offset;    // nt!PspCreateProcessNotifyRoutine
			DbgPrint("[CallbackEnum] PspCreateProcessNotifyRoutine : %p", pTable);

			SIZE_T nbCB = 0;
			for (int x = 0; x < 64; ++x)
			{
				ULONG_PTR entry = *(ULONG_PTR*)(pTable + x * sizeof(ULONG_PTR));
				if (!entry) break;

				ULONG_PTR callbackAddr = *(ULONG_PTR*)(((entry & ~0xF)) + 0x8);   // +0x8 offset de la fonction
				DbgPrint("[CallbackEnum] [%d] Callback : %p", nbCB, (PVOID)callbackAddr);

				ret_req.buffer[nbCB++] = (ULONG64)callbackAddr;
			}
			ret_req.count = nbCB;
			break;
		}
	}
	return ret_req;
}

REQUEST do_enumThreadCallbacks() {
	REQUEST ret_req = {};
	UNICODE_STRING us = RTL_CONSTANT_STRING(L"PsSetCreateThreadNotifyRoutine");
	PUCHAR psStub = (PUCHAR)MmGetSystemRoutineAddress(&us);
	PUCHAR pspStub = nullptr;
	if (!psStub) return ret_req;
	DbgPrint("[CallbackEnum] PsSetCreateThreadNotifyRoutine : %p", psStub);

	for (SIZE_T i = 0; i < 0x500; i++) {
		if (*(psStub + i) == 0xe8) {
			LONG offset = *(LONG*)(psStub + i + 1);
			pspStub = psStub + i + 5 + offset;
			break;
		}
	}
	if (!pspStub) return ret_req;
	DbgPrint("[CallbackEnum] PspSetCreateThreadNotifyRoutine : %p", pspStub);

	for (SIZE_T i = 0; i < 0x500; ++i) {
		if (*(pspStub + i) == 0x48 && *(pspStub + i + 1) == 0x8D && *(pspStub + i + 2) == 0x0D) {
			LONG offset = *(LONG*)(pspStub + i + 3);
			PUCHAR pTable = pspStub + i + 7 + offset;
			DbgPrint("[CallbackEnum] PspCreateThreadNotifyRoutine : %p", pTable);

			SIZE_T nbCB = 0;
			for (int x = 0; x < 64; ++x)
			{
				ULONG_PTR entry = *(ULONG_PTR*)(pTable + x * sizeof(ULONG_PTR));
				if (!entry) break;

				ULONG_PTR callbackAddr = *(ULONG_PTR*)(((entry & ~0xF)) + 0x8);   // +0x8 offset de la fonction
				DbgPrint("[CallbackEnum] [%d] Callback : %p", nbCB, (PVOID)callbackAddr);

				ret_req.buffer[nbCB++] = (ULONG64)callbackAddr;
			}
			ret_req.count = nbCB;
			break;
		}
	}
	return ret_req;
}

REQUEST do_enumLImagesCallbacks() {
	REQUEST ret_req = {};
	UNICODE_STRING us = RTL_CONSTANT_STRING(L"PsSetLoadImageNotifyRoutine");
	PUCHAR psStub = (PUCHAR)MmGetSystemRoutineAddress(&us);
	PUCHAR pspStub = nullptr;
	if (!psStub) return ret_req;
	DbgPrint("[CallbackEnum] PsSetLoadImageNotifyRoutine : %p", psStub);

	//De PsSetLoadImageNotifyRoutine -> PsSetLoadImageNotifyRoutineEx
	for (SIZE_T i = 0; i < 0x500; i++) {
		if (*(psStub + i) == 0xe8) {
			LONG offset = *(LONG*)(psStub + i + 1);
			pspStub = psStub + i + 5 + offset;
			break;
		}
	}
	if (!pspStub) return ret_req;
	DbgPrint("[CallbackEnum] PsSetLoadImageNotifyRoutineEx : %p", pspStub);

	for (SIZE_T i = 0; i < 0x500; ++i) {
		if (*(pspStub + i) == 0x48 && *(pspStub + i + 1) == 0x8D && *(pspStub + i + 2) == 0x0D) {
			LONG offset = *(LONG*)(pspStub + i + 3);
			PUCHAR pTable = pspStub + i + 7 + offset;
			DbgPrint("[CallbackEnum] PspLoadImageNotifyRoutine : %p", pTable);

			SIZE_T nbCB = 0;
			for (int x = 0; x < 64; ++x)
			{
				ULONG_PTR entry = *(ULONG_PTR*)(pTable + x * sizeof(ULONG_PTR));
				if (!entry) break;

				ULONG_PTR callbackAddr = *(ULONG_PTR*)(((entry & ~0xF)) + 0x8);
				DbgPrint("[CallbackEnum] [%d] Callback : %p", nbCB, (PVOID)callbackAddr);

				ret_req.buffer[nbCB++] = (ULONG64)callbackAddr;
			}
			ret_req.count = nbCB;
			break;
		}
	}
	return ret_req;
}

REQUEST do_enumCmRegisterCallbacks() {
	REQUEST ret_req = {};
	UNICODE_STRING us = RTL_CONSTANT_STRING(L"CmRegisterCallback");
	PUCHAR psStub = (PUCHAR)MmGetSystemRoutineAddress(&us);
	PUCHAR pspStub = nullptr;
	PUCHAR pspStub2 = nullptr;
	if (!psStub) return ret_req;
	DbgPrint("[CallbackEnum] CmRegisterCallback : %p", psStub);

	//De CmRegisterCallback -> CmpRegisterCallbackInternal
	for (SIZE_T i = 0; i < 0x500; i++) {
		if (*(psStub + i) == 0xe8) {
			LONG offset = *(LONG*)(psStub + i + 1);
			pspStub = psStub + i + 5 + offset;
			break;
		}
	}
	if (!pspStub) return ret_req;
	DbgPrint("[CallbackEnum] CmpRegisterCallbackInternal : %p", pspStub);

	//De CmpRegisterCallbackInternal -> CmpInsertCallbackInListByAltitude
	for (SIZE_T i = 0; i < 0x500; i++) {
		if (*(pspStub + i) == 0x48 && *(pspStub + i + 1) == 0x8b && *(pspStub + i + 2) == 0xcb && *(pspStub + i + 3) == 0xe8) {
			LONG offset = *(LONG*)(pspStub + i + 4);
			pspStub2 = pspStub + i + 8 + offset;
			break;
		}
	}
	if (!pspStub2) return ret_req;
	DbgPrint("[CallbackEnum] CmpInsertCallbackInListByAltitude : %p", pspStub2);

	int nbCB = 0;
	for (SIZE_T i = 0; i < 0x500; ++i) {
		if (*(pspStub2 + i) == 0x4c && *(pspStub2 + i + 1) == 0x8D && *(pspStub2 + i + 2) == 0x3D) {
			LONG offset = *(LONG*)(pspStub2 + i + 3);
			PCMREG_CALLBACK pTable = CONTAINING_RECORD(pspStub2 + i + 7 + offset, _CMREG_CALLBACK, List);
			DbgPrint("[CallbackEnum] CallbackListHead : %p", pTable);

			LIST_ENTRY* head = &pTable->List;
			for (LIST_ENTRY* node = head->Flink; head != node; node = node->Flink) {
				PCMREG_CALLBACK cb = CONTAINING_RECORD(node, _CMREG_CALLBACK, List);
				ret_req.buffer[nbCB++] = (ULONG64)cb->Function;
			}

			ret_req.count = nbCB;
			break;
		}
	}
	return ret_req;
}

namespace callbackEnum {
	namespace ioctl_codes {
		constexpr ULONG processCallbackEnum = IOCTL_ENUM_PROC_CB;
		constexpr ULONG threadCallbackEnum = IOCTL_ENUM_THRD_CB;
		constexpr ULONG limagesCallbackEnum = IOCTL_ENUM_LIMG_CB;
		constexpr ULONG cmregsCallbackEnum = IOCTL_ENUM_CMRG_CB;
	}

	NTSTATUS create_close(PDEVICE_OBJECT ioctl_device, PIRP irp) {
		UNREFERENCED_PARAMETER(ioctl_device);
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	NTSTATUS device_ctl(PDEVICE_OBJECT ioctl_device, PIRP irp) {
		//irp - est l'object qui contient des donnes de l'IOCTL
		UNREFERENCED_PARAMETER(ioctl_device);

		DbgPrint("[CallbackEnum] device_ctl a été trigger.");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		//Get stack from received IRP
		PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);
		REQUEST resp_req = {};
		REQUEST* req = reinterpret_cast<REQUEST*>(irp->AssociatedIrp.SystemBuffer);

		if (irp_stack == nullptr || req == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		const ULONG ctl_code = irp_stack->Parameters.DeviceIoControl.IoControlCode;

		switch (ctl_code)
		{
		case ioctl_codes::processCallbackEnum:
			resp_req = do_enumProcessCallbacks();
			status = STATUS_SUCCESS;
			break;
		case ioctl_codes::threadCallbackEnum:
			resp_req = do_enumThreadCallbacks();
			status = STATUS_SUCCESS;
			break;
		case ioctl_codes::limagesCallbackEnum:
			resp_req = do_enumLImagesCallbacks();
			status = STATUS_SUCCESS;
			break;
		case ioctl_codes::cmregsCallbackEnum:
			resp_req = do_enumCmRegisterCallbacks();
			status = STATUS_SUCCESS;
			break;
		default:
			DbgPrint("[CallbackEnum] CTL code non reconnu.");
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &resp_req, sizeof(REQUEST));

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(REQUEST);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
}


/*
	Le driver sera chargé par KDMapper donc pas besoin d�fini le DriverEntry comme :
		->	extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)

	Car le syst�me ne popuilera pas les paramètre avec ce que l'on veux.
	Cependant comme le driver utilise des IOCTL on a besoin de DriverObject pour qu'il puisse �tre r�f�rencer et atteint par le client
*/

NTSTATUS DriverMain(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	DbgPrint("[CallbackEnum] Rogue entry : DriverMain started !");

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\CallbackEnum");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\GLOBAL??\\CallbackEnum");

	PDEVICE_OBJECT ioctl_device = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &ioctl_device);

	if (status != STATUS_SUCCESS) {
		DbgPrint("[CallbackEnum] Erreur de creation du device IOCTL.");
		return status;
	}
	DbgPrint("[CallbackEnum] Device créé.");

	status = IoCreateSymbolicLink(&symLink, &devName);

	if (status != STATUS_SUCCESS) {
		DbgPrint("[CallbackEnum] Erreur de creation du lien symbolic du device.");
		return status;
	}
	DbgPrint("[CallbackEnum] Lien symbolic établit.");

	//Set ioctl device to buffered IO mode qui correspond au mode des CTL_CODE definie dans le namespace
	SetFlag(ioctl_device->Flags, DO_BUFFERED_IO);

	driver_object->MajorFunction[IRP_MJ_CREATE] = callbackEnum::create_close;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = callbackEnum::create_close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = callbackEnum::device_ctl;

	//set the IOCTL device as ready
	ClearFlag(ioctl_device->Flags, DO_DEVICE_INITIALIZING);

	DbgPrint("[CallbackEnum] Device IOCTL configuré et prêt.");

	return status;
}

extern "C" NTSTATUS DriverEntry() {
	UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\CallbackEnum");
	return IoCreateDriver(&name, DriverMain);
}