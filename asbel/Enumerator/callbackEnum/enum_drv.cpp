#include <ntifs.h>
#pragma warning(disable: 28252)   // evite le warning pour la non definition de IoCreateDriver
 
#define IOCTL_ENUM_PROC_CB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

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

VOID do_enumProcessCallbacks(PULONG64 buffer, PSIZE_T count) {
	*count = 0;
	__try {
		UNICODE_STRING us = RTL_CONSTANT_STRING(L"PsSetCreateProcessNotifyRoutine");
		PUCHAR psStub = (PUCHAR)MmGetSystemRoutineAddress(&us);
		PUCHAR pspStub = nullptr;
		if (!psStub) return;
		DbgPrint("[CallbackEnum] PsSetCreateProcessNotifyRoutine : %p", psStub);

		//De PsSetCreateProcessNotifyRoutine -> PspSetCreateProcessNotifyRoutine
		for (SIZE_T i = 0; i < 0x500; i++) {
			if (*(psStub + i) == 0xe8) {
				LONG offset = *(LONG*)(psStub + i + 1);
				pspStub = psStub + i + 5 + offset;
				break;
			}
		}
		if (!pspStub) return;
		DbgPrint("[CallbackEnum] PspSetCreateProcessNotifyRoutine : %p", pspStub);

		for (SIZE_T i = 0; i < 0x500; ++i) {
			if (*(pspStub + i) == 0x4C && *(pspStub + i + 1) == 0x8D && *(pspStub + i + 2) == 0x2D) {
				LONG offset = *(LONG*)(pspStub + i + 3);
				PUCHAR pTable = pspStub + i + 7 + offset;    // nt!PspCreateProcessNotifyRoutine
				if (!MmIsAddressValid(pTable))                 // ----- // FIX 2
					return;
				DbgPrint("[CallbackEnum] PspCreateProcessNotifyRoutine : %p", pspStub);

				SIZE_T nbCB = 0;
				for (int x = 0; x < 64; ++x)
				{
					ULONG_PTR entry = *(ULONG_PTR*)(pTable + x * sizeof(ULONG_PTR));

					PVOID callbackAddr = *(PVOID*)((entry & ~0xf) + 0x8); // +0x8 offset de la fonction
					DbgPrint("[CallbackEnum] [%d]Callback : %p", x, pspStub);

					buffer[nbCB++] = (ULONG64)callbackAddr;
				}

				*count = nbCB;
				break;
			}
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[CallbackEnum] exception 0x%X", GetExceptionCode());
		*count = 0;
	}
}


namespace callbackEnum {
	namespace ioctl_codes {
		constexpr ULONG processCallbackEnum = IOCTL_ENUM_PROC_CB;
	}

	struct REQUEST {
		ULONG64 buffer[500];
		SIZE_T count;
	};

	NTSTATUS create_close(PDEVICE_OBJECT ioctl_device, PIRP irp) {
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
		REQUEST* req = reinterpret_cast<REQUEST*>(irp->AssociatedIrp.SystemBuffer);

		if (irp_stack == nullptr || req == nullptr) {
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		const ULONG ctl_code = irp_stack->Parameters.DeviceIoControl.IoControlCode;

		switch (ctl_code)
		{
		case ioctl_codes::processCallbackEnum:
			DbgPrint("[CallbackEnum] do process callback");
			do_enumProcessCallbacks(req->buffer, &(req->count));
			status = STATUS_SUCCESS;
			break;
		default:
			DbgPrint("[CallbackEnum] CTL code non reconnu.");
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(REQUEST);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
}


/*
	Le driver sera chargé par KDMapper donc pas besoin d�fini le DriverEntry comme :
		->	extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)

	Car le syst�me ne popuilera pas les param�tre avec ce que l'on veux.
	Cependant comme le driver utilise des IOCTL on a besoin de DriverObject pour qu'il puisse �tre r�f�rencer et atteint par le client
*/

extern "C" NTSTATUS DriverMain(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	DbgPrint("[CallbackEnum] Hi from DriverMain !");

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\CallbackEnum");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\CallbackEnum");

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
	DbgPrint("[CallbackEnum] Hi from DriverEntry !");

	UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\CallbackEnum");
	return IoCreateDriver(&name, DriverMain);
}