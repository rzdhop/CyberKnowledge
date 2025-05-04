#include <ntifs.h>

//Define Unexported/Undocumented function from ntifs.h
extern "C" {
	//Implement the driver referencing (to create the DriverMain Entrypoint as driver entrypoint)
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	
	//Implement R/W primitives for driver
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PUNICODE_STRING SourceProcess, PVOID SourceAddress,
											 PEPROCESS TargetProcess, PVOID TargetAddress,
											 SIZE_T BufferSize, KPROCESSOR_MODE PreviousM0de,
											 PSIZE_T ReturnSize);
}

namespace callbackEnum {
	namespace ioctl_codes {
		constexpr ULONG processCallbackEnum		= CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	struct REQUEST {
		HANDLE process; //process attached

		PVOID target; //Mem target addrr
		PVOID buffer; //Mem content

		SIZE_T buffer_size;
		SIZE_T return_size;
	};

	NTSTATUS create(PDEVICE_OBJECT ioctl_device, PIRP irp) {
		UNREFERENCED_PARAMETER(ioctl_device);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT ioctl_device, PIRP irp) {
		//irp - est l'object qui contient des donnes de l'IOCTL
		UNREFERENCED_PARAMETER(ioctl_device);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
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

		static PEPROCESS target_process = nullptr;
		const ULONG ctl_code = irp_stack->Parameters.DeviceIoControl.IoControlCode;

		switch (ctl_code)
		{
			case ioctl_codes::processCallbackEnum:
				if (target_process != nullptr) {
					break;
				}
				break;

			default:
				DbgPrint("[CallbackEnum] CTL code non reconnu.");
				break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(REQUEST);

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[Callaback Enum] Bye !\n");
}

/*
	Le driver sera chargé par KDMapper donc pas besoin défini le DriverEntry comme : 
		->	extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)

	Car le système ne popuilera pas les paramètre avec ce que l'on veux.
	Cependant comme le driver utilise des IOCTL on a besoin de DriverObject pour qu'il puisse être référencer et atteint par le client
*/

NTSTATUS DriverMain(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	DbgPrint("[CallbackEnum] Hi from DriverMain !");

	UNICODE_STRING ioctl_device_name = {};
	RtlInitUnicodeString(&ioctl_device_name, L"\\Device\CallbackEnum");

	PDEVICE_OBJECT ioctl_device = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &ioctl_device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &ioctl_device);

	if (status != STATUS_SUCCESS) {
		DbgPrint("[CallbackEnum] Erreur de creation du device IOCTL.");
		return status;
	}
	DbgPrint("[CallbackEnum] Device créé.");

	UNICODE_STRING symbolik_link = {};
	RtlInitUnicodeString(&symbolik_link, L"\\DosDevices\CallbackEnum");
	NTSTATUS status = IoCreateSymbolicLink(&symbolik_link, &ioctl_device_name);

	if (status != STATUS_SUCCESS) {
		DbgPrint("[CallbackEnum] Erreur de creation du lien symbolic du device.");
		return status;
	}
	DbgPrint("[CallbackEnum] Lien symbolic établit.");

	//Set ioctl device to buffered IO mode qui correspond au mode des CTL_CODE definie dans le namespace
	SetFlag(ioctl_device->Flags, DO_BUFFERED_IO);

	driver_object->MajorFunction[IRP_MJ_CREATE] = callbackEnum::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = callbackEnum::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = callbackEnum::device_ctl;

	//set the IOCTL device as ready
	ClearFlag(ioctl_device->Flags, DO_DEVICE_INITIALIZING);

	DbgPrint("[CallbackEnum] Device IOCTL configuré et prêt.");

	return status;
}

NTSTATUS DriverEntry() {
	DbgPrint("[CallbackEnum] Hi from DriverEntry !");

	UNICODE_STRING drv_name = {};
	RtlInitUnicodeString(&drv_name, L"\\Driver\CallbackEnum");

    return IoCreateDriver(&drv_name, DriverMain);
}