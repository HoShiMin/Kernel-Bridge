#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "Kernel-Bridge/FilterCallbacks.h"
#include "Kernel-Bridge/IOCTLHandlers.h"
#include "Kernel-Bridge/IOCTLs.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

namespace {
    PCWSTR DeviceNamePath = L"\\Device\\Kernel-Bridge";
    PCWSTR DeviceLinkPath = L"\\??\\Kernel-Bridge";
    PDEVICE_OBJECT DeviceInstance = NULL;
    PFLT_FILTER FilterHandle = NULL;
}

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS SEC_ENTRY FilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

static NTSTATUS SEC_ENTRY FilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static NTSTATUS DriverControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_CLEANUP)
static NTSTATUS DriverStub(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

static NTSTATUS DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

EXTERN_C_END

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FilterUnload)
#pragma alloc_text(PAGE, FilterInstanceSetup)
#pragma alloc_text(PAGE, DriverStub)
#pragma alloc_text(PAGE, DriverUnload)
#endif

// Operations registration:
static CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
    {
        IRP_MJ_CREATE,
        0,
        reinterpret_cast<PFLT_PRE_OPERATION_CALLBACK>(FilterPreOperation),
        reinterpret_cast<PFLT_POST_OPERATION_CALLBACK>(FilterPostOperation)
    },
    {
        IRP_MJ_READ,
        0,
        reinterpret_cast<PFLT_PRE_OPERATION_CALLBACK>(FilterPreOperation),
        reinterpret_cast<PFLT_POST_OPERATION_CALLBACK>(FilterPostOperation)
    },
    {
        IRP_MJ_WRITE,
        0,
        reinterpret_cast<PFLT_PRE_OPERATION_CALLBACK>(FilterPreOperation),
        reinterpret_cast<PFLT_POST_OPERATION_CALLBACK>(FilterPostOperation)
    },
    {
        IRP_MJ_OPERATION_END
    }
};

// What we want to filter:
static CONST FLT_REGISTRATION FilterRegistration = 
{
    sizeof(FLT_REGISTRATION), // Size
    FLT_REGISTRATION_VERSION, // Version
    0,                        // Flags

    NULL,      // Context
    Callbacks, // Operation callbacks

    reinterpret_cast<PFLT_FILTER_UNLOAD_CALLBACK>(FilterUnload), // MiniFilterUnload

    FilterInstanceSetup, // InstanceSetup
    NULL, // InstanceQueryTeardown
    NULL, // InstanceTeardownStart
    NULL, // InstanceTeardownComplete
    NULL, // GenerateFileName
    NULL, // GenerateDestinationFileName
    NULL, // NormalizeNameComponent
    NULL, // TransactionNotifierCallback
    NULL, // NormalizeNameComponentExCallback
};


NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = reinterpret_cast<PDRIVER_UNLOAD>(DriverUnload);
    DriverObject->MajorFunction[IRP_MJ_CREATE]  = DriverStub;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DriverStub;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]   = DriverStub;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

    UNICODE_STRING DeviceName;
    RtlInitUnicodeString(&DeviceName, DeviceNamePath);
    NTSTATUS Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceInstance);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Kernel-Bridge]: IoCreateDevice Error!\r\n"));
        return Status;
    }

    UNICODE_STRING DeviceLink;
    RtlInitUnicodeString(&DeviceLink, DeviceLinkPath);
    Status = IoCreateSymbolicLink(&DeviceLink, &DeviceName);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Kernel-Bridge]: IoCreateSymbolicLink Error!\r\n"));
        IoDeleteDevice(DeviceInstance);
        return Status;
    }

    // We're try to register as minifilter:
    Status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &FilterHandle
    );

    if (NT_SUCCESS(Status)) {
        Status = FltStartFiltering(FilterHandle);
        if (NT_SUCCESS(Status)) {
            KdPrint(("[Kernel-Bridge]: Successfully registered as filter!\r\n"));
        } else {
            KdPrint(("[Kernel-Bridge]: FltStartFiltering failure: 0x%X\r\n", Status));
            FltUnregisterFilter(FilterHandle);
            FilterHandle = NULL;
        }
    } else {
        KdPrint(("[Kernel-Bridge]: Unable to register as filter: 0x%X\r\n", Status));
    }

    KdPrint(("[Kernel-Bridge]: Successfully loaded!\r\n"));
    return STATUS_SUCCESS;
}

static NTSTATUS SEC_ENTRY FilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    return VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM
        ? STATUS_FLT_DO_NOT_ATTACH
        : STATUS_SUCCESS;
}

static NTSTATUS SEC_ENTRY FilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    if (FilterHandle) FltUnregisterFilter(FilterHandle);

    return STATUS_SUCCESS;
}

NTSTATUS CallIoctlDispatcher(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
{
    ULONG ExceptionCode = 0;
    PEXCEPTION_POINTERS ExceptionPointers = NULL;
    NTSTATUS Status;
    __try {
        Status = DispatchIOCTL(RequestInfo, ResponseLength);
    }
    __except (
        ExceptionCode = GetExceptionCode(),
        ExceptionPointers = GetExceptionInformation(),
        EXCEPTION_EXECUTE_HANDLER
    ) {
        Status = STATUS_UNSUCCESSFUL;
        KdPrint((
            "[Kernel-Bridge]: Exception catched in IOCTL handler!\r\n"
            "\tCode: 0x%llX\r\n"
            "\tAddress: 0x%llX\r\n"
            "\tCTL: 0x%llX\r\n",
            ExceptionCode,
            ExceptionPointers->ExceptionRecord->ExceptionAddress,
            RequestInfo->ControlCode
        ));
    }
    return Status;
}



// IOCTLs handler:
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static NTSTATUS DriverControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

    IOCTL_INFO RequestInfo;
    RequestInfo.ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
    switch (EXTRACT_CTL_METHOD(RequestInfo.ControlCode)) {
    case METHOD_BUFFERED: {
        RequestInfo.InputBuffer      = Irp->AssociatedIrp.SystemBuffer;
        RequestInfo.OutputBuffer     = Irp->AssociatedIrp.SystemBuffer;
        RequestInfo.InputBufferSize  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
        RequestInfo.OutputBufferSize = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
        Irp->IoStatus.Status = CallIoctlDispatcher(&RequestInfo, &Irp->IoStatus.Information);
        break;
    }
    case METHOD_NEITHER: {
        RequestInfo.InputBuffer      = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
        RequestInfo.OutputBuffer     = Irp->UserBuffer;
        RequestInfo.InputBufferSize  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
        RequestInfo.OutputBufferSize = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
        Irp->IoStatus.Status = CallIoctlDispatcher(&RequestInfo, &Irp->IoStatus.Information);
        break;
    }
    case METHOD_IN_DIRECT:
    case METHOD_OUT_DIRECT: {
        RequestInfo.InputBuffer      = Irp->AssociatedIrp.SystemBuffer;
        RequestInfo.OutputBuffer     = Irp->MdlAddress ? MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) : NULL;
        RequestInfo.InputBufferSize  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
        RequestInfo.OutputBufferSize = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
        Irp->IoStatus.Status = CallIoctlDispatcher(&RequestInfo, &Irp->IoStatus.Information);
        break;
    }
    default: {
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        KdPrint(("[Kernel-Bridge] Unknown method of IRP!\r\n"));
    }
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_CLEANUP)
static NTSTATUS DriverStub(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
    UNICODE_STRING DeviceLink;
    RtlInitUnicodeString(&DeviceLink, DeviceLinkPath);
    IoDeleteSymbolicLink(&DeviceLink);
    IoDeleteDevice(DeviceInstance);
    return STATUS_SUCCESS;
}