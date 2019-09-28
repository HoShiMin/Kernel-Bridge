#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "Kernel-Bridge/DriverEvents.h"
#include "Kernel-Bridge/FilterCallbacks.h"
#include "Kernel-Bridge/IOCTLHandlers.h"
#include "Kernel-Bridge/IOCTLs.h"

#include "API/CppSupport.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

namespace {
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Kernel-Bridge");
    UNICODE_STRING DeviceLink = RTL_CONSTANT_STRING(L"\\??\\Kernel-Bridge");
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

static VOID PowerCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);

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

static PVOID PowerCallbackRegistration = NULL;

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
        IRP_MJ_DEVICE_CONTROL,
        0,
        reinterpret_cast<PFLT_PRE_OPERATION_CALLBACK>(FilterPreOperation),
        reinterpret_cast<PFLT_POST_OPERATION_CALLBACK>(FilterPostOperation)
    },
    {
        IRP_MJ_INTERNAL_DEVICE_CONTROL,
        0,
        reinterpret_cast<PFLT_PRE_OPERATION_CALLBACK>(FilterPreOperation),
        reinterpret_cast<PFLT_POST_OPERATION_CALLBACK>(FilterPostOperation)
    },
    {
        IRP_MJ_FILE_SYSTEM_CONTROL,
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


extern "C" NTSTATUS NTAPI DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialization of POOL_NX_OPTIN:
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    __crt_init(); // Global objects initialization

    DriverObject->DriverUnload = reinterpret_cast<PDRIVER_UNLOAD>(DriverUnload);
    DriverObject->MajorFunction[IRP_MJ_CREATE]  = DriverStub;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DriverStub;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]   = DriverStub;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

    NTSTATUS Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceInstance);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Kernel-Bridge]: IoCreateDevice Error!\r\n"));
        return Status;
    }

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

    // Registering the power callback to handle sleep/resume for support in VMM:
    PCALLBACK_OBJECT PowerCallbackObject = NULL;
    UNICODE_STRING PowerObjectName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES PowerObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&PowerObjectName, OBJ_CASE_INSENSITIVE);
    Status = ExCreateCallback(&PowerCallbackObject, &PowerObjectAttributes, FALSE, TRUE);
    if (NT_SUCCESS(Status)) {
        PowerCallbackRegistration = ExRegisterCallback(PowerCallbackObject, PowerCallback, NULL);
        ObDereferenceObject(PowerCallbackObject);
        if (!PowerCallbackRegistration) {
            KdPrint(("[Kernel-Bridge]: Unable to register the power callback!\r\n"));
        }
    }
    else {
        KdPrint(("[Kernel-Bridge]: Unable to create the power callback!\r\n"));
    }

    OnDriverLoad(DriverObject, DeviceInstance, FilterHandle, RegistryPath);

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
    PAGED_CODE();

    OnFilterUnload(DeviceInstance, FilterHandle, Flags);
    
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
        Status = ExceptionCode;
        KdPrint((
            "[Kernel-Bridge]: Exception catched in IOCTL handler!\r\n"
            "\tCode: 0x%X\r\n"
            "\tAddress: 0x%p\r\n"
            "\tCTL: 0x%X\r\n",
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
        KdPrint(("[Kernel-Bridge]: Unknown method of IRP!\r\n"));
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
    PAGED_CODE();
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    switch (IrpStack->MajorFunction) {
    case IRP_MJ_CREATE:
        OnDriverCreate(DeviceObject, FilterHandle, Irp, IrpStack);
        break;
    case IRP_MJ_CLEANUP:
        OnDriverCleanup(DeviceObject, FilterHandle, Irp, IrpStack);
        break;
    case IRP_MJ_CLOSE:
        OnDriverClose(DeviceObject, FilterHandle, Irp, IrpStack);
        break;
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID PowerCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (reinterpret_cast<SIZE_T>(Argument1) != PO_CB_SYSTEM_STATE_LOCK) return;

    if (Argument2) {
        OnSystemWake();
    } else {
        OnSystemSleep();
    }
}

static NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    OnDriverUnload(DriverObject, DeviceInstance);

    __crt_deinit(); // Global objects destroying

    if (PowerCallbackRegistration)
        ExUnregisterCallback(PowerCallbackRegistration);

    IoDeleteSymbolicLink(&DeviceLink);
    IoDeleteDevice(DeviceInstance);
    
    KdPrint(("[Kernel-Bridge]: Successfully unloaded!\r\n"));
    return STATUS_SUCCESS;
}