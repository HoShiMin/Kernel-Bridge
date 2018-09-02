#include <fltKernel.h>

#include "FilterCallbacks.h"

VOID OnDriverLoad(
    PDRIVER_OBJECT DriverObject, 
    PDEVICE_OBJECT DeviceObject, 
    PFLT_FILTER FilterHandle,
    PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if (FilterHandle)
        Communication::StartServer(FilterHandle);
}

VOID OnDriverUnload(
    PDRIVER_OBJECT DriverObject, 
    PDEVICE_OBJECT DeviceObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(DeviceObject);
}

VOID OnFilterUnload(
    PDEVICE_OBJECT DeviceObject, 
    PFLT_FILTER FilterHandle,
    FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(FilterHandle);
    UNREFERENCED_PARAMETER(Flags);

    Communication::StopServer();
}

VOID OnDriverCreate(
    PDEVICE_OBJECT DeviceObject,
    PFLT_FILTER FilterHandle,
    PIRP Irp,
    PIO_STACK_LOCATION IrpStack
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(FilterHandle);
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpStack);
}

VOID OnDriverCleanup(
    PDEVICE_OBJECT DeviceObject,
    PFLT_FILTER FilterHandle,
    PIRP Irp,
    PIO_STACK_LOCATION IrpStack
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(FilterHandle);
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpStack);
}

VOID OnDriverClose(
    PDEVICE_OBJECT DeviceObject,
    PFLT_FILTER FilterHandle,
    PIRP Irp,
    PIO_STACK_LOCATION IrpStack
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(FilterHandle);
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpStack);
}