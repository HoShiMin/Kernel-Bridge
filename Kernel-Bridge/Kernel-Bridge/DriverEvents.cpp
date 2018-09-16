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

    if (FilterHandle) {
        Communication::StartServer(FilterHandle);
        KdPrint(("[Kernel-Bridge]: ObHandlesFilter status: 0x%X\r\n", KbCallbacks::StartObHandlesFilter()));
        KdPrint(("[Kernel-Bridge]: PsProcessFilter status: 0x%X\r\n", KbCallbacks::StartPsProcessFilter()));
        KdPrint(("[Kernel-Bridge]: PsThreadFilter status: 0x%X\r\n", KbCallbacks::StartPsThreadFilter()));
        KdPrint(("[Kernel-Bridge]: PsImageFilter status: 0x%X\r\n", KbCallbacks::StartPsImageFilter()));
    }
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

    KbCallbacks::StopObHandlesFilter();
    KbCallbacks::StopPsProcessFilter();
    KbCallbacks::StopPsThreadFilter();
    KbCallbacks::StopPsImageFilter();

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