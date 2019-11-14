#include <fltKernel.h>

#include "FilterCallbacks.h"
#include "../API/Hypervisor.h"

volatile LONG KbHandlesCount = 0;

VOID OnDriverLoad(
    PDRIVER_OBJECT DriverObject, 
    PDEVICE_OBJECT DeviceObject, 
    PFLT_FILTER FilterHandle,
    PUNICODE_STRING RegistryPath
) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if (FilterHandle) {
        Communication::StartServer(FilterHandle);
        Status = KbCallbacks::StartObHandlesFilter();
        KdPrint(("[Kernel-Bridge]: ObHandlesFilter status: 0x%X\r\n", Status));
        Status = KbCallbacks::StartPsProcessFilter();
        KdPrint(("[Kernel-Bridge]: PsProcessFilter status: 0x%X\r\n", Status));
        Status = KbCallbacks::StartPsThreadFilter();
        KdPrint(("[Kernel-Bridge]: PsThreadFilter status: 0x%X\r\n", Status));
        Status = KbCallbacks::StartPsImageFilter();
        KdPrint(("[Kernel-Bridge]: PsImageFilter status: 0x%X\r\n", Status));
    }
}

VOID OnDriverUnload(
    PDRIVER_OBJECT DriverObject, 
    PDEVICE_OBJECT DeviceObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(DeviceObject);
    Hypervisor::Devirtualize(); // Devirtualize processor if it is in virtualized state
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
    InterlockedIncrement(&KbHandlesCount);
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
    InterlockedDecrement(&KbHandlesCount);
}

namespace HypervisorManagement {
    static bool NeedToRevirtualizeOnWake = false;
}

VOID OnSystemSleep()
{
    using namespace HypervisorManagement;
    if (Hypervisor::IsVirtualized()) {
        NeedToRevirtualizeOnWake = true;
        Hypervisor::Devirtualize();
    }
    else {
        NeedToRevirtualizeOnWake = false;
    }
}

VOID OnSystemWake()
{
    using namespace HypervisorManagement;
    if (NeedToRevirtualizeOnWake)
        Hypervisor::Virtualize();
}
