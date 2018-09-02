#pragma once

VOID OnDriverLoad(
    PDRIVER_OBJECT DriverObject, 
    PDEVICE_OBJECT DeviceObject, 
    PFLT_FILTER FilterHandle,
    PUNICODE_STRING RegistryPath
);

VOID OnDriverUnload(
    PDRIVER_OBJECT DriverObject, 
    PDEVICE_OBJECT DeviceObject
);

VOID OnFilterUnload(
    PDEVICE_OBJECT DeviceObject, 
    PFLT_FILTER FilterHandle,
    FLT_FILTER_UNLOAD_FLAGS Flags
);

VOID OnDriverCreate(
    PDEVICE_OBJECT DeviceObject,
    PFLT_FILTER FilterHandle,
    PIRP Irp,
    PIO_STACK_LOCATION IrpStack
);

VOID OnDriverCleanup(
    PDEVICE_OBJECT DeviceObject,
    PFLT_FILTER FilterHandle,
    PIRP Irp,
    PIO_STACK_LOCATION IrpStack
);

VOID OnDriverClose(
    PDEVICE_OBJECT DeviceObject,
    PFLT_FILTER FilterHandle,
    PIRP Irp,
    PIO_STACK_LOCATION IrpStack
);