#include <wdm.h>

NTSTATUS NTAPI OnLoad(PVOID hModule, LPCWSTR ModuleName)
{
    DbgPrint("[LOADABLE]: OnLoad %ws 0x%p\r\n", ModuleName, hModule);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnUnload()
{
    DbgPrint("[LOADABLE]: OnUnload\r\n");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnDeviceControl(ULONG CtlCode, OPTIONAL PVOID Argument)
{
    DbgPrint("[LOADABLE]: OnDeviceControl: 0x%X, 0x%p\r\n", CtlCode, Argument);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS NTAPI DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_SUCCESS;
}