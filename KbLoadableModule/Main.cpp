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

NTSTATUS NTAPI OnDeviceControl(UINT64 CtlCode, OPTIONAL PVOID Argument)
{
    DbgPrint("[LOADABLE]: OnDeviceControl: 0x%X, 0x%p\r\n", CtlCode, Argument);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnException(ULONG ExceptionCode, PEXCEPTION_POINTERS ExceptionPointers)
{
    UNREFERENCED_PARAMETER(ExceptionPointers);
    DbgPrint("[LOADABLE]: Exception catched: 0x%X\r\n", ExceptionCode);
    return STATUS_SUCCESS;
}