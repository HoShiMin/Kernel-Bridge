#include <wdm.h>

NTSTATUS NTAPI OnLoad(PVOID hModule, LPCWSTR ModuleName)
{
    KdPrint(("[LOADABLE]: OnLoad %ws 0x%p\r\n", ModuleName, hModule));
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnUnload()
{
    KdPrint(("[LOADABLE]: OnUnload\r\n"));
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnDeviceControl(UINT64 CtlCode, OPTIONAL PVOID Argument)
{
    *(PSHORT)(NULL) = 0x1234;
    KdPrint(("[LOADABLE]: OnDeviceControl: 0x%X, 0x%p\r\n", CtlCode, Argument));
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnException(ULONG ExceptionCode, PEXCEPTION_POINTERS ExceptionPointers)
{
    UNREFERENCED_PARAMETER(ExceptionPointers);
    KdPrint(("[LOADABLE]: Exception catched: 0x%X\r\n", ExceptionCode));
    return STATUS_SUCCESS;
}