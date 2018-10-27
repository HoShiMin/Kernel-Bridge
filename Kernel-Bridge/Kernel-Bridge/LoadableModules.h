#pragma once

namespace LoadableModules {
    using _OnLoad = NTSTATUS(*)(PVOID hModule, LPCWSTR Name);
    using _OnUnload = NTSTATUS(*)();
    using _OnDeviceControl = NTSTATUS(*)(UINT64 CtlCode, PVOID Argument);
    using _OnException = NTSTATUS(*)(ULONG ExceptionCode, PEXCEPTION_POINTERS ExceptionPointers);

    NTSTATUS LoadModule(
        PVOID hModule,
        LPCWSTR ModuleName,
        OPTIONAL _OnLoad OnLoad = NULL,
        OPTIONAL _OnUnload OnUnload = NULL,
        OPTIONAL _OnDeviceControl OnDeviceControl = NULL,
        OPTIONAL _OnException OnException = NULL
    );

    NTSTATUS CallModule(PVOID hModule, UINT64 CtlCode, OPTIONAL PVOID Argument = NULL);

    NTSTATUS UnloadModule(PVOID hModule);

    PVOID GetModuleHandle(LPCWSTR ModuleName);
}