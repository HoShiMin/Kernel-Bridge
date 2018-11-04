#pragma once

namespace LoadableModules {
    using _OnLoad = NTSTATUS(NTAPI*)(PVOID hModule, LPCWSTR Name);
    using _OnUnload = NTSTATUS(NTAPI*)();
    using _OnDeviceControl = NTSTATUS(NTAPI*)(ULONG CtlCode, PVOID Argument);

    NTSTATUS LoadModule(
        PVOID hModule,
        LPCWSTR ModuleName,
        OPTIONAL _OnLoad OnLoad = NULL,
        OPTIONAL _OnUnload OnUnload = NULL,
        OPTIONAL _OnDeviceControl OnDeviceControl = NULL
    );

    NTSTATUS CallModule(PVOID hModule, ULONG CtlCode, OPTIONAL PVOID Argument = NULL);

    NTSTATUS UnloadModule(PVOID hModule);

    PVOID GetModuleHandle(LPCWSTR ModuleName);
}