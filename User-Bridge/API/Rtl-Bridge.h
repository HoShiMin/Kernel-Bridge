#pragma once

namespace KbRtl {
    enum KbLdrStatus {
        KbLdrSuccess,
        KbLdrImportNotResolved,
        KbLdrOrdinalImportNotSupported,
        KbLdrKernelMemoryNotAllocated,
        KbLdrTransitionFailure,
        KbLdrCreationFailure
    };

    // 'DriverImage' is a raw *.sys file data
    // 'DriverName' is a system name of driver in format L"\\Driver\\YourDriverName"
    KbLdrStatus WINAPI KbMapDriverMemory(PVOID DriverImage, LPCWSTR DriverName);
    KbLdrStatus WINAPI KbMapDriverFile(LPCWSTR DriverPath, LPCWSTR DriverName);

    // 'ModuleImage' is a raw *.sys file data
    // 'ModuleName' is a custom unique name for the loadable module
    KbLdrStatus WINAPI KbLoadModuleMemory(PVOID ModuleImage, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);
    KbLdrStatus WINAPI KbLoadModuleFile(LPCWSTR ModulePath, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);
}