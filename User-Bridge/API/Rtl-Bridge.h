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
    KbLdrStatus WINAPI KbRtlMapDriverMemory(PVOID DriverImage, LPCWSTR DriverName);
    KbLdrStatus WINAPI KbRtlMapDriverFile(LPCWSTR DriverPath, LPCWSTR DriverName);

    // 'ModuleImage' is a raw *.sys file data
    // 'ModuleName' is a custom unique name for the loadable module
    KbLdrStatus WINAPI KbRtlLoadModuleMemory(PVOID ModuleImage, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);
    KbLdrStatus WINAPI KbRtlLoadModuleFile(LPCWSTR ModulePath, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);
}