#include <Windows.h>

#include "Rtl-Bridge.h"

// User-Bridge types:
#include <CtlTypes.h>
#include <User-Bridge.h>

// PEUtils modules:
#include <PEAnalyzer.h>
#include <PELoader.h>

#include <string>

namespace KbRtl {
    KbMapDrvStatus WINAPI KbMapDriver(PVOID DriverImage, LPCWSTR DriverName)
    {
        try {
            PELoader Loader(
                static_cast<HMODULE>(DriverImage),
                [](LPCSTR LibName, LPCSTR FunctionName) -> PVOID {
                    // Converting ANSI-name to Unicode-name:
                    ULONG SymbolsCount = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, FunctionName, -1, NULL, 0);
                    std::wstring WideName(SymbolsCount, static_cast<WCHAR>(0x0000));
                    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, FunctionName, -1, const_cast<LPWSTR>(WideName.c_str()), SymbolsCount - 1);

                    WdkTypes::PVOID KernelAddress = NULL;
                    BOOL Status = Stuff::KbGetKernelProcAddress(WideName.c_str(), &KernelAddress);
                    if (!Status) throw KbMapDrvImportNotResolved;
                
                    return reinterpret_cast<PVOID>(KernelAddress);
                },
                [](LPCSTR LibName, WORD Ordinal) -> PVOID {
                    throw KbMapDrvOrdinalImportNotSupported;
                }
            );

            WdkTypes::PVOID KImageAddress = NULL;
            BOOL Status = VirtualMemory::KbAllocKernelMemory(Loader.GetDeployedSize(), TRUE, &KImageAddress);
            if (!Status) throw KbMapDrvKernelMemoryNotAllocated;

            Loader.Relocate(reinterpret_cast<HMODULE>(KImageAddress));

            Status = VirtualMemory::KbCopyMoveMemory(
                KImageAddress, 
                reinterpret_cast<WdkTypes::PVOID>(Loader.Get()), 
                Loader.GetDeployedSize(), 
                FALSE
            );

            if (!Status) {
                VirtualMemory::KbFreeKernelMemory(KImageAddress);
                return KbMapDrvTransitionFailure;
            }

            return Stuff::KbCreateDriver(
                DriverName,
                reinterpret_cast<WdkTypes::PVOID>(
                    Loader.GetBaseRelativeEntryPoint(reinterpret_cast<HMODULE>(KImageAddress))
                )
            ) ? KbMapDrvSuccess : KbMapDrvCreationFailure;
        } 
        catch (KbMapDrvStatus Status) {
            return Status;
        }
    }
}