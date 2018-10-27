#include <Windows.h>

// User-Bridge types:
#include <WdkTypes.h>
#include <CtlTypes.h>
#include <User-Bridge.h>
#include "Rtl-Bridge.h"

// PEUtils modules:
#include <PEAnalyzer.h>
#include <PELoader.h>

#include <string>

namespace KbRtl {

    static PVOID GetKernelProcAddress(LPCSTR FunctionName)
    {
        // Converting ANSI-name to Unicode-name:
        ULONG SymbolsCount = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, FunctionName, -1, NULL, 0);
        std::wstring WideName(SymbolsCount, static_cast<WCHAR>(0x0000));
        MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, FunctionName, -1, const_cast<LPWSTR>(WideName.c_str()), SymbolsCount - 1);

        // Getting the actual kernel address:
        WdkTypes::PVOID KernelAddress = NULL;
        BOOL Status = Stuff::KbGetKernelProcAddress(WideName.c_str(), &KernelAddress);
        return Status ? reinterpret_cast<PVOID>(KernelAddress) : NULL;
    }

    class FileReader {
    private:
        PVOID Memory;
        ULONG Size;
    public:
        FileReader() : Memory(NULL) {
        
        }
        ~FileReader() {
            Free();
        }

        BOOL Load(LPCWSTR Path) {
            HANDLE hFile = CreateFile(Path, FILE_READ_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return FALSE;

            Size = GetFileSize(hFile, NULL);
            if (!Size) {
                CloseHandle(hFile);
                return FALSE;
            }

            Memory = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            ULONG BytesRead = 0;
            if (!Memory || !ReadFile(hFile, Memory, Size, &BytesRead, NULL) || BytesRead != Size) {
                if (Memory) VirtualFree(Memory, 0, MEM_RELEASE);
                CloseHandle(hFile);
                Memory = NULL;
                Size = 0;
                return FALSE;
            }

            CloseHandle(hFile);
            return TRUE;
        }

        VOID Free() {
            if (Memory) VirtualFree(Memory, 0, MEM_RELEASE);
            Memory = NULL;
            Size = 0;
        }

        PVOID GetMemory() { return Memory; }
        ULONG GetSize() const { return Size; }
    };

    KbLdrStatus WINAPI KbMapDriverMemory(PVOID DriverImage, LPCWSTR DriverName)
    {
        try {
            PELoader Loader(
                static_cast<HMODULE>(DriverImage),
                [](LPCSTR LibName, LPCSTR FunctionName) -> PVOID {
                    PVOID Address = GetKernelProcAddress(FunctionName);
                    if (!Address) throw KbLdrImportNotResolved;
                    return Address;
                },
                [](LPCSTR LibName, WORD Ordinal) -> PVOID {
                    throw KbLdrOrdinalImportNotSupported;
                }
            );

            WdkTypes::PVOID KImageAddress = NULL;
            BOOL Status = VirtualMemory::KbAllocKernelMemory(Loader.GetDeployedSize(), TRUE, &KImageAddress);
            if (!Status) throw KbLdrKernelMemoryNotAllocated;

            Loader.Relocate(reinterpret_cast<HMODULE>(KImageAddress));

            Status = VirtualMemory::KbCopyMoveMemory(
                KImageAddress, 
                reinterpret_cast<WdkTypes::PVOID>(Loader.Get()), 
                Loader.GetDeployedSize(), 
                FALSE
            );

            if (!Status) {
                VirtualMemory::KbFreeKernelMemory(KImageAddress);
                return KbLdrTransitionFailure;
            }

            return LoadableModules::KbCreateDriver(
                DriverName,
                reinterpret_cast<WdkTypes::PVOID>(
                    Loader.GetBaseRelativeEntryPoint(reinterpret_cast<HMODULE>(KImageAddress))
                )
            ) ? KbLdrSuccess : KbLdrCreationFailure;
        } 
        catch (KbLdrStatus Status) {
            return Status;
        }
    }

    KbLdrStatus WINAPI KbMapDriverFile(LPCWSTR DriverPath, LPCWSTR DriverName)
    {
        FileReader Reader;
        if (!Reader.Load(DriverPath)) return KbLdrCreationFailure;
        return KbMapDriverMemory(Reader.GetMemory(), DriverName);
    }

    KbLdrStatus WINAPI KbLoadModuleMemory(PVOID DriverImage, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* ImageBase)
    {
        try {
            PELoader Loader(
                static_cast<HMODULE>(DriverImage),
                [](LPCSTR LibName, LPCSTR FunctionName) -> PVOID {
                    PVOID Address = GetKernelProcAddress(FunctionName);
                    if (!Address) throw KbLdrImportNotResolved;
                    return Address;
                },
                [](LPCSTR LibName, WORD Ordinal) -> PVOID {
                    throw KbLdrOrdinalImportNotSupported;
                }
            );

            PEAnalyzer Module(Loader.Get(), FALSE);

            WdkTypes::HMODULE hModule = NULL;
            BOOL Status = VirtualMemory::KbAllocKernelMemory(Loader.GetDeployedSize(), TRUE, &hModule);
            if (!Status) throw KbLdrKernelMemoryNotAllocated;

            Loader.Relocate(reinterpret_cast<HMODULE>(hModule));

            Status = VirtualMemory::KbCopyMoveMemory(
                hModule, 
                reinterpret_cast<WdkTypes::PVOID>(Loader.Get()), 
                Loader.GetDeployedSize(), 
                FALSE
            );

            if (!Status) {
                VirtualMemory::KbFreeKernelMemory(hModule);
                return KbLdrTransitionFailure;
            }

            WdkTypes::PVOID ModuleBase = reinterpret_cast<WdkTypes::PVOID>(Module.GetImageBase());
            WdkTypes::PVOID OnLoad = NULL, OnUnload = NULL, OnDeviceControl = NULL, OnException = NULL;
            const auto& Exports = Module.GetExportsInfo();
            for (const auto& Export : Exports.Exports) {
                WdkTypes::PVOID VA = hModule + static_cast<WdkTypes::PVOID>(Export.RVA);
                if (Export.Name == "OnLoad") {
                    OnLoad = VA;
                } else if (Export.Name == "OnUnload") {
                    OnUnload = VA;
                } else if (Export.Name == "OnDeviceControl") {
                    OnDeviceControl = VA;
                } else if (Export.Name == "OnException") {
                    OnException = VA;
                }
            }

            Status = LoadableModules::KbLoadModule(
                hModule,
                ModuleName,
                OnLoad,
                OnUnload,
                OnDeviceControl,
                OnException
            );

            if (!Status) {
                VirtualMemory::KbFreeKernelMemory(hModule);
                return KbLdrCreationFailure;
            }

            *ImageBase = hModule;
            return KbLdrSuccess;
        } 
        catch (KbLdrStatus Status) {
            return Status;
        }
    }

    KbLdrStatus WINAPI KbLoadModuleFile(LPCWSTR ModulePath, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule)
    {
        FileReader Reader;
        if (!Reader.Load(ModulePath)) return KbLdrCreationFailure;
        return KbLoadModuleMemory(Reader.GetMemory(), ModuleName, hModule);
    }
}