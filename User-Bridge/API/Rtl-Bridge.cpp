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

    KbLdrStatus WINAPI KbRtlMapDriverMemory(PVOID DriverImage, LPCWSTR DriverName)
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
            BOOL Status = VirtualMemory::KbAllocKernelMemory(Loader.getDeployedSize(), TRUE, &KImageAddress);
            if (!Status) throw KbLdrKernelMemoryNotAllocated;

            Loader.relocate(reinterpret_cast<HMODULE>(KImageAddress));

            Status = VirtualMemory::KbCopyMoveMemory(
                KImageAddress, 
                reinterpret_cast<WdkTypes::PVOID>(Loader.get()), 
                Loader.getDeployedSize(), 
                FALSE
            );

            if (!Status) {
                VirtualMemory::KbFreeKernelMemory(KImageAddress);
                return KbLdrTransitionFailure;
            }

            return LoadableModules::KbCreateDriver(
                DriverName,
                reinterpret_cast<WdkTypes::PVOID>(
                    Loader.getBaseRelativeEntryPoint(reinterpret_cast<HMODULE>(KImageAddress))
                )
            ) ? KbLdrSuccess : KbLdrCreationFailure;
        } 
        catch (KbLdrStatus Status) {
            return Status;
        }
    }

    KbLdrStatus WINAPI KbRtlMapDriverFile(LPCWSTR DriverPath, LPCWSTR DriverName)
    {
        FileReader Reader;
        if (!Reader.Load(DriverPath)) return KbLdrCreationFailure;
        return KbRtlMapDriverMemory(Reader.GetMemory(), DriverName);
    }

    KbLdrStatus WINAPI KbRtlLoadModuleMemory(PVOID DriverImage, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* ImageBase)
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

            PEAnalyzer Module(Loader.get(), FALSE);

            WdkTypes::HMODULE hModule = NULL;
            BOOL Status = VirtualMemory::KbAllocKernelMemory(Loader.getDeployedSize(), TRUE, &hModule);
            if (!Status) throw KbLdrKernelMemoryNotAllocated;

            Loader.relocate(reinterpret_cast<HMODULE>(hModule));

            Status = VirtualMemory::KbCopyMoveMemory(
                hModule, 
                reinterpret_cast<WdkTypes::PVOID>(Loader.get()), 
                Loader.getDeployedSize(), 
                FALSE
            );

            if (!Status) {
                VirtualMemory::KbFreeKernelMemory(hModule);
                return KbLdrTransitionFailure;
            }

            WdkTypes::PVOID ModuleBase = reinterpret_cast<WdkTypes::PVOID>(Module.getImageBase());
            WdkTypes::PVOID OnLoad = NULL, OnUnload = NULL, OnDeviceControl = NULL;
            const auto& Exports = Module.getExportsInfo();
            for (const auto& Export : Exports.exports) {
                WdkTypes::PVOID VA = hModule + static_cast<WdkTypes::PVOID>(Export.rva);
                if (Export.name == "OnLoad") {
                    OnLoad = VA;
                } else if (Export.name == "OnUnload") {
                    OnUnload = VA;
                } else if (Export.name == "OnDeviceControl") {
                    OnDeviceControl = VA;
                }
            }

            Status = LoadableModules::KbLoadModule(
                hModule,
                ModuleName,
                OnLoad,
                OnUnload,
                OnDeviceControl
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

    KbLdrStatus WINAPI KbRtlLoadModuleFile(LPCWSTR ModulePath, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule)
    {
        FileReader Reader;
        if (!Reader.Load(ModulePath)) return KbLdrCreationFailure;
        return KbRtlLoadModuleMemory(Reader.GetMemory(), ModuleName, hModule);
    }
}