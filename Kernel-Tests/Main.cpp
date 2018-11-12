#include "pch.h"

#include "WdkTypes.h"
#include "CtlTypes.h"
#include "FltTypes.h"
#include "User-Bridge.h"
#include "Rtl-Bridge.h"

#include <fltUser.h>
#include "CommPort.h"
#include "Flt-Bridge.h"

#include "Kernel-Tests.h"

#include <vector>
#include <string>
#include <iostream>
#include <set>

#define _NO_CVCONST_H
#include <dbghelp.h>
#include "SymParser.h"

#include "../Kernel-Bridge/API/PTE.h"

#include <intrin.h>

void RunTests() {
    BeeperTest tBeeper(L"Beeper");
    IoplTest tIopl(L"IOPL");
    VirtualMemoryTest tVirtualMemory(L"VirtualMemory");
    MdlTest tMdl(L"Mdl");
    PhysicalMemoryTest tPhysicalMemory(L"PhysicalMemory");
    ProcessesTest tProcesses(L"Processes");
    ShellTest tShell(L"Shells");
    StuffTest tStuff(L"Stuff");
}

class PhysMem {
public:
    static VOID Read(WdkTypes::PVOID Address, OUT PVOID Buffer, ULONG Size, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        if (!PhysicalMemory::KbReadPhysicalMemory(Address, Buffer, Size, CachingType))
            throw GetLastError();
    }

    static VOID Write(WdkTypes::PVOID Address, IN PVOID Buffer, ULONG Size, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        if (!PhysicalMemory::KbWritePhysicalMemory(Address, Buffer, Size, CachingType))
            throw GetLastError();
    }

    static BYTE ReadByte(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        BYTE Buffer = 0;
        Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
        return Buffer;
    }

    static WORD ReadWord(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        WORD Buffer = 0;
        Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
        return Buffer;
    }

    static DWORD ReadDword(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        DWORD Buffer = 0;
        Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
        return Buffer;
    }

    static DWORD64 ReadQword(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        DWORD64 Buffer = 0;
        Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
        return Buffer;
    }

    static VOID WriteByte(WdkTypes::PVOID PhysicalAddress, BYTE Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
    }

    static VOID WriteWord(WdkTypes::PVOID PhysicalAddress, WORD Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
    }

    static VOID WriteDword(WdkTypes::PVOID PhysicalAddress, DWORD Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
    }

    static VOID WriteQword(WdkTypes::PVOID PhysicalAddress, DWORD64 Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
        Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
    }

    static WdkTypes::PVOID GetPhysAddress(WdkTypes::PVOID Address) {
        WdkTypes::PVOID PA = NULL;
        if (!PhysicalMemory::KbGetPhysicalAddress(NULL, Address, &PA))
            throw GetLastError();
        return PA;
    }

    static WdkTypes::PVOID GetVirtualForPhysical(WdkTypes::PVOID PhysicalAddress) {
        WdkTypes::PVOID VirtualAddress = NULL;
        PhysicalMemory::KbGetVirtualForPhysical(PhysicalAddress, &VirtualAddress);
        return VirtualAddress;
    }
};

class VirtMem {
public:
    static VOID Read(WdkTypes::PVOID Dest, WdkTypes::PVOID Src, ULONG Size) {
        if (!VirtualMemory::KbCopyMoveMemory(Dest, Src, Size, FALSE))
            throw GetLastError();
    }

    static VOID Write(WdkTypes::PVOID Dest, WdkTypes::PVOID Src, ULONG Size) {
        if (!VirtualMemory::KbCopyMoveMemory(Dest, Src, Size, FALSE))
            throw GetLastError();
    }

    static BYTE ReadByte(WdkTypes::PVOID VirtualAddress) {
        BYTE Buffer = 0;
        Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
        return Buffer;
    }

    static WORD ReadWord(WdkTypes::PVOID VirtualAddress) {
        WORD Buffer = 0;
        Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
        return Buffer;
    }

    static DWORD ReadDword(WdkTypes::PVOID VirtualAddress) {
        DWORD Buffer = 0;
        Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
        return Buffer;
    }

    static DWORD64 ReadQword(WdkTypes::PVOID VirtualAddress) {
        DWORD64 Buffer = 0;
        Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
        return Buffer;
    }

    static VOID WriteByte(WdkTypes::PVOID VirtualAddress, BYTE Value) {
        Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
    }

    static VOID WriteWord(WdkTypes::PVOID VirtualAddress, WORD Value) {
        Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
    }

    static VOID WriteDword(WdkTypes::PVOID VirtualAddress, DWORD Value) {
        Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
    }

    static VOID WriteQword(WdkTypes::PVOID VirtualAddress, DWORD64 Value) {
        Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
    }
};

void TranslationTest()
{
    using namespace VirtualMemory;
    using namespace PhysicalMemory;
    using namespace KernelShells;

    WdkTypes::PVOID KernelMemory = NULL;
    KbAllocKernelMemory(4096, FALSE, &KernelMemory);

    VIRTUAL_ADDRESS Va = {};
    Va.Value = KernelMemory;

    VirtualLock(&Va, sizeof(Va));

    using REGS = struct {
        CR3 Cr3;
        CR4 Cr4;
    };
    REGS Regs = {};

    KbExecuteShellCode([](auto GetKernelProcAddress, auto Argument) -> ULONG {
        REGS* Regs = (REGS*)Argument;
        Regs->Cr3.Value = __readcr3();
        Regs->Cr4.Value = __readcr4();
        return 0;
    }, &Regs);

    PML4E Pml4e = {};
    PDPE Pdpe = {};
    PDE Pde = {};
    PTE Pte = {};

    try {
        WdkTypes::PVOID pPml4e = PFN_TO_PAGE(Regs.Cr3.x64.Bitmap.PML4) + Va.x64.Page4Kb.PageMapLevel4Offset * sizeof(Pml4e);
        WdkTypes::PVOID VirtPml4e = PhysMem::GetVirtualForPhysical(pPml4e);
        Pml4e.x64.Value = VirtMem::ReadQword(VirtPml4e);

        WdkTypes::PVOID pPdpe = PFN_TO_PAGE(Pml4e.x64.Page4Kb.PDP) + Va.x64.Page4Kb.PageDirectoryPointerOffset * sizeof(Pdpe);
        WdkTypes::PVOID VirtPdpe = PhysMem::GetVirtualForPhysical(pPdpe);
        Pdpe.x64.Value = VirtMem::ReadQword(VirtPdpe);

        WdkTypes::PVOID pPde = PFN_TO_PAGE(Pdpe.x64.Page4Kb.PD) + Va.x64.Page4Kb.PageDirectoryOffset * sizeof(Pde);
        WdkTypes::PVOID VirtPde = PhysMem::GetVirtualForPhysical(pPde);
        Pde.x64.Value = VirtMem::ReadQword(VirtPde);

        WdkTypes::PVOID pPte = PFN_TO_PAGE(Pde.x64.Page4Kb.PT) + Va.x64.Page4Kb.PageTableOffset * sizeof(Pte);
        WdkTypes::PVOID VirtPte = PhysMem::GetVirtualForPhysical(pPte);
        Pte.x64.Value = VirtMem::ReadQword(VirtPte);

        WdkTypes::PVOID PhysicalAddress = PFN_TO_PAGE(Pte.x64.Page4Kb.PhysicalPageBase) + Va.x64.Page4Kb.PageOffset;
        WdkTypes::PVOID ValidPhysicalAddress = PhysMem::GetPhysAddress(Va.Value);

        if (PhysicalAddress == ValidPhysicalAddress)
            printf("Addresses are matched, PA = 0x%llX\n", PhysicalAddress);
        
    } catch (DWORD LastError) {
        printf("LE: 0x%X\r\n", LastError);
    }

    KbFreeKernelMemory(KernelMemory);
}

int main() {
    KbLoader::KbUnload();
    if (KbLoader::KbLoadAsFilter(
        L"C:\\Temp\\Kernel-Bridge\\Kernel-Bridge.sys",
        L"260000" // Altitude of minifilter
    )) {
        TranslationTest();
        
        //for (int i = 0; i < 1; i++) {
        //    WdkTypes::HMODULE hModule = NULL;
        //    KbRtl::KbLdrStatus LdrStatus = KbRtl::KbLoadModuleFile(L"C:\\Temp\\Kernel-Bridge\\KbLoadableModule.dll", L"LdMd", &hModule);
        //    if (LdrStatus == KbRtl::KbLdrSuccess) {
        //        LoadableModules::KbCallModule(hModule, 1, 0x11223344);
        //        LoadableModules::KbCallModule(hModule, 2, 0x1EE7C0DE);
        //        LoadableModules::KbUnloadModule(hModule);
        //    }

        //    RunTests();
        //}
        //KbLoader::KbUnload();
    } else {
        std::wcout << L"Unable to load driver!" << std::endl;
    }

    std::wcout << L"Press any key to exit..." << std::endl;
    std::cin.get();

    return 0;
}