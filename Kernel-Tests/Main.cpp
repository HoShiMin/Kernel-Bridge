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
#include <fstream>

#define _NO_CVCONST_H
#include <dbghelp.h>
#include "SymParser.h"

#include <PTE.h>

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

void TranslationTest(PVOID Address)
{
    using namespace VirtualMemory;
    using namespace PhysicalMemory;
    using namespace KernelShells;
    using namespace Processes::MemoryManagement;

    VIRTUAL_ADDRESS Va = {};
    Va.Value = reinterpret_cast<SIZE_T>(Address);

    printf("Target VA: %p\r\n", Address);

    VirtualLock(Address, 1);

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
        WdkTypes::PVOID pPml4e = PFN_TO_PAGE(Regs.Cr3.x64.Bitmap.PML4) + Va.x64.NonPageSize.Page4Kb.PageMapLevel4Offset * sizeof(Pml4e);
        WdkTypes::PVOID VirtPml4e = PhysMem::GetVirtualForPhysical(pPml4e);
        Pml4e.x64.Value = VirtMem::ReadQword(VirtPml4e);
        printf("PML4E: VA = %p, PA = %p\r\n", (PVOID)VirtPml4e, (PVOID)pPml4e);
        //Pml4e.x64.Page4Kb.US = 1;
        VirtMem::WriteQword(VirtPml4e, Pml4e.x64.Value);

        WdkTypes::PVOID pPdpe = PFN_TO_PAGE(Pml4e.x64.Page4Kb.PDP) + Va.x64.NonPageSize.Page4Kb.PageDirectoryPointerOffset * sizeof(Pdpe);
        WdkTypes::PVOID VirtPdpe = PhysMem::GetVirtualForPhysical(pPdpe);
        Pdpe.x64.Value = VirtMem::ReadQword(VirtPdpe);
        printf("PDPE: VA = %p, PA = %p\r\n", (PVOID)VirtPdpe, (PVOID)pPdpe);
        //Pdpe.x64.Page4Kb.US = 1;
        VirtMem::WriteQword(VirtPdpe, Pdpe.x64.Value);

        WdkTypes::PVOID pPde = PFN_TO_PAGE(Pdpe.x64.NonPageSize.Page4Kb.PD) + Va.x64.NonPageSize.Page4Kb.PageDirectoryOffset * sizeof(Pde);
        WdkTypes::PVOID VirtPde = PhysMem::GetVirtualForPhysical(pPde);
        Pde.x64.Value = VirtMem::ReadQword(VirtPde);
        printf("PDE: VA = %p, PA = %p\r\n", (PVOID)VirtPde, (PVOID)pPde);
        //Pde.x64.Page4Kb.US = 1;
        VirtMem::WriteQword(VirtPde, Pde.x64.Value);

        WdkTypes::PVOID pPte = PFN_TO_PAGE(Pde.x64.Page4Kb.PT) + Va.x64.NonPageSize.Page4Kb.PageTableOffset * sizeof(Pte);
        WdkTypes::PVOID VirtPte = PhysMem::GetVirtualForPhysical(pPte);
        Pte.x64.Value = VirtMem::ReadQword(VirtPte);
        printf("PTE: VA = %p, PA = %p\r\n", (PVOID)VirtPte, (PVOID)pPte);
        //Pte.x64.Page4Kb.US = 1;
        printf("> AVL: %i, G: %i, A: %i, D: %i\n", (int)Pte.x64.Page4Kb.AVL, (int)Pte.x64.Page4Kb.G, (int)Pte.x64.Page4Kb.A, (int)Pte.x64.Page4Kb.D);
        Pte.x64.Page4Kb.AVL = 0b101; // Trigger CoW
        VirtMem::WriteQword(VirtPte, Pte.x64.Value);

        WdkTypes::PVOID PhysicalAddress = PFN_TO_PAGE(Pte.x64.Page4Kb.PhysicalPageBase) + Va.x64.NonPageSize.Page4Kb.PageOffset;
        WdkTypes::PVOID ValidPhysicalAddress = PhysMem::GetPhysAddress(Va.Value);
        printf("PA = 0x%llX, VPA = 0x%llX\n", PhysicalAddress, ValidPhysicalAddress);

        PULONG KMem = (PULONG)Address;
        *KMem = *KMem;

        PhysicalAddress = PFN_TO_PAGE(Pte.x64.Page4Kb.PhysicalPageBase) + Va.x64.NonPageSize.Page4Kb.PageOffset;
        ValidPhysicalAddress = PhysMem::GetPhysAddress(Va.Value);
        printf("PA = 0x%llX, VPA = 0x%llX\n", PhysicalAddress, ValidPhysicalAddress);

        if (PhysicalAddress == ValidPhysicalAddress)
            printf("Addresses are matches, PA = 0x%llX\n", PhysicalAddress);
        
    } catch (DWORD LastError) {
        printf("LE: 0x%X\r\n", LastError);
    }

    //KbFreeNonCachedMemory(KernelMemory, 4096);
}

void SmmTest() {
    SetThreadAffinityMask(GetCurrentThread(), 1);

    UINT64 MsrBaseAddress = 0x30000;
    CPU::KbReadMsr(0xC0010111, &MsrBaseAddress);

    union SMM_ADDR {
        unsigned long long Value;
        struct {
            unsigned long long Reserved0 : 17;
            unsigned long long Base : 35;
            unsigned long long Reserved1 : 12;
        } Bitmap;
    };

    union SMM_MASK {
        unsigned long long Value;
        struct {
            unsigned long long AE : 1;
            unsigned long long TE : 1;
            unsigned long long Reserved0 : 15;
            unsigned long long Base : 35;
            unsigned long long Reserved1 : 12;
        } Bitmap;
    };

    SMM_ADDR MsrProtectedBase = {};
    CPU::KbReadMsr(0xC0010112, &MsrProtectedBase.Value);

    SMM_MASK MsrProtectedMask = {};
    CPU::KbReadMsr(0xC0010113, &MsrProtectedMask.Value);

    __debugbreak();
}

void print_cpuid() {
    int regs[4] = {};
    __cpuid(regs, 0);
    char str[13] = {};
    // CPUID Vendor = RBX + RDX + RCX:
    *(int*)(str + 0) = regs[1]; // RBX
    *(int*)(str + 4) = regs[3]; // RDX
    *(int*)(str + 8) = regs[2]; // RCX
    printf("CPU: %s\r\n", str);
}

void RandomRpmTest() {
    using namespace VirtualMemory;
    using namespace Processes::MemoryManagement;

    PVOID Buffer = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    VirtualLock(Buffer, 4096);

    const WdkTypes::PVOID Base = 0xFFFFFFFFFFFFFFFF;
    for (auto i = Base; i >= 0x7FFFFFFFFFFFFFFF; i -= 4096) {
        BOOL Status = KbReadProcessMemory(GetCurrentProcessId(), Base, Buffer, 4096);
        if (Status) printf("[%p] OK\r\n", (PVOID)i);
    }

    VirtualFree(Buffer, 4096, MEM_FREE);
    printf("Random RPM OK\r\n");
}

int main() {

    printf("[Kernel-Tests]: PID: %i, TID: %i\r\n", GetCurrentProcessId(), GetCurrentThreadId());

    if (KbLoader::KbLoadAsFilter(
        L"C:\\Temp\\Kernel-Bridge\\Kernel-Bridge.sys",
        L"260000" // Altitude of minifilter
    )) {
        RandomRpmTest();
        getchar();
        return 0;

        using namespace Processes::MemoryManagement;
        BYTE Buffer[8] = {};
        
        PVOID Addr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "SetLastError");
        TranslationTest(Addr);

        if (false && Hypervisor::KbVmmEnable()) {
            printf("VMM enabled!\r\n");
            while (true) {
                print_cpuid();
                Sleep(1000);
            }
            Hypervisor::KbVmmDisable();
            printf("VMM disabled!\r\n");
            print_cpuid();
        }
        else {
            printf("Unable to start VMM!\r\n");
        }
        KbLoader::KbUnload();
    } else {
        std::wcout << L"Unable to load driver!" << std::endl;
    }

    std::wcout << L"Press any key to exit..." << std::endl;
    std::cin.get();

    return 0;
}