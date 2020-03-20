#include <ntifs.h>

#include "MemoryUtils.h"
#include "PTE.h"
#include "Registers.h"
#include "PteUtils.h"

namespace Pte {
#ifdef _AMD64_
    extern "C" unsigned long long __readcr3();
    extern "C" unsigned long long __readcr4();
    extern "C" void __invlpg(void* Page);
#else
    extern "C" unsigned long __readcr3();
    extern "C" unsigned long __readcr4();
#endif

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN GetPageTables(PVOID Address, OUT PAGE_TABLES_INFO* Info) {
        if (!Info) return FALSE;
        *Info = {};

        using namespace PhysicalMemory;

        VIRTUAL_ADDRESS Va = {};
        Va.Value = reinterpret_cast<unsigned long long>(Address);

        CR3 Cr3 = {};
        Cr3.Value = static_cast<unsigned long long>(__readcr3());

        CR4 Cr4 = {};
        Cr4.Value = static_cast<unsigned long long>(__readcr4());

#ifdef _AMD64_
        PVOID64 Pml4ePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Cr3.x64.Bitmap.PML4) + Va.x64.Generic.PageMapLevel4Offset * sizeof(PML4E::x64));
        Info->Pml4e = reinterpret_cast<PML4E*>(GetVirtualForPhysical(Pml4ePhys));
        if (!Info->Pml4e) return FALSE;
        if (!Info->Pml4e->x64.Generic.P) return TRUE;

        PVOID64 PdpePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pml4e->x64.Generic.PDP) + Va.x64.Generic.PageDirectoryPointerOffset * sizeof(PDPE::x64));
        Info->Pdpe = reinterpret_cast<PDPE*>(GetVirtualForPhysical(PdpePhys));
        if (!Info->Pdpe) return FALSE;
        if (Info->Pdpe->x64.Generic.PS) {
            // Page size = 1 Gb:
            if (!Info->Pdpe->x64.PageSize.Page1Gb.P) return FALSE;
            Info->Type = PAGE_TABLES_INFO::pt64Page1Gb;
        }
        else {
            PVOID64 PdePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pdpe->x64.NonPageSize.Generic.PD) + Va.x64.NonPageSize.Generic.PageDirectoryOffset * sizeof(PDE::x64));
            Info->Pde = reinterpret_cast<PDE*>(GetVirtualForPhysical(PdePhys));
            if (!Info->Pde) return FALSE;
            if (Info->Pde->x64.Generic.PS) {
                // Page size = 2 Mb:
                Info->Type = PAGE_TABLES_INFO::pt64Page2Mb;
            }
            else {
                // Page size = 4 Kb:
                Info->Type = PAGE_TABLES_INFO::pt64Page4Kb;

                PVOID64 PtePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pde->x64.Page4Kb.PT) + Va.x64.NonPageSize.Page4Kb.PageTableOffset * sizeof(PTE::x64));
                Info->Pte = reinterpret_cast<PTE*>(GetVirtualForPhysical(PtePhys));
                if (!Info->Pte) return FALSE;
            }
        }
#else
        if (Cr4.x32.Bitmap.PAE) {
            PVOID64 PdpePhys = reinterpret_cast<PVOID64>(PFN_TO_PDP_PAE(Cr3.x32.Pae.PDP) + Va.x32.Pae.Generic.PageDirectoryPointerOffset * sizeof(PDPE::x32));
            Info->Pdpe = reinterpret_cast<PDPE*>(GetVirtualForPhysical(PdpePhys));
            if (!Info->Pdpe) return FALSE;
            if (!Info->Pdpe->x32.Pae.Generic.P) return TRUE;

            PVOID64 PdePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pdpe->x32.Pae.Generic.PD) + Va.x32.Pae.Generic.PageDirectoryOffset * sizeof(PDE::x32));
            Info->Pde = reinterpret_cast<PDE*>(GetVirtualForPhysical(PdePhys));
            if (!Info->Pde) return FALSE;
            if (!Info->Pde->x32.Pae.Generic.PS) {
                // Page size = 2 Mb:
                Info->Type = PAGE_TABLES_INFO::pt32PaePage2Mb;
            }
            else {
                // Page size = 4 Kb:
                Info->Type = PAGE_TABLES_INFO::pt32PaePage4Kb;

                if (!Info->Pde->x32.Pae.Page4Kb.P) return TRUE;
                PVOID64 PtePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pde->x32.Pae.Page4Kb.PT) + Va.x32.Pae.Page4Kb.PageTableOffset * sizeof(PTE::x32));
                Info->Pte = reinterpret_cast<PTE*>(GetVirtualForPhysical(PtePhys));
                if (!Info->Pte) return FALSE;
            }
        }
        else {
            if (Cr4.x32.Bitmap.PSE) {
                PVOID64 PdePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Cr3.x32.NonPae.PD) + Va.x32.NonPae.Page4Kb.PageDirectoryOffset * sizeof(PDE::x32));
                Info->Pde = reinterpret_cast<PDE*>(GetVirtualForPhysical(PdePhys));
                if (!Info->Pde) return FALSE;

                if (Info->Pde->x32.NonPae.Generic.PS) {
                    // Page size = 4 Mb:
                    Info->Type = PAGE_TABLES_INFO::pt32NonPaePage4Mb;
                }
                else {
                    // Page size = 4 Kb:
                    Info->Type = PAGE_TABLES_INFO::pt32NonPaePage4Kb;

                    if (!Info->Pde->x32.NonPae.Page4Kb.P) return TRUE;

                    PVOID64 PtePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pde->x32.NonPae.Page4Kb.PT) + Va.x32.NonPae.Page4Kb.PageTableOffset * sizeof(PTE::x32));
                    Info->Pte = reinterpret_cast<PTE*>(GetVirtualForPhysical(PtePhys));
                    if (!Info->Pte) return FALSE;
                }
            }
            else {
                // Page size = 4 Kb:
                Info->Type = PAGE_TABLES_INFO::pt32NonPaePage4Kb;

                PVOID64 PdePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Cr3.x32.NonPae.PD) + Va.x32.NonPae.Page4Kb.PageDirectoryOffset * sizeof(PDE::x32));
                Info->Pde = reinterpret_cast<PDE*>(GetVirtualForPhysical(PdePhys));
                if (!Info->Pde) return FALSE;
                if (!Info->Pde->x32.NonPae.Page4Kb.P) return TRUE;

                PVOID64 PtePhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Info->Pde->x32.NonPae.Page4Kb.PT) + Va.x32.NonPae.Page4Kb.PageTableOffset * sizeof(PTE::x32));
                Info->Pte = reinterpret_cast<PTE*>(GetVirtualForPhysical(PtePhys));
                if (!Info->Pte) return FALSE;
            }
        }
#endif
        return TRUE;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN TriggerCopyOnWrite(OPTIONAL PEPROCESS Process, PVOID Address, OPTIONAL OUT PULONG PageSize) {
        BOOLEAN NeedToAttach = Process && Process != PsGetCurrentProcess();
        KAPC_STATE ApcState;
        if (NeedToAttach)
            KeStackAttachProcess(Process, &ApcState);

        BOOLEAN Status = FALSE;
        PAGE_TABLES_INFO Info = {};
        Status = GetPageTables(Address, &Info);
        if (Status) __try {
            // AVL is a 3-bit field:
            //   AVL:CopyOnWrite : 1
            //   AVL:Unused : 1
            //   AVL:Writeable : 1;
            // We're setting the CoW and Writeable bits (0b101):
            constexpr unsigned int COW_AND_WRITEABLE_MASK = 0b101;

            if (PageSize) *PageSize = 0;

            switch (Info.Type) {
            case PAGE_TABLES_INFO::pt32NonPaePage4Kb:
                // PDE -> PTE -> PA:
                if (PageSize) *PageSize = 4096;
                if (Info.Pte->x32.NonPae.Page4Kb.D) break;
                Info.Pte->x32.NonPae.Page4Kb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            case PAGE_TABLES_INFO::pt32NonPaePage4Mb:
                // PDE -> PA:
                if (PageSize) *PageSize = 4096 * 1024;
                if (Info.Pde->x32.NonPae.Page4Mb.D) break;
                Info.Pde->x32.NonPae.Page4Mb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            case PAGE_TABLES_INFO::pt32PaePage4Kb:
                // PDPE -> PDE -> PTE -> PA:
                if (PageSize) *PageSize = 4096;
                if (Info.Pte->x32.Pae.Page4Kb.D) break;
                Info.Pte->x32.Pae.Page4Kb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            case PAGE_TABLES_INFO::pt32PaePage2Mb:
                // PDPE -> PDE -> PA:
                if (PageSize) *PageSize = 2048 * 1024;
                if (Info.Pde->x32.Pae.Page2Mb.D) break;
                Info.Pde->x32.Pae.Page2Mb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            case PAGE_TABLES_INFO::pt64Page4Kb:
                // PML4E -> PDPE -> PDE -> PTE -> PA:
                if (PageSize) *PageSize = 4096;
                if (Info.Pte->x64.Page4Kb.D) break;
                Info.Pte->x64.Page4Kb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            case PAGE_TABLES_INFO::pt64Page2Mb:
                // PML4E -> PDPE -> PDE -> PA:
                if (PageSize) *PageSize = 2048 * 1024;
                if (Info.Pde->x64.Page2Mb.D) break;
                Info.Pde->x64.Page2Mb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            case PAGE_TABLES_INFO::pt64Page1Gb:
                // PML4E -> PDPE -> PA:
                if (PageSize) *PageSize = 1024 * 1024 * 1024;
                if (Info.Pdpe->x64.PageSize.Page1Gb.D) break;
                Info.Pdpe->x64.PageSize.Page1Gb.AVL = COW_AND_WRITEABLE_MASK;
                break;
            }

            __invlpg(Address); // Reset the TLB
            *reinterpret_cast<unsigned char*>(Address) = *reinterpret_cast<unsigned char*>(Address);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = FALSE;
        }

        if (NeedToAttach)
            KeUnstackDetachProcess(&ApcState);

        return Status;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN IsPagePresent(PVOID Address, OPTIONAL OUT PULONG PageSize) {
        BOOLEAN IsPresent = FALSE;
        PAGE_TABLES_INFO Info = {};
        if (GetPageTables(Address, &Info)) __try {

            if (PageSize) *PageSize = 0;

            switch (Info.Type) {
            case PAGE_TABLES_INFO::pt32NonPaePage4Kb:
                // PDE -> PTE -> PA:
                if (PageSize) *PageSize = 4096;
                IsPresent = Info.Pte->x32.NonPae.Page4Kb.P;
                break;
            case PAGE_TABLES_INFO::pt32NonPaePage4Mb:
                // PDE -> PA:
                if (PageSize) *PageSize = 4096 * 1024;
                IsPresent = Info.Pde->x32.NonPae.Page4Mb.P;
                break;
            case PAGE_TABLES_INFO::pt32PaePage4Kb:
                // PDPE -> PDE -> PTE -> PA:
                if (PageSize) *PageSize = 4096;
                IsPresent = Info.Pte->x32.Pae.Page4Kb.P;
                break;
            case PAGE_TABLES_INFO::pt32PaePage2Mb:
                // PDPE -> PDE -> PA:
                if (PageSize) *PageSize = 2048 * 1024;
                IsPresent = Info.Pde->x32.Pae.Page2Mb.P;
                break;
            case PAGE_TABLES_INFO::pt64Page4Kb:
                // PML4E -> PDPE -> PDE -> PTE -> PA:
                if (PageSize) *PageSize = 4096;
                IsPresent = Info.Pte->x64.Page4Kb.P;
                break;
            case PAGE_TABLES_INFO::pt64Page2Mb:
                // PML4E -> PDPE -> PDE -> PA:
                if (PageSize) *PageSize = 2048 * 1024;
                IsPresent = Info.Pde->x64.Page2Mb.P;
                break;
            case PAGE_TABLES_INFO::pt64Page1Gb:
                // PML4E -> PDPE -> PA:
                if (PageSize) *PageSize = 1024 * 1024 * 1024;
                IsPresent = Info.Pdpe->x64.PageSize.Page1Gb.P;
                break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            IsPresent = FALSE;
        }

        return IsPresent;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN IsProcessPagePresent(OPTIONAL PEPROCESS Process, PVOID Address, OPTIONAL OUT PULONG PageSize) {
        if (!Process || Process == PsGetCurrentProcess()) 
            return IsPagePresent(Address, PageSize);
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        BOOLEAN IsPresent = IsPagePresent(Address, PageSize);
        KeUnstackDetachProcess(&ApcState);
        return IsPresent;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN IsMemoryRangePresent(OPTIONAL PEPROCESS Process, PVOID Address, SIZE_T Size) {
        if (!Size) return FALSE;

        BOOLEAN NeedToAttach = Process && Process != PsGetCurrentProcess();
        KAPC_STATE ApcState;
        if (NeedToAttach)
            KeStackAttachProcess(Process, &ApcState);

        BOOLEAN IsPresent = TRUE;

        PVOID Page = Address;
        do {
            ULONG PageSize = 0;
            IsPresent = IsPagePresent(Address, &PageSize) && PageSize;
            if (!IsPresent) break;
            Page = reinterpret_cast<PVOID>(reinterpret_cast<SIZE_T>(ALIGN_DOWN_POINTER_BY(Page, PageSize)) + PageSize);
        } while (Page < reinterpret_cast<PVOID>(reinterpret_cast<SIZE_T>(Address) + Size));

        if (NeedToAttach)
            KeUnstackDetachProcess(&ApcState);

        return IsPresent;
    }
}