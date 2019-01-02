//#define ENABLE_HYPERVISOR

#ifdef ENABLE_HYPERVISOR
#include <ntifs.h>
#include "MemoryUtils.h"

#include "Hypervisor.h"
#include "PTE.h"
#include "DescriptorTables.h"
#include "SVM.h"

extern "C" void _enable();
extern "C" void _disable();

extern "C" void _sgdt(__out void* Gdtr);
extern "C" void __sidt(__out void* Idtr);

extern "C" unsigned long long __readmsr(unsigned long Index);
extern "C" void __writemsr(unsigned long Index, unsigned long long Value);

extern "C" void __cpuid(__out int Info[4], int FunctionIdEax);
extern "C" void __cpuidex(__out int Info[4], int FunctionIdEx, int SubfunctionIdEcx);

extern "C" unsigned long long __readcr0();
extern "C" unsigned long long __readcr2();
extern "C" unsigned long long __readcr3();
extern "C" unsigned long long __readcr4();

extern "C" void __svm_clgi();
extern "C" void __svm_invlpga(void* Va, int ASID);
extern "C" void __svm_skinit(int SLB);
extern "C" void __svm_stgi();
extern "C" void __svm_vmload(size_t VmcbPa);
extern "C" void __svm_vmrun(size_t VmcbPa);
extern "C" void __svm_vmsave(size_t VmcbPa);

extern "C" NTSYSAPI VOID NTAPI RtlCaptureContext(OUT PCONTEXT Context);

namespace Supplementation {
    static PVOID AllocPhys(SIZE_T Size, MEMORY_CACHING_TYPE CachingType = MmNonCached) {
        PVOID Memory = PhysicalMemory::AllocPhysicalMemorySpecifyCache(
            0,
            reinterpret_cast<PVOID64>(MAXDWORD32),
            0,
            Size,
            CachingType
        );
        if (Memory) RtlZeroMemory(Memory, Size);
        return Memory;
    }

    static VOID FreePhys(PVOID Memory) {
        PhysicalMemory::FreePhysicalMemory(Memory);
    }
}

namespace NestedPaging {
    using namespace Supplementation;

    struct NESTED_PAGING_TABLES {
        DECLSPEC_ALIGN(PAGE_SIZE) PML4E Pml4e;
        DECLSPEC_ALIGN(PAGE_SIZE) PDPE Pdpe[512];
        DECLSPEC_ALIGN(PAGE_SIZE) PDE Pde[512][512];
    };

    static NESTED_PAGING_TABLES* BuildNestedPagingTables() {
        using namespace PhysicalMemory;

        NESTED_PAGING_TABLES* Npt = reinterpret_cast<NESTED_PAGING_TABLES*>(AllocPhys(sizeof(*Npt)));
        if (!Npt) return NULL;

        Npt->Pml4e.x64.Page2Mb.P = TRUE; // Present
        Npt->Pml4e.x64.Page2Mb.RW = TRUE; // Writeable
        Npt->Pml4e.x64.Page2Mb.US = TRUE; // User
        Npt->Pml4e.x64.Page2Mb.PDP = reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pdpe[0])) >> PAGE_SHIFT;

        for (int i = 0; i < _ARRAYSIZE(Npt->Pdpe); i++) {
            Npt->Pdpe[i].x64.Page2Mb.P = TRUE; // Present
            Npt->Pdpe[i].x64.Page2Mb.RW = TRUE; // Writeable
            Npt->Pdpe[i].x64.Page2Mb.US = TRUE; // User
            Npt->Pdpe[i].x64.Page2Mb.PD = reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pde[i][0])) >> PAGE_SHIFT;

            for (int j = 0; j < _ARRAYSIZE(Npt->Pde[i]); j++) {
                Npt->Pde[i][j].x64.Page2Mb.P = TRUE; // Present
                Npt->Pde[i][j].x64.Page2Mb.RW = TRUE; // Writeable
                Npt->Pde[i][j].x64.Page2Mb.US = TRUE; // User
                Npt->Pde[i][j].x64.Page2Mb.PhysicalPageBase = i * _ARRAYSIZE(Npt->Pde[i]) + j;
            }
        }

        return Npt;
    }

    static void FreeNestedPagingTables(IN NESTED_PAGING_TABLES* Npt) {
        FreePhys(Npt);
    }
}

namespace SVM {
    using namespace Supplementation;
    using namespace NestedPaging;

    static volatile bool IsVirtualized = false;

    union EFER {
        unsigned long long Value;
        struct {
            unsigned long long SystemCallExtensions : 1; // 1 = enable SYSCALL/SYSRET support
            unsigned long long Reserved0 : 7;
            unsigned long long LongModeEnable : 1;
            unsigned long long Reserved1 : 1;
            unsigned long long LongModeActive : 1;
            unsigned long long NoExecuteEnable : 1;
            unsigned long long SecureVirtualMachineEnable : 1;
            unsigned long long LongModeSegmentLimitEnable : 1;
            unsigned long long FastFxsaveFxrstor : 1;
            unsigned long long TranslationCacheExtension : 1;
            unsigned long long Reserved2 : 48;
        } Bitmap;
    };

    enum AMD_MSR : unsigned long {
        MSR_PAT   = 0x00000277, // Extension of the page tables in SVM (nested paging)
        MSR_EFER  = 0xC0000080, // Etended Feature Enable Register
        MSR_STAR  = 0xC0000081, // Legacy mode: address of a SYSCALL instruction
        MSR_LSTAR = 0xC0000081, // Long mode: address of a SYSCALL instruction
        MSR_CSTAR = 0xC0000081, // Compatibility mode: address of a SYSCALL instruction
        MSR_VM_HSAVE_PA = 0xC0010117, // Physical address of a 4KB block of memory where VMRUN saves host state, and from which #VMEXIT reloads host state
    };

    // Shared between all processors:
    struct SHARED_VM_DATA {
        NESTED_PAGING_TABLES* Npt;
        MSRPM* Msrpm;
    };

    // Unique for each processor:
    struct PRIVATE_VM_DATA {
        DECLSPEC_ALIGN(PAGE_SIZE) VMCB Guest;
        DECLSPEC_ALIGN(PAGE_SIZE) VMCB Host;
        DECLSPEC_ALIGN(PAGE_SIZE) unsigned char HostStateArea[PAGE_SIZE];
        DECLSPEC_ALIGN(PAGE_SIZE) unsigned char VmmStack[KERNEL_STACK_SIZE];
    };

    static SHARED_VM_DATA SharedVmData = {};

    static MSRPM* BuildMsrpm() {
        return reinterpret_cast<MSRPM*>(AllocPhys(sizeof(MSRPM)));
    }

/*
    void FreeMsrpm(MSRPM* Msrpm) {
        FreePhys(Msrpm);
    }
*/
    static void FillVmcbSegmentAttributes(
        _Out_ VMCB_STATE_SAVE_AREA::VMCB_SEGMENT_ATTRIBUTE* Attribute,
        const SEGMENT_SELECTOR* Selector,
        const DESCRIPTOR_TABLE_REGISTER_LONG* Gdtr
    ) {
        auto Gdt = reinterpret_cast<USER_SEGMENT_DESCRIPTOR_LONG*>(Gdtr->BaseAddress);
        auto Descriptor = &Gdt[Selector->Bitmap.SelectorIndex];
        Attribute->Value = 0;
        Attribute->Bitmap.Type   = Descriptor->Generic.Type;
        Attribute->Bitmap.System = Descriptor->Generic.System;
        Attribute->Bitmap.Dpl    = Descriptor->Generic.Dpl;
        Attribute->Bitmap.Present   = Descriptor->Generic.Present;
        Attribute->Bitmap.Available = Descriptor->Generic.Available;
        Attribute->Bitmap.LongMode  = Descriptor->Generic.LongMode;
        Attribute->Bitmap.DefaultOperandSize = Descriptor->Generic.DefaultOperandSize;
        Attribute->Bitmap.Granularity = Descriptor->Generic.Granularity;
    }

    // Virtualize the current processor (core):
    static bool VirtualizeProcessor(SHARED_VM_DATA* Shared, PRIVATE_VM_DATA* Private) {
        using namespace PhysicalMemory;

        CONTEXT Context = {};
        Context.ContextFlags = CONTEXT_ALL;
        RtlCaptureContext(&Context);

        if (IsVirtualized) return true;

        // Interceptions:
        Private->Guest.ControlArea.InterceptCpuid = TRUE;
        Private->Guest.ControlArea.InterceptVmrun = TRUE;
        Private->Guest.ControlArea.InterceptMsr = TRUE;
        Private->Guest.ControlArea.MsrpmBasePa = reinterpret_cast<UINT64>(GetPhysicalAddress(Shared->Msrpm));

        // Guest Address Space ID:
        Private->Guest.ControlArea.GuestAsid = 1;

        // Nested paging:
        Private->Guest.ControlArea.NpEnable = TRUE;
        Private->Guest.ControlArea.NestedPageTableCr3 = reinterpret_cast<UINT64>(GetPhysicalAddress(Shared->Npt));

        DESCRIPTOR_TABLE_REGISTER_LONG Gdtr = {}, Idtr = {};
        _sgdt(&Gdtr);
        __sidt(&Idtr);

        // Setting up the initial guest state to the current system state:
        Private->Guest.StateSaveArea.Gdtr.Base  = Gdtr.BaseAddress;
        Private->Guest.StateSaveArea.Gdtr.Limit = Gdtr.Limit;
        Private->Guest.StateSaveArea.Idtr.Base  = Idtr.BaseAddress;
        Private->Guest.StateSaveArea.Idtr.Limit = Idtr.Limit;

        Private->Guest.StateSaveArea.Cs.Limit = GetSegmentLimit(Context.SegCs);
        Private->Guest.StateSaveArea.Ds.Limit = GetSegmentLimit(Context.SegDs);
        Private->Guest.StateSaveArea.Es.Limit = GetSegmentLimit(Context.SegEs);
        Private->Guest.StateSaveArea.Ss.Limit = GetSegmentLimit(Context.SegSs);
        
        Private->Guest.StateSaveArea.Cs.Selector = Context.SegCs;
        Private->Guest.StateSaveArea.Ds.Selector = Context.SegDs;
        Private->Guest.StateSaveArea.Es.Selector = Context.SegEs;
        Private->Guest.StateSaveArea.Ss.Selector = Context.SegSs;

        FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Cs.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegCs), &Gdtr);
        FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Ds.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegDs), &Gdtr);
        FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Es.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegEs), &Gdtr);
        FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Ss.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegSs), &Gdtr);

        Private->Guest.StateSaveArea.Efer = __readmsr(MSR_EFER);
        Private->Guest.StateSaveArea.Cr0 = __readcr0();
        Private->Guest.StateSaveArea.Cr2 = __readcr2();
        Private->Guest.StateSaveArea.Cr3 = __readcr3();
        Private->Guest.StateSaveArea.Cr4 = __readcr4();
        Private->Guest.StateSaveArea.Rflags = Context.EFlags;
        Private->Guest.StateSaveArea.Rsp = Context.Rsp;
        Private->Guest.StateSaveArea.Rip = Context.Rip;
        Private->Guest.StateSaveArea.GuestPat = __readmsr(MSR_PAT);

        // Enable the SVM:
        EFER Efer = {};
        Efer.Value = __readmsr(MSR_EFER);
        Efer.Bitmap.SecureVirtualMachineEnable = TRUE;
        __writemsr(MSR_EFER, Efer.Value);

        // Store state to the guest VMCB:
        __svm_vmsave(reinterpret_cast<size_t>(GetPhysicalAddress(&Private->Guest)));

        // Store the address of the HostStateArea:
        __writemsr(MSR_VM_HSAVE_PA, reinterpret_cast<UINT64>(GetPhysicalAddress(Private->HostStateArea)));

        // Store state to the host VMCB to load it after the #VMEXIT:
        __svm_vmsave(reinterpret_cast<size_t>(GetPhysicalAddress(&Private->Host)));

        // Ok, let's go:

        return true;
    }

    // Virtualize all processors:
    static bool VirtualizeAllProcessors(OUT SHARED_VM_DATA* Shared) {
        using namespace NestedPaging;

        Shared->Npt = BuildNestedPagingTables();
        if (!Shared->Npt) return false;

        Shared->Msrpm = BuildMsrpm();
        if (!Shared->Msrpm) {
            FreeNestedPagingTables(Shared->Npt);
            return false;
        }

        // Virtualizing each processor:
        ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        for (unsigned int i = 0; i < ProcessorsCount; i++) {
            PROCESSOR_NUMBER ProcessorNumber = {};
            KeGetProcessorNumberFromIndex(i, &ProcessorNumber);

            GROUP_AFFINITY Affinity = {}, PreviousAffinity = {};
            Affinity.Group = ProcessorNumber.Group;
            Affinity.Mask = 1LL << ProcessorNumber.Number;
            KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);

            PRIVATE_VM_DATA* Private = reinterpret_cast<PRIVATE_VM_DATA*>(AllocPhys(sizeof(*Private)));
            VirtualizeProcessor(Shared, Private);

            KeRevertToUserGroupAffinityThread(&PreviousAffinity);
        }

        return true;
    }
}

namespace Hypervisor {
    bool Virtualize() {
        SVM::VirtualizeAllProcessors(&SVM::SharedVmData);
        return true;
    }
}
#endif