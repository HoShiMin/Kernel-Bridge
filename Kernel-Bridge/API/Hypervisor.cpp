/*
    Inspired by:
      - SimpleSvm by Satoshi Tanda: https://github.com/tandasat/SimpleSvm
      - SimpleVisor by Alex Ionescu: https://github.com/ionescu007/SimpleVisor
      - Hypervisor From Scratch tutorials: https://rayanfam.com/topics/hypervisor-from-scratch-part-1/
*/

#ifdef _AMD64_

#include <intrin.h>

#include <ntifs.h>
#include "MemoryUtils.h"
#include "Callable.h"

#include "Hypervisor.h"
#include "PTE.h"
#include "Registers.h"
#include "MSR.h"
#include "CPUID.h"
#include "Segmentation.h"
#include "Interrupts.h"
#include "Hyper-V.h"
#include "SVM.h"
#include "VMX.h"

#include <vector>
#include <unordered_set>
#include <unordered_map>

// Defined in VMM.asm:
extern "C" void _sldt(__out SEGMENT_SELECTOR* Selector);
extern "C" void _str(__out SEGMENT_SELECTOR* TaskRegister);
extern "C" void __invd();
/* VMX-only */ extern "C" void __invept(VMX::INVEPT_TYPE Type, __in VMX::INVEPT_DESCRIPTOR* Descriptor);
/* VMX-only */ extern "C" void __invvpid(VMX::INVVPID_TYPE Type, __in VMX::INVVPID_DESCRIPTOR* Descriptor);

extern "C" NTSYSAPI VOID NTAPI RtlCaptureContext(__out PCONTEXT ContextRecord);
extern "C" NTSYSAPI VOID NTAPI RtlRestoreContext(__in PCONTEXT ContextRecord, __in_opt EXCEPTION_RECORD* ExceptionRecord);

// Magic value, defined by hypervisor, triggers #VMEXIT and VMM shutdown:
constexpr unsigned int HYPER_BRIDGE_SIGNATURE = 0x1EE7C0DE;
constexpr unsigned int CPUID_VMM_SHUTDOWN = HYPER_BRIDGE_SIGNATURE;

// Exit action for the SvmVmexitHandler/VmxVmexitHandler:
enum class VMM_STATUS : bool
{
    VMM_SHUTDOWN = false, // Devirtualize the current logical processor
    VMM_CONTINUE = true   // Continue execution in the virtualized environment
};

struct GUEST_CONTEXT
{
    unsigned long long Rax;
    unsigned long long Rbx;
    unsigned long long Rcx;
    unsigned long long Rdx;
    unsigned long long Rsi;
    unsigned long long Rdi;
    unsigned long long Rbp;
    unsigned long long R8;
    unsigned long long R9;
    unsigned long long R10;
    unsigned long long R11;
    unsigned long long R12;
    unsigned long long R13;
    unsigned long long R14;
    unsigned long long R15;
};

static volatile bool g_IsVirtualized = false;

namespace Supplementation
{
    static PVOID AllocPhys(SIZE_T Size, MEMORY_CACHING_TYPE CachingType = MmCached, ULONG MaxPhysBits = 0)
    {
        PVOID64 HighestAcceptableAddress = MaxPhysBits
            ? reinterpret_cast<PVOID64>((1ULL << MaxPhysBits) - 1)
            : reinterpret_cast<PVOID64>((1ULL << 48) - 1);

        PVOID Memory = PhysicalMemory::AllocPhysicalMemorySpecifyCache(
            0,
            HighestAcceptableAddress,
            0,
            Size,
            CachingType
        );
        if (Memory) RtlSecureZeroMemory(Memory, Size);
        return Memory;
    }

    static VOID FreePhys(PVOID Memory)
    {
        PhysicalMemory::FreePhysicalMemory(Memory);
    }

    namespace FastPhys
    {
        // As is from ntoskrnl.exe disassembly (VirtualAddress may be unaligned):
        inline static unsigned long long MiGetPteAddress(unsigned long long VirtualAddress)
        {
            return 0xFFFFF680'00000000ull + ((VirtualAddress >> 9ull) & 0x7FFFFFFFF8ull);
        }

        // To fixup differences between different kernels:
        static const unsigned long long g_PteCorrective = []() -> unsigned long long
        {
            unsigned long long TestVa = reinterpret_cast<unsigned long long>(&g_PteCorrective);

            /* Manual traversal to obtain a valid PTE pointer in system memory */

            VIRTUAL_ADDRESS Va = { TestVa };

            auto Pml4ePhys = PFN_TO_PAGE(CR3{ __readcr3() }.x64.Bitmap.PML4) + Va.x64.NonPageSize.Generic.PageMapLevel4Offset * sizeof(PML4E);
            const PML4E* Pml4e = reinterpret_cast<const PML4E*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(Pml4ePhys) }));

            auto PdpePhys = PFN_TO_PAGE(Pml4e->x64.Generic.PDP) + Va.x64.NonPageSize.Generic.PageDirectoryPointerOffset * sizeof(PDPE);
            const PDPE* Pdpe = reinterpret_cast<const PDPE*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(PdpePhys) }));

            auto PdePhys = PFN_TO_PAGE(Pdpe->x64.NonPageSize.Generic.PD) + Va.x64.NonPageSize.Generic.PageDirectoryOffset * sizeof(PDE);
            const PDE* Pde = reinterpret_cast<const PDE*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(PdePhys) }));

            auto PtePhys = PFN_TO_PAGE(Pde->x64.Page4Kb.PT) + Va.x64.NonPageSize.Page4Kb.PageTableOffset * sizeof(PTE);
            const PTE* Pte = reinterpret_cast<const PTE*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(PtePhys) }));

            /* Then get a PTE pointer by MiGetPteAddress and calculate a difference */

            unsigned long long PteByMi = MiGetPteAddress(TestVa & 0xFFFFFFFFFFFFF000ull);

            return reinterpret_cast<unsigned long long>(Pte) - PteByMi;
        }();

        inline unsigned long long GetPhysAddressFast4KbUnsafe(unsigned long long Va)
        {
            return PFN_TO_PAGE(reinterpret_cast<const PTE*>(MiGetPteAddress(Va) + g_PteCorrective)->x64.Page4Kb.PhysicalPageFrameNumber) + (Va & 0xFFF);
        }

        unsigned long long GetPhysAddressFast4Kb(unsigned long long Cr3, unsigned long long VirtualAddress)
        {
            VIRTUAL_ADDRESS Va = { VirtualAddress };

            auto Pml4ePhys = PFN_TO_PAGE(CR3{ Cr3 }.x64.Bitmap.PML4) + Va.x64.NonPageSize.Generic.PageMapLevel4Offset * sizeof(PML4E);
            const PML4E* Pml4e = reinterpret_cast<const PML4E*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(Pml4ePhys) }));

            auto PdpePhys = PFN_TO_PAGE(Pml4e->x64.Generic.PDP) + Va.x64.NonPageSize.Generic.PageDirectoryPointerOffset * sizeof(PDPE);
            const PDPE* Pdpe = reinterpret_cast<const PDPE*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(PdpePhys) }));

            auto PdePhys = PFN_TO_PAGE(Pdpe->x64.NonPageSize.Generic.PD) + Va.x64.NonPageSize.Generic.PageDirectoryOffset * sizeof(PDE);
            const PDE* Pde = reinterpret_cast<const PDE*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(PdePhys) }));

            auto PtePhys = PFN_TO_PAGE(Pde->x64.Page4Kb.PT) + Va.x64.NonPageSize.Page4Kb.PageTableOffset * sizeof(PTE);
            const PTE* Pte = reinterpret_cast<const PTE*>(MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = static_cast<long long>(PtePhys) }));

            return PFN_TO_PAGE(Pte->x64.Page4Kb.PhysicalPageFrameNumber) + Va.x64.NonPageSize.Page4Kb.PageOffset;
        }
    }
}

namespace VMX
{
    static void FreePrivateVmData(void* Private);
}

namespace
{
    enum class CPU_VENDOR {
        cpuIntel,
        cpuAmd,
        cpuUnknown
    };

    CPU_VENDOR GetCpuVendor()
    {
        static CPU_VENDOR CpuVendor = CPU_VENDOR::cpuUnknown;
        if (CpuVendor != CPU_VENDOR::cpuUnknown)
        {
            return CpuVendor;
        }

        CPUID_REGS Regs;
        __cpuid(Regs.Raw, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (Regs.Regs.Ebx == 'uneG' && Regs.Regs.Edx == 'Ieni' && Regs.Regs.Ecx == 'letn')
        {
            CpuVendor = CPU_VENDOR::cpuIntel;
        }
        else if (Regs.Regs.Ebx == 'htuA' && Regs.Regs.Edx == 'itne' && Regs.Regs.Ecx == 'DMAc')
        {
            CpuVendor = CPU_VENDOR::cpuAmd;
        }
        
        return CpuVendor;
    }

    static void GetHvCpuName(
        __out unsigned long long& rbx,
        __out unsigned long long& rcx,
        __out unsigned long long& rdx
    ) {
        // RBX + RDX + RCX = "Hyper-Bridge":
        rbx = 'epyH';
        rcx = 'egdi';
        rdx = 'rB-r';
    }

    static bool DevirtualizeProcessor(__out void*& PrivateVmData)
    {
        PrivateVmData = NULL;

        // Trigger the #VMEXIT with the predefined arguments:
        CPUID_REGS Regs = {};
        __cpuid(Regs.Raw, CPUID_VMM_SHUTDOWN);
        if (Regs.Regs.Ecx != CPUID_VMM_SHUTDOWN) return false; // Processor not virtualized!

        // Processor is devirtualized now:
        //  Info.Eax -> PRIVATE_VM_DATA* Private LOW
        //  Info.Ebx -> Vmexit RIP
        //  Info.Ecx -> VMEXIT_SIGNATURE
        //  Info.Edx -> PRIVATE_VM_DATA* Private HIGH

        PrivateVmData = reinterpret_cast<void*>(
            (static_cast<UINT64>(Regs.Regs.Edx) << 32u) |
            (static_cast<UINT64>(Regs.Regs.Eax))
        );

        return true;
    }

    static bool DevirtualizeAllProcessors()
    {
        ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        void** PrivateVmDataArray = VirtualMemory::AllocArray<void*>(ProcessorsCount);

        KeIpiGenericCall([](ULONG_PTR Arg) -> ULONG_PTR
        {
            void** PrivateVmDataArray = reinterpret_cast<void**>(Arg);
            ULONG CurrentProcessor = KeGetCurrentProcessorNumber();
            void* PrivateVmData = NULL;
            bool Status = DevirtualizeProcessor(OUT PrivateVmData);
            PrivateVmDataArray[CurrentProcessor] = PrivateVmData; // Data buffer to free
            return static_cast<ULONG_PTR>(Status);
        }, reinterpret_cast<ULONG_PTR>(PrivateVmDataArray));
             
        CPU_VENDOR vendor = GetCpuVendor();

        for (ULONG i = 0; i < ProcessorsCount; ++i)
        {
            if (PrivateVmDataArray[i])
            {
                if (vendor == CPU_VENDOR::cpuIntel)
                {
                    VMX::FreePrivateVmData(PrivateVmDataArray[i]);
                }
                else
                {
                    Supplementation::FreePhys(PrivateVmDataArray[i]);
                }
            }
        }

        g_IsVirtualized = false;

        return true;
    }
}

namespace SVM
{
    using namespace Supplementation;
    using namespace AMD;

    struct NESTED_PAGING_TABLES
    {
        DECLSPEC_ALIGN(PAGE_SIZE) PML4E Pml4e;
        DECLSPEC_ALIGN(PAGE_SIZE) PDPE Pdpe[512];
        DECLSPEC_ALIGN(PAGE_SIZE) PDE Pde[512][512];
    };

    static void BuildNestedPagingTables(__out NESTED_PAGING_TABLES* Npt)
    {
        using namespace PhysicalMemory;

        if (!Npt) return;

        Npt->Pml4e.x64.Page2Mb.P = TRUE; // Present
        Npt->Pml4e.x64.Page2Mb.RW = TRUE; // Writeable
        Npt->Pml4e.x64.Page2Mb.US = TRUE; // User
        Npt->Pml4e.x64.Page2Mb.PDP = PAGE_TO_PFN(reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pdpe[0])));

        for (int i = 0; i < _ARRAYSIZE(Npt->Pdpe); ++i)
        {
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.P = TRUE; // Present
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.RW = TRUE; // Writeable
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.US = TRUE; // User
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.PD = PAGE_TO_PFN(reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pde[i][0])));

            for (int j = 0; j < _ARRAYSIZE(Npt->Pde[i]); ++j)
            {
                Npt->Pde[i][j].x64.Page2Mb.P = TRUE; // Present
                Npt->Pde[i][j].x64.Page2Mb.RW = TRUE; // Writeable
                Npt->Pde[i][j].x64.Page2Mb.US = TRUE; // User
                Npt->Pde[i][j].x64.Page2Mb.PS = TRUE; // Large page
                Npt->Pde[i][j].x64.Page2Mb.PhysicalPageFrameNumber = i * _ARRAYSIZE(Npt->Pde[i]) + j;
            }
        }
    }

    // Defined in the VMM.asm:
    extern "C" void SvmVmmRun(void* InitialVmmStackPointer);

    // Unique for each processor:
    struct PRIVATE_VM_DATA
    {
        union
        {
            struct INITIAL_VMM_STACK_LAYOUT
            {
                PVOID GuestVmcbPa;
                PVOID HostVmcbPa;
                PRIVATE_VM_DATA* Private;
            };
            DECLSPEC_ALIGN(PAGE_SIZE) unsigned char VmmStack[KERNEL_STACK_SIZE];
            struct
            {
                unsigned char FreeSpace[KERNEL_STACK_SIZE - sizeof(INITIAL_VMM_STACK_LAYOUT)];
                INITIAL_VMM_STACK_LAYOUT InitialStack;
            } Layout;
        } VmmStack;
        DECLSPEC_ALIGN(PAGE_SIZE) VMCB Guest;
        DECLSPEC_ALIGN(PAGE_SIZE) VMCB Host;
        DECLSPEC_ALIGN(PAGE_SIZE) unsigned char HostStateArea[PAGE_SIZE];
        DECLSPEC_ALIGN(PAGE_SIZE) MSRPM Msrpm;
        DECLSPEC_ALIGN(PAGE_SIZE) NESTED_PAGING_TABLES Npt;
    };

    static void FillVmcbSegmentAttributes(
        _Out_ VMCB_STATE_SAVE_AREA::VMCB_SEGMENT_ATTRIBUTE* Attribute,
        const SEGMENT_SELECTOR* Selector,
        const DESCRIPTOR_TABLE_REGISTER_LONG* Gdtr
    ) {
        auto Gdt = reinterpret_cast<SEGMENT_DESCRIPTOR_LONG*>(Gdtr->BaseAddress);
        auto Descriptor = reinterpret_cast<USER_SEGMENT_DESCRIPTOR_LONG*>(&Gdt[Selector->Bitmap.SelectorIndex]);
        
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

    void InjectEvent(__out VMCB* Guest, unsigned char Vector, unsigned char Type, unsigned int Code)
    {
        EVENTINJ Event = {};
        Event.Bitmap.Vector = Vector;
        Event.Bitmap.Type = Type;
        Event.Bitmap.ErrorCodeValid = TRUE;
        Event.Bitmap.Valid = TRUE;
        Event.Bitmap.ErrorCode = Code;
        Guest->ControlArea.EventInjection = Event.Value;
    }

    void InjectEvent(__out VMCB* Guest, unsigned char Vector, unsigned char Type)
    {
        EVENTINJ Event = {};
        Event.Bitmap.Vector = Vector;
        Event.Bitmap.Type = Type;
        Event.Bitmap.Valid = TRUE;
        Guest->ControlArea.EventInjection = Event.Value;
    }

    extern "C" VMM_STATUS SvmVmexitHandler(PRIVATE_VM_DATA* Private, GUEST_CONTEXT* Context)
    {
        // Load the host state:
        __svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.HostVmcbPa));
        
        // Restore the guest's RAX that was overwritten by host's RAX on #VMEXIT:
        Context->Rax = Private->Guest.StateSaveArea.Rax;

        VMM_STATUS Status = VMM_STATUS::VMM_CONTINUE;
        switch (Private->Guest.ControlArea.ExitCode)
        {
        case VMEXIT_CPUID:
        {
            CPUID_REGS Regs = {};
            int Function = static_cast<int>(Context->Rax);
            int SubLeaf = static_cast<int>(Context->Rcx);
            __cpuidex(Regs.Raw, Function, SubLeaf);

            switch (Function) {
            case CPUID_VMM_SHUTDOWN:
            {
                // Shutdown was triggered:
                Status = VMM_STATUS::VMM_SHUTDOWN;
                break;
            }
            case CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID:
            {
                // Vendor = 'Hyper-Bridge' as RBX + RDX + RCX:
                Context->Rax = Regs.Regs.Eax;
                GetHvCpuName(Context->Rbx, Context->Rcx, Context->Rdx);
                break;
            }
            default:
            {
                Context->Rax = Regs.Regs.Eax;
                Context->Rbx = Regs.Regs.Ebx;
                Context->Rcx = Regs.Regs.Ecx;
                Context->Rdx = Regs.Regs.Edx;
                break;
            }
            }
            break;
        }
        case VMEXIT_MSR:
        {
            if ((Context->Rcx & MAXUINT32) == static_cast<unsigned int>(AMD_MSR::MSR_EFER) && Private->Guest.ControlArea.ExitInfo1)
            {
                EFER Efer = {};
                Efer.Value = ((Context->Rdx & MAXUINT32) << 32) | (Context->Rax & MAXUINT32);
                if (!Efer.Bitmap.SecureVirtualMachineEnable)
                {
                    InjectEvent(&Private->Guest, 13, 3, 0); // #GP (Vector = 13, Type = Exception)
                    break;
                }
                Private->Guest.StateSaveArea.Efer = Efer.Value;
            }
            break;
        }
        case VMEXIT_VMRUN:
        {
            InjectEvent(&Private->Guest, 13, 3, 0); // #GP (Vector = 13, Type = Exception)
            break;
        }
        }

        if (Status == VMM_STATUS::VMM_SHUTDOWN)
        {
            // We should to devirtualize this processor:
            Context->Rax = reinterpret_cast<UINT64>(Private) & MAXUINT32; // Low part
            Context->Rbx = Private->Guest.ControlArea.NextRip;
            Context->Rcx = Private->Guest.StateSaveArea.Rsp;
            Context->Rdx = reinterpret_cast<UINT64>(Private) >> 32; // High part

            // Load the guest's state:
            __svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.GuestVmcbPa));
            
            // Store the GIF - Global Interrupt Flag:
            _disable();
            __svm_stgi();

            // Disable the SVM by resetting the EFER.SVME bit:
            EFER Efer = {};
            Efer.Value = __readmsr(static_cast<unsigned long>(AMD_MSR::MSR_EFER));
            Efer.Bitmap.SecureVirtualMachineEnable = FALSE;
            __writemsr(static_cast<unsigned long>(AMD_MSR::MSR_EFER), Efer.Value);

            // Restoring the EFlags:
            __writeeflags(Private->Guest.StateSaveArea.Rflags);
        }

        Private->Guest.StateSaveArea.Rax = Context->Rax;
        
        // Go to the next instruction:
        Private->Guest.StateSaveArea.Rip = Private->Guest.ControlArea.NextRip;

        return Status;
    }

    // Virtualize the current logical processor:
    static bool VirtualizeProcessor()
    {
        using namespace PhysicalMemory;

        static volatile bool IsVirtualized = false;
        IsVirtualized = false;

        CONTEXT Context = {};
        Context.ContextFlags = CONTEXT_ALL;
        RtlCaptureContext(&Context);

        if (IsVirtualized) return true;

        // Enable the SVM by setting up the EFER.SVME bit:
        EFER Efer = {};
        Efer.Value = __readmsr(static_cast<unsigned long>(AMD_MSR::MSR_EFER));
        Efer.Bitmap.SecureVirtualMachineEnable = TRUE;
        __writemsr(static_cast<unsigned long>(AMD_MSR::MSR_EFER), Efer.Value);

        PRIVATE_VM_DATA* Private = reinterpret_cast<PRIVATE_VM_DATA*>(AllocPhys(sizeof(*Private)));

        // Interceptions:
        Private->Guest.ControlArea.InterceptCpuid = TRUE;
        Private->Guest.ControlArea.InterceptVmrun = TRUE;
        Private->Guest.ControlArea.InterceptMsr = TRUE;
        Private->Guest.ControlArea.MsrpmBasePa = reinterpret_cast<UINT64>(GetPhysicalAddress(&Private->Msrpm));

        // Guest Address Space ID:
        Private->Guest.ControlArea.GuestAsid = 1;

        // Nested paging:
        BuildNestedPagingTables(&Private->Npt);
        Private->Guest.ControlArea.NpEnable = TRUE;
        Private->Guest.ControlArea.NestedPageTableCr3 = reinterpret_cast<UINT64>(GetPhysicalAddress(&Private->Npt.Pml4e));

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

        Private->Guest.StateSaveArea.Efer = Efer.Value;
        Private->Guest.StateSaveArea.Cr0 = __readcr0();
        Private->Guest.StateSaveArea.Cr2 = __readcr2();
        Private->Guest.StateSaveArea.Cr3 = __readcr3();
        Private->Guest.StateSaveArea.Cr4 = __readcr4();
        Private->Guest.StateSaveArea.Rflags = Context.EFlags;
        Private->Guest.StateSaveArea.Rsp = Context.Rsp;
        Private->Guest.StateSaveArea.Rip = Context.Rip;
        Private->Guest.StateSaveArea.GuestPat = __readmsr(static_cast<unsigned long>(AMD_MSR::MSR_PAT));

        PVOID GuestVmcbPa = GetPhysicalAddress(&Private->Guest);
        PVOID HostVmcbPa = GetPhysicalAddress(&Private->Host);

        // Store state to the guest VMCB:
        __svm_vmsave(reinterpret_cast<size_t>(GuestVmcbPa));

        // Store the address of the HostStateArea:
        __writemsr(static_cast<unsigned long>(AMD_MSR::MSR_VM_HSAVE_PA), reinterpret_cast<UINT64>(GetPhysicalAddress(Private->HostStateArea)));

        // Store state to the host VMCB to load it after the #VMEXIT:
        __svm_vmsave(reinterpret_cast<size_t>(HostVmcbPa));

        // Ok, let's go:
        IsVirtualized = true;
        Private->VmmStack.Layout.InitialStack.GuestVmcbPa = GuestVmcbPa;
        Private->VmmStack.Layout.InitialStack.HostVmcbPa = HostVmcbPa;
        Private->VmmStack.Layout.InitialStack.Private = Private;
        SvmVmmRun(&Private->VmmStack.Layout.InitialStack);
        
        // If SvmVmmRun returns to here, something went wrong:
        FreePhys(Private);
        return false;
    }

    // Virtualize all processors:
    static bool VirtualizeAllProcessors()
    {
        using namespace Supplementation;

        // Virtualizing each processor:
        bool Status = Callable::CallInSystemContext([](void* Arg) -> bool
        {
            return Callable::ForEachCpu([](void* Arg, auto ProcessorNumber) -> bool
            {
                UNREFERENCED_PARAMETER(Arg);
                UNREFERENCED_PARAMETER(ProcessorNumber);
                return VirtualizeProcessor();
            }, Arg);
        }, NULL);

        if (!Status)
            DevirtualizeAllProcessors();

        return Status;
    }

    static bool IsSvmSupported()
    {
        CPUID_REGS Regs = {};
        
        // Check the 'AuthenticAMD' vendor name:
        __cpuid(Regs.Raw, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (Regs.Regs.Ebx != 'htuA' || Regs.Regs.Edx != 'itne' || Regs.Regs.Ecx != 'DMAc') return false;

        // Check the AMD SVM (AMD-V) support:
        constexpr unsigned int CPUID_FN80000001_ECX_SVM = 1 << 2;
        __cpuid(Regs.Raw, CPUID::Generic::CPUID_EXTENDED_FEATURE_INFORMATION);
        if ((Regs.Regs.Ecx & CPUID_FN80000001_ECX_SVM) == 0) return false;

        // Check the Nested Paging support (AMD-RVI):
        constexpr unsigned int CPUID_FN8000000A_EDX_NESTED_PAGING = 1 << 0;
        __cpuid(Regs.Raw, CPUID::AMD::CPUID_SVM_FEATURES);
        if ((Regs.Regs.Edx & CPUID_FN8000000A_EDX_NESTED_PAGING) == 0) return false;

        // Check that the EFER.SVME is writeable (we can enable the SVM):
        VM_CR VmCr = {};
        VmCr.Value = __readmsr(static_cast<unsigned long>(AMD_MSR::MSR_VM_CR));
        if (VmCr.Bitmap.SVMDIS) return false;

        return true;
    }
}

namespace VMX
{
    using namespace Supplementation;
    using namespace Intel;

    namespace VMCALLS
    {
        enum class VMCALL_INDEX
        {
            VmmCall
        };

        unsigned long long VmmCall(unsigned long long(*Fn)(void* Arg), void* Arg, bool SwitchToCallerAddressSpace = false)
        {
            return __kb_vmcall(
                static_cast<unsigned long long>(VMCALL_INDEX::VmmCall),
                reinterpret_cast<unsigned long long>(Fn),
                reinterpret_cast<unsigned long long>(Arg),
                static_cast<unsigned long long>(SwitchToCallerAddressSpace)
            );
        }
    }

    struct MTRR_INFO
    {
        UINT64 MaxPhysAddrBits;
        UINT64 PhysAddrMask;
        IA32_VMX_EPT_VPID_CAP EptVpidCap;
        IA32_MTRRCAP MtrrCap;
        IA32_MTRR_DEF_TYPE MtrrDefType;

        // For the first 1 megabyte of the physical address space:
        union
        {
            MTRR_FIXED_GENERIC Generic[11];
            struct {
                // 512-Kbyte range:
                IA32_MTRR_FIX64K RangeFrom00000To7FFFF;

                // Two 128-Kbyte ranges:
                IA32_MTRR_FIX16K RangeFrom80000To9FFFF;
                IA32_MTRR_FIX16K RangeFromA0000ToBFFFF;

                // Eight 32-Kbyte ranges:
                IA32_MTRR_FIX4K RangeFromC0000ToC7FFF;
                IA32_MTRR_FIX4K RangeFromC8000ToCFFFF;
                IA32_MTRR_FIX4K RangeFromD0000ToD7FFF;
                IA32_MTRR_FIX4K RangeFromD8000ToDFFFF;
                IA32_MTRR_FIX4K RangeFromE0000ToE7FFF;
                IA32_MTRR_FIX4K RangeFromE8000ToEFFFF;
                IA32_MTRR_FIX4K RangeFromF0000ToF7FFF;
                IA32_MTRR_FIX4K RangeFromF8000ToFFFFF;
            } Ranges;
        } Fixed;

        // For the memory above the first megabyte of the physical address space:
        struct
        {
            IA32_MTRR_PHYSBASE PhysBase;
            IA32_MTRR_PHYSMASK PhysMask;
        } Variable[10];

        bool IsSupported;
    };

    // E.g.: MaskLow<char>(5) -> 0b00011111:
    template <typename T>
    constexpr T MaskLow(unsigned char SignificantBits)
    {
        return static_cast<T>((1ULL << SignificantBits) - 1);
    }

    // E.g.: MaskHigh<char>(3) -> 0b11100000:
    template <typename T>
    constexpr T MaskHigh(unsigned char SignificantBits)
    {
        return MaskLow<T>(SignificantBits) << ((sizeof(T) * 8) - SignificantBits);
    }

    static void InitMtrr(__out MTRR_INFO* MtrrInfo)
    {
        *MtrrInfo = {};

        CPUID::FEATURE_INFORMATION Features = {};
        __cpuid(Features.Regs.Raw, CPUID::Intel::CPUID_FEATURE_INFORMATION);
        MtrrInfo->IsSupported = Features.Intel.MTRR;

        if (!MtrrInfo->IsSupported) return;

        CPUID::Intel::VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES MaxAddrSizes = {};
        __cpuid(MaxAddrSizes.Regs.Raw, CPUID::Intel::CPUID_VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES);
        MtrrInfo->MaxPhysAddrBits = MaxAddrSizes.Bitmap.PhysicalAddressBits;
        MtrrInfo->PhysAddrMask = ~MaskLow<unsigned long long>(static_cast<unsigned char>(MtrrInfo->MaxPhysAddrBits));

        MtrrInfo->EptVpidCap.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_EPT_VPID_CAP));
        MtrrInfo->MtrrCap.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRRCAP));
        MtrrInfo->MtrrDefType.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_DEF_TYPE));

        if (MtrrInfo->MtrrCap.Bitmap.FIX && MtrrInfo->MtrrDefType.Bitmap.FE)
        {
            // 512-Kbyte range:
            MtrrInfo->Fixed.Ranges.RangeFrom00000To7FFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX64K_00000));

            // Two 128-Kbyte ranges:
            MtrrInfo->Fixed.Ranges.RangeFrom80000To9FFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX16K_80000));
            MtrrInfo->Fixed.Ranges.RangeFromA0000ToBFFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX16K_A0000));
        
            // Eight 32-Kbyte ranges:
            MtrrInfo->Fixed.Ranges.RangeFromC0000ToC7FFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_C0000));
            MtrrInfo->Fixed.Ranges.RangeFromC8000ToCFFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_C8000));
            MtrrInfo->Fixed.Ranges.RangeFromD0000ToD7FFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_D0000));
            MtrrInfo->Fixed.Ranges.RangeFromD8000ToDFFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_D8000));
            MtrrInfo->Fixed.Ranges.RangeFromE0000ToE7FFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_E0000));
            MtrrInfo->Fixed.Ranges.RangeFromE8000ToEFFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_E8000));
            MtrrInfo->Fixed.Ranges.RangeFromF0000ToF7FFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_F0000));
            MtrrInfo->Fixed.Ranges.RangeFromF8000ToFFFFF.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_FIX4K_F8000));
        }

        for (unsigned i = 0; i < MtrrInfo->MtrrCap.Bitmap.VCNT; ++i)
        {
            if (i == ARRAYSIZE(MtrrInfo->Variable)) break;
            MtrrInfo->Variable[i].PhysBase.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_PHYSBASE0) + i * 2);
            MtrrInfo->Variable[i].PhysMask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_MTRR_PHYSMASK0) + i * 2);
        }
    }

    struct MEMORY_RANGE
    {
        unsigned long long First;
        unsigned long long Last;
    };

    static bool AreRangesIntersects(const MEMORY_RANGE& Range1, const MEMORY_RANGE& Range2)
    {
        return Range1.First <= Range2.Last && Range1.Last >= Range2.First;
    }

    static bool MixMtrrTypes(MTRR_MEMORY_TYPE Type1, MTRR_MEMORY_TYPE Type2, __out MTRR_MEMORY_TYPE& Mixed)
    {
        Mixed = MTRR_MEMORY_TYPE::Uncacheable;

        if (Type1 == MTRR_MEMORY_TYPE::Uncacheable || Type2 == MTRR_MEMORY_TYPE::Uncacheable)
        {
            Mixed = MTRR_MEMORY_TYPE::Uncacheable;
            return true;
        }

        if (Type1 == Type2)
        {
            Mixed = Type1;
            return true;
        }
        else
        {
            if ((Type1 == MTRR_MEMORY_TYPE::WriteThrough || Type1 == MTRR_MEMORY_TYPE::WriteBack)
                && (Type2 == MTRR_MEMORY_TYPE::WriteThrough || Type2 == MTRR_MEMORY_TYPE::WriteBack))
            {
                Mixed = MTRR_MEMORY_TYPE::WriteThrough;
                return true;
            }
        }

        return false; // Memory types are conflicting, returning Uncacheable
    }

    static MTRR_MEMORY_TYPE CalcMemoryTypeByFixedMtrr(
        MTRR_FIXED_GENERIC FixedMtrrGeneric,
        const MEMORY_RANGE& MtrrRange,
        const MEMORY_RANGE& PhysRange
    ) {
        bool Initialized = false;
        MTRR_MEMORY_TYPE MemType = MTRR_MEMORY_TYPE::Uncacheable;

        constexpr unsigned long long RangeBitsMask = 0b1111'1111;
        constexpr unsigned long long RangeBitsCount = 8;
        constexpr unsigned long long RangesCount = (sizeof(FixedMtrrGeneric) * 8) / RangeBitsCount;
        const unsigned long long SubrangeSize = (MtrrRange.Last - MtrrRange.First + 1) / RangeBitsCount;

        for (unsigned int i = 0; i < RangesCount; ++i)
        {
            MEMORY_RANGE Subrange;
            Subrange.First = MtrrRange.First + i * SubrangeSize;
            Subrange.Last = Subrange.First + SubrangeSize - 1;

            if (AreRangesIntersects(PhysRange, Subrange))
            {
                MTRR_MEMORY_TYPE SubrangeType = static_cast<MTRR_MEMORY_TYPE>((FixedMtrrGeneric.Value >> (i * RangeBitsCount)) & RangeBitsMask);
                if (Initialized)
                {
                    bool MixingStatus = MixMtrrTypes(MemType, SubrangeType, OUT MemType);
                    if (!MixingStatus)
                    {
                        // Cache types are conflicting in overlapped regions, returning Uncacheable:
                        MemType = MTRR_MEMORY_TYPE::Uncacheable;
                    }
                }
                else
                {
                    MemType = SubrangeType;
                    Initialized = true;
                }

                // If at least one range is Uncacheable - then
                // all overlapped ranges are Uncacheable:
                if (MemType == MTRR_MEMORY_TYPE::Uncacheable)
                {
                    break;
                }
            }
        }

        return MemType;
    }

    static const MEMORY_RANGE FixedRanges[] = {
        { 0x00000, 0x7FFFF },
        { 0x80000, 0x9FFFF },
        { 0xA0000, 0xBFFFF },
        { 0xC0000, 0xC7FFF },
        { 0xC8000, 0xCFFFF },
        { 0xD0000, 0xD7FFF },
        { 0xD8000, 0xDFFFF },
        { 0xE0000, 0xE7FFF },
        { 0xE8000, 0xEFFFF },
        { 0xF0000, 0xF7FFF },
        { 0xF8000, 0xFFFFF },
    };

    static MTRR_MEMORY_TYPE GetMtrrMemoryType(__in const MTRR_INFO* MtrrInfo, unsigned long long PhysicalAddress, unsigned int PageSize)
    {
        if (!MtrrInfo || !PageSize || !MtrrInfo->MtrrDefType.Bitmap.E)
            return MTRR_MEMORY_TYPE::Uncacheable;

        constexpr unsigned long long FIRST_MEGABYTE = 0x100000ULL;

        MEMORY_RANGE PhysRange = {};
        PhysRange.First = PhysicalAddress;
        PhysRange.Last = PhysicalAddress + PageSize - 1;

        bool IsMemTypeInitialized = false;

        // Default type:
        MTRR_MEMORY_TYPE MemType = static_cast<MTRR_MEMORY_TYPE>(MtrrInfo->MtrrDefType.Bitmap.Type);

        if (PhysicalAddress < FIRST_MEGABYTE && MtrrInfo->MtrrCap.Bitmap.FIX && MtrrInfo->MtrrDefType.Bitmap.FE)
        {
            for (unsigned int i = 0; i < ARRAYSIZE(FixedRanges); ++i)
            {
                MTRR_FIXED_GENERIC MtrrFixedGeneric = {};
                MtrrFixedGeneric.Value = MtrrInfo->Fixed.Generic[i].Value;
                if (AreRangesIntersects(PhysRange, FixedRanges[i]))
                {
                    MTRR_MEMORY_TYPE FixedMemType = CalcMemoryTypeByFixedMtrr(MtrrFixedGeneric, FixedRanges[i], PhysRange);
                    if (FixedMemType == MTRR_MEMORY_TYPE::Uncacheable) return FixedMemType;
                    if (IsMemTypeInitialized)
                    {
                        bool IsMixed = MixMtrrTypes(MemType, FixedMemType, OUT MemType);
                        if (!IsMixed)
                        {
                            return MTRR_MEMORY_TYPE::Uncacheable;
                        }
                    }
                    else
                    {
                        IsMemTypeInitialized = true;
                        MemType = FixedMemType;
                    }
                }
            }
        }

        for (unsigned int i = 0; i < MtrrInfo->MtrrCap.Bitmap.VCNT; ++i)
        {
            // If this entry is valid:
            if (!MtrrInfo->Variable[i].PhysMask.Bitmap.V) continue;
            
            unsigned long long MtrrPhysBase = PFN_TO_PAGE(MtrrInfo->Variable[i].PhysBase.Bitmap.PhysBasePfn);
            unsigned long long MtrrPhysMask = PFN_TO_PAGE(MtrrInfo->Variable[i].PhysMask.Bitmap.PhysMaskPfn) | MtrrInfo->PhysAddrMask;
            unsigned long long MaskedMtrrPhysBase = MtrrPhysBase & MtrrPhysMask;
            MTRR_MEMORY_TYPE VarMemType = MTRR_MEMORY_TYPE::Uncacheable;
            bool IsVarMemTypeInitialized = false;
            for (unsigned long long Page = PhysicalAddress; Page < PhysicalAddress + PageSize; Page += PAGE_SIZE)
            {
                if ((Page & MtrrPhysMask) == MaskedMtrrPhysBase)
                {
                    auto PageMemType = static_cast<MTRR_MEMORY_TYPE>(MtrrInfo->Variable[i].PhysBase.Bitmap.Type);
                    if (IsVarMemTypeInitialized)
                    {
                        bool IsMixed = MixMtrrTypes(VarMemType, PageMemType, OUT VarMemType);
                        if (!IsMixed)
                        {
                            return MTRR_MEMORY_TYPE::Uncacheable;
                        }
                    }
                    else
                    {
                        VarMemType = PageMemType;
                        IsVarMemTypeInitialized = true;
                    }

                    if (VarMemType == MTRR_MEMORY_TYPE::Uncacheable)
                    {
                        return MTRR_MEMORY_TYPE::Uncacheable;
                    }
                }
            }

            if (IsVarMemTypeInitialized)
            {
                if (VarMemType == MTRR_MEMORY_TYPE::Uncacheable)
                {
                    return MTRR_MEMORY_TYPE::Uncacheable;
                }

                if (IsMemTypeInitialized)
                {
                    bool IsMixed = MixMtrrTypes(MemType, VarMemType, OUT MemType);
                    if (!IsMixed)
                    {
                        return MTRR_MEMORY_TYPE::Uncacheable;
                    }
                }
                else
                {
                    MemType = VarMemType;
                    IsMemTypeInitialized = true;
                }
            }
        }

        return MemType;
    }

    // Defined in the VMM.asm:
    extern "C" void VmxVmmRun(void* InitialVmmStackLayout);

    struct EPT_TABLES
    {
        DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4e;
        DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpte[512];
        DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Pde[512][512];
        DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE PteForFirstLargePage[2 * 1048576 / 4096];
    };

    struct EPT_ENTRIES
    {
        EPT_PML4E* Pml4e;
        EPT_PDPTE* Pdpte;
        EPT_PDE* Pde;
        EPT_PTE* Pte;
    };

    struct LARGE_PAGE_LAYOUT
    {
        EPT_PTE Pte[512];
    };

    struct LARGE_PAGE_DESCRIPTOR
    {
        EPT_PDE* Pde;
        EPT_PDE OriginalPde;
        LARGE_PAGE_LAYOUT* Layout;
    };

    struct PAGE_HANDLER
    {
        EPT_PTE OnRead;
        EPT_PTE OnWrite;
        EPT_PTE OnExecute;
        EPT_PTE OnExecuteRead;
        EPT_PTE OnExecuteWrite;
    };

    struct EPT_PTE_HANDLER
    {
        EPT_PTE* Pte;
        PAGE_HANDLER Handlers;
    };

    static void InitializeEptTables(__in const MTRR_INFO* MtrrInfo, __out EPT_TABLES* Ept, __out EPTP* Eptp)
    {
        using namespace PhysicalMemory;

        memset(Ept, 0, sizeof(EPT_TABLES));
        memset(Eptp, 0, sizeof(EPTP));

        PVOID64 Pml4ePhys = GetPhysicalAddress(&Ept->Pml4e);
        Eptp->Bitmap.EptMemoryType = static_cast<unsigned char>(MTRR_MEMORY_TYPE::WriteBack);
        Eptp->Bitmap.PageWalkLength = 3;
        Eptp->Bitmap.AccessedAndDirtyFlagsSupport = FALSE;
        Eptp->Bitmap.EptPml4ePhysicalPfn = PAGE_TO_PFN(reinterpret_cast<UINT64>(Pml4ePhys));

        PVOID64 PdptePhys = GetPhysicalAddress(Ept->Pdpte);
        Ept->Pml4e.Page2Mb.ReadAccess = TRUE;
        Ept->Pml4e.Page2Mb.WriteAccess = TRUE;
        Ept->Pml4e.Page2Mb.ExecuteAccess = TRUE;
        Ept->Pml4e.Page2Mb.EptPdptePhysicalPfn = PAGE_TO_PFN(reinterpret_cast<UINT64>(PdptePhys));

        for (unsigned int i = 0; i < _ARRAYSIZE(Ept->Pdpte); ++i)
        {
            PVOID64 PdePhys = GetPhysicalAddress(Ept->Pde[i]);
            Ept->Pdpte[i].Page2Mb.ReadAccess = TRUE;
            Ept->Pdpte[i].Page2Mb.WriteAccess = TRUE;
            Ept->Pdpte[i].Page2Mb.ExecuteAccess = TRUE;
            Ept->Pdpte[i].Page2Mb.EptPdePhysicalPfn = PAGE_TO_PFN(reinterpret_cast<UINT64>(PdePhys));

            for (unsigned int j = 0; j < _ARRAYSIZE(Ept->Pde[i]); ++j)
            {
                if (i == 0 && j == 0)
                {
                    PVOID64 PtePhys = GetPhysicalAddress(Ept->PteForFirstLargePage);
                    Ept->Pde[i][j].Page4Kb.ReadAccess = TRUE;
                    Ept->Pde[i][j].Page4Kb.WriteAccess = TRUE;
                    Ept->Pde[i][j].Page4Kb.ExecuteAccess = TRUE;
                    Ept->Pde[i][j].Page4Kb.EptPtePhysicalPfn = PAGE_TO_PFN(reinterpret_cast<UINT64>(PtePhys));

                    for (unsigned int k = 0; k < _ARRAYSIZE(Ept->PteForFirstLargePage); ++k)
                    {
                        MTRR_MEMORY_TYPE MemType = MTRR_MEMORY_TYPE::Uncacheable;
                        if (MtrrInfo->IsSupported)
                        {
                            MemType = GetMtrrMemoryType(MtrrInfo, PFN_TO_PAGE(static_cast<unsigned long long>(k)), PAGE_SIZE);
                        }

                        Ept->PteForFirstLargePage[k].Page4Kb.ReadAccess = TRUE;
                        Ept->PteForFirstLargePage[k].Page4Kb.WriteAccess = TRUE;
                        Ept->PteForFirstLargePage[k].Page4Kb.ExecuteAccess = TRUE;
                        Ept->PteForFirstLargePage[k].Page4Kb.Type = static_cast<unsigned char>(MemType);
                        Ept->PteForFirstLargePage[k].Page4Kb.PagePhysicalPfn = k;
                    }
                }
                else
                {
                    unsigned long long PagePfn = i * _ARRAYSIZE(Ept->Pde[i]) + j;
                    constexpr unsigned long long LargePageSize = 2 * 1048576; // 2 Mb

                    MTRR_MEMORY_TYPE MemType = MTRR_MEMORY_TYPE::Uncacheable;
                    if (MtrrInfo->IsSupported)
                    {
                        MemType = GetMtrrMemoryType(MtrrInfo, PFN_TO_LARGE_PAGE(PagePfn), LargePageSize);
                    }

                    Ept->Pde[i][j].Page2Mb.ReadAccess = TRUE;
                    Ept->Pde[i][j].Page2Mb.WriteAccess = TRUE;
                    Ept->Pde[i][j].Page2Mb.ExecuteAccess = TRUE;
                    Ept->Pde[i][j].Page2Mb.Type = static_cast<unsigned char>(MemType);
                    Ept->Pde[i][j].Page2Mb.LargePage = TRUE;
                    Ept->Pde[i][j].Page2Mb.PagePhysicalPfn = PagePfn;
                }
            }
        }
    }

    bool GetEptEntries(unsigned long long PhysicalAddress, const EPT_TABLES& Ept, __out EPT_ENTRIES& Entries)
    {
        VIRTUAL_ADDRESS Addr;
        Addr.x64.Value = PhysicalAddress;

        // Our EPT supports only one PML4E (512 Gb of the physical address space):
        if (Addr.x64.Generic.PageMapLevel4Offset > 0)
        {
            __stosq(reinterpret_cast<unsigned long long*>(&Entries), 0, sizeof(Entries) / sizeof(unsigned long long));
            return false;
        }

        auto PdpteIndex = Addr.x64.NonPageSize.Generic.PageDirectoryPointerOffset;
        auto PdeIndex = Addr.x64.NonPageSize.Generic.PageDirectoryOffset;

        Entries.Pml4e = const_cast<EPT_PML4E*>(&Ept.Pml4e);
        Entries.Pdpte = const_cast<EPT_PDPTE*>(&Ept.Pdpte[PdpteIndex]);
        Entries.Pde = const_cast<EPT_PDE*>(&Ept.Pde[PdpteIndex][PdeIndex]);
        if (Entries.Pde->Generic.LargePage)
        {
            Entries.Pte = reinterpret_cast<EPT_PTE*>(NULL);
        }
        else
        {
            PVOID64 PtPhys = reinterpret_cast<PVOID64>(PFN_TO_PAGE(Entries.Pde->Page4Kb.EptPtePhysicalPfn));
            PVOID PtVa = PhysicalMemory::GetVirtualForPhysical(PtPhys);
            Entries.Pte = &((reinterpret_cast<EPT_PTE*>(PtVa))[Addr.x64.NonPageSize.Page4Kb.PageTableOffset]);
        }

        return true;
    }

    void BuildPtesForPde(__in const EPT_PDE& Pde, __out LARGE_PAGE_LAYOUT& Ptes)
    {
        for (unsigned int i = 0; i < ARRAYSIZE(Ptes.Pte); ++i)
        {
            Ptes.Pte[i].Page4Kb.ReadAccess = TRUE;
            Ptes.Pte[i].Page4Kb.WriteAccess = TRUE;
            Ptes.Pte[i].Page4Kb.ExecuteAccess = TRUE;
            Ptes.Pte[i].Page4Kb.Type = Pde.Page2Mb.Type;
            Ptes.Pte[i].Page4Kb.PagePhysicalPfn = PAGE_TO_PFN(PFN_TO_LARGE_PAGE(Pde.Page2Mb.PagePhysicalPfn)) + i;
        }
    }

    void BuildPageHandler(MTRR_MEMORY_TYPE CacheType, UINT64 ReadPa, UINT64 WritePa, UINT64 ExecutePa, UINT64 ExecuteReadPa, UINT64 ExecuteWritePa, __out PAGE_HANDLER& Handler)
    {
        Handler.OnRead.Value = 0;
        Handler.OnWrite.Value = 0;
        Handler.OnExecute.Value = 0;
        Handler.OnExecuteRead.Value = 0;
        Handler.OnExecuteWrite.Value = 0;

        if (ReadPa)
        {
            Handler.OnRead.Page4Kb.ReadAccess = TRUE;
            Handler.OnRead.Page4Kb.Type = static_cast<unsigned long long>(CacheType);
            Handler.OnRead.Page4Kb.PagePhysicalPfn = PAGE_TO_PFN(ReadPa);
        }

        if (WritePa)
        {
            // We're unable to make a write-only page:
            Handler.OnWrite.Page4Kb.ReadAccess = TRUE; // Without it we will get the EPT_MISCONFIGURATION error
            Handler.OnWrite.Page4Kb.WriteAccess = TRUE;
            Handler.OnWrite.Page4Kb.Type = static_cast<unsigned long long>(CacheType);
            Handler.OnWrite.Page4Kb.PagePhysicalPfn = PAGE_TO_PFN(WritePa);
        }

        if (ExecutePa)
        {
            Handler.OnExecute.Page4Kb.ExecuteAccess = TRUE;
            Handler.OnExecute.Page4Kb.Type = static_cast<unsigned long long>(CacheType);
            Handler.OnExecute.Page4Kb.PagePhysicalPfn = PAGE_TO_PFN(ExecutePa);
        }

        if (ExecuteReadPa)
        {
            Handler.OnExecuteRead.Page4Kb.ReadAccess = TRUE;
            Handler.OnExecuteRead.Page4Kb.ExecuteAccess = TRUE;
            Handler.OnExecuteRead.Page4Kb.Type = static_cast<unsigned long long>(CacheType);
            Handler.OnExecuteRead.Page4Kb.PagePhysicalPfn = PAGE_TO_PFN(ExecuteReadPa);
        }

        if (ExecuteWritePa)
        {
            Handler.OnExecuteWrite.Page4Kb.ReadAccess = TRUE;
            Handler.OnExecuteWrite.Page4Kb.WriteAccess = TRUE;
            Handler.OnExecuteWrite.Page4Kb.ExecuteAccess = TRUE;
            Handler.OnExecuteWrite.Page4Kb.Type = static_cast<unsigned long long>(CacheType);
            Handler.OnExecuteWrite.Page4Kb.PagePhysicalPfn = PAGE_TO_PFN(ExecuteWritePa);
        }

        if (ReadPa && (ReadPa == WritePa))
        {
            Handler.OnRead.Page4Kb.WriteAccess = TRUE;
            Handler.OnWrite.Page4Kb.ReadAccess = TRUE;
        }

        if (WritePa && (WritePa == ExecutePa))
        {
            Handler.OnWrite.Page4Kb.ExecuteAccess = TRUE;
            Handler.OnExecute.Page4Kb.WriteAccess = TRUE;
        }

        if (ExecutePa && (ReadPa == ExecutePa))
        {
            Handler.OnRead.Page4Kb.ExecuteAccess = TRUE;
            Handler.OnExecute.Page4Kb.ReadAccess = TRUE;
        }

        if (ExecuteReadPa && (ExecuteReadPa == ExecuteWritePa))
        {
            Handler.OnExecuteRead.Page4Kb.WriteAccess = TRUE;
        }
    }

    static size_t vmread(size_t field);

    class EptHandler final
    {
    private:
        EPT_TABLES* m_Ept;
        std::unordered_map<uint64_t, LARGE_PAGE_DESCRIPTOR> m_PageDescriptors; // Guest PA (aligned by 2Mb) -> 4Kb PTEs describing a 2Mb page
        std::unordered_map<uint64_t, EPT_PTE_HANDLER> m_Handlers; // Guest PA (aligned by 4Kb) -> Page handlers (EPT entries for RWX)
        VMX::INVEPT_DESCRIPTOR m_InveptDescriptor;

        struct
        {
            const void* Rip;
            EPT_PTE* Pte;
            EPT_PTE PendingPrevEntry;
        } m_PendingHandler;

        constexpr static unsigned int PageSize = 4096;
        constexpr static unsigned int LargePageSize = 2 * 1048576;

        inline void invept()
        {
            __invept(VMX::INVEPT_TYPE::SingleContextInvalidation, &m_InveptDescriptor);
        }

    public:
        EptHandler(__in EPT_TABLES* Ept)
            : m_Ept(Ept)
            , m_PendingHandler({})
            , m_InveptDescriptor({})
        {}

        ~EptHandler()
        {
            for (auto& [_, Desc] : m_PageDescriptors)
            {
                *Desc.Pde = Desc.OriginalPde;
                Supplementation::FreePhys(Desc.Layout);
            }
        }

        void CompleteInitialization(VMX::EPTP Eptp)
        {
            m_InveptDescriptor.Eptp = Eptp.Value;
        }

        void InterceptPage(
            unsigned long long Pa,
            unsigned long long ReadPa,
            unsigned long long WritePa,
            unsigned long long ExecutePa,
            unsigned long long ExecuteReadPa,
            unsigned long long ExecuteWritePa
        ) {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto HandlerEntry = m_Handlers.find(Pa4Kb);
            if (HandlerEntry != m_Handlers.end())
            {
                PAGE_HANDLER Handler = {};
                BuildPageHandler(static_cast<MTRR_MEMORY_TYPE>(HandlerEntry->second.Handlers.OnRead.Page4Kb.Type), ReadPa, WritePa, ExecutePa, ExecuteReadPa, ExecuteWritePa, OUT Handler);
                HandlerEntry->second.Handlers = Handler;
                *HandlerEntry->second.Pte = Handler.OnRead;
                invept();
                return;
            }

            unsigned long long Pa2Mb = ALIGN_DOWN_BY(Pa, LargePageSize);
            auto DescriptorEntry = m_PageDescriptors.find(Pa2Mb);
            if (DescriptorEntry == m_PageDescriptors.end())
            {
                EPT_ENTRIES EptEntries;
                GetEptEntries(Pa2Mb, *m_Ept, OUT EptEntries);

                LARGE_PAGE_DESCRIPTOR Desc = {
                    .Pde = EptEntries.Pde,
                    .OriginalPde = *EptEntries.Pde,
                    .Layout = reinterpret_cast<LARGE_PAGE_LAYOUT*>(Supplementation::AllocPhys(sizeof(LARGE_PAGE_LAYOUT)))
                };

                BuildPtesForPde(Desc.OriginalPde, OUT *Desc.Layout);

                DescriptorEntry = m_PageDescriptors.emplace(Pa2Mb, Desc).first;
            }

            auto& Descriptor = DescriptorEntry->second;
            auto* Pde = &Descriptor.Pde->Page4Kb;
            Pde->LargePage = FALSE;
            Pde->Reserved0 = 0;
            Pde->EptPtePhysicalPfn = PAGE_TO_PFN(reinterpret_cast<uint64_t>(PhysicalMemory::GetPhysicalAddress(Descriptor.Layout)));

            unsigned long long PteIndex = (Pa - Pa2Mb) / PageSize;
            auto* Pte = &Descriptor.Layout->Pte[PteIndex];

            EPT_PTE_HANDLER Handler = {};
            BuildPageHandler(static_cast<MTRR_MEMORY_TYPE>(DescriptorEntry->second.OriginalPde.Page2Mb.Type), ReadPa, WritePa, ExecutePa, ExecuteReadPa, ExecuteWritePa, OUT Handler.Handlers);
            Handler.Pte = Pte;
            m_Handlers.emplace(Pa4Kb, Handler);

            *Pte = Handler.Handlers.OnRead;
            invept();
        }

        void DeinterceptPage(unsigned long long Pa)
        {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto HandlerEntry = m_Handlers.find(Pa4Kb);
            if (HandlerEntry != m_Handlers.end())
            {
                m_Handlers.erase(HandlerEntry);
            }

            if (m_Handlers.empty())
            {
                unsigned long long Pa2Mb = ALIGN_DOWN_BY(Pa, LargePageSize);
                auto DescriptorEntry = m_PageDescriptors.find(Pa2Mb);
                if (DescriptorEntry != m_PageDescriptors.end())
                {
                    auto& Desc = DescriptorEntry->second;
                    *Desc.Pde = Desc.OriginalPde;
                    Supplementation::FreePhys(Desc.Layout);
                    m_PageDescriptors.erase(DescriptorEntry);
                    invept();
                }
            }
        }

        bool HandleRead(unsigned long long Pa)
        {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto Handler = m_Handlers.find(Pa4Kb);
            if (Handler == m_Handlers.end())
            {
                return false;
            }

            auto& Entry = Handler->second;
            auto PteEntry = Entry.Handlers.OnRead;
            if (!PteEntry.Value)
            {
                return false;
            }

            *Entry.Pte = PteEntry;
            invept();

            return true;
        }

        bool HandleWrite(unsigned long long Pa, const void* NextInstruction)
        {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto Handler = m_Handlers.find(Pa4Kb);
            if (Handler == m_Handlers.end())
            {
                return false;
            }

            auto& HandlerEntry = Handler->second;
            if (!HandlerEntry.Handlers.OnWrite.Value)
            {
                return false;
            }

            auto* Pte = HandlerEntry.Pte;
            
            m_PendingHandler.Rip = NextInstruction;
            m_PendingHandler.Pte = Pte;
            m_PendingHandler.PendingPrevEntry = *Pte;

            *Pte = HandlerEntry.Handlers.OnWrite;
            invept();

            return true;
        }

        bool HandleExecute(unsigned long long Pa)
        {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto Handler = m_Handlers.find(Pa4Kb);
            if (Handler == m_Handlers.end())
            {
                return false;
            }

            auto& Entry = Handler->second;
            auto PteEntry = Entry.Handlers.OnExecute;
            if (!PteEntry.Value)
            {
                return false;
            }

            *Entry.Pte = PteEntry;
            invept();

            return true;
        }

        bool HandleExecuteRead(unsigned long long Pa, const void* NextInstruction)
        {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto Handler = m_Handlers.find(Pa4Kb);
            if (Handler == m_Handlers.end())
            {
                return false;
            }

            auto& HandlerEntry = Handler->second;
            if (!HandlerEntry.Handlers.OnExecuteRead.Value)
            {
                return false;
            }

            auto* Pte = HandlerEntry.Pte;

            m_PendingHandler.Rip = NextInstruction;
            m_PendingHandler.Pte = Pte;
            m_PendingHandler.PendingPrevEntry = *Pte;

            *Pte = HandlerEntry.Handlers.OnExecuteRead;
            invept();

            return true;
        }

        bool HandleExecuteWrite(unsigned long long Pa, const void* NextInstruction)
        {
            unsigned long long Pa4Kb = ALIGN_DOWN_BY(Pa, PageSize);
            auto Handler = m_Handlers.find(Pa4Kb);
            if (Handler == m_Handlers.end())
            {
                return false;
            }

            auto& HandlerEntry = Handler->second;
            if (!HandlerEntry.Handlers.OnExecuteWrite.Value)
            {
                return false;
            }

            auto* Pte = HandlerEntry.Pte;

            m_PendingHandler.Rip = NextInstruction;
            m_PendingHandler.Pte = Pte;
            m_PendingHandler.PendingPrevEntry = *Pte;

            *Pte = HandlerEntry.Handlers.OnExecuteWrite;
            invept();

            return true;
        }

        bool CompletePendingHandler(const void* Rip)
        {
            if (m_PendingHandler.Rip != Rip)
            {
                return false;
            }

            *m_PendingHandler.Pte = m_PendingHandler.PendingPrevEntry;
            m_PendingHandler.Rip = NULL;

            invept();

            return true;
        }
    };

    struct SHARED_VM_DATA;

    // Unique for each processor:
    struct PRIVATE_VM_DATA
    {
        union
        {
            DECLSPEC_ALIGN(PAGE_SIZE) unsigned char VmmStack[KERNEL_STACK_SIZE];
            struct
            {
                struct INITIAL_VMM_STACK_LAYOUT
                {
                    PVOID VmcsPa;
                    SHARED_VM_DATA* Shared;
                    PRIVATE_VM_DATA* Private;
                };
                unsigned char FreeSpace[KERNEL_STACK_SIZE - sizeof(INITIAL_VMM_STACK_LAYOUT)];
                INITIAL_VMM_STACK_LAYOUT InitialStack;
            } Layout;
        } VmmStack;

        DECLSPEC_ALIGN(PAGE_SIZE) VMCS Vmxon; // VMXON structure is the same as VMCS with the same size
        DECLSPEC_ALIGN(PAGE_SIZE) VMCS Vmcs;
        DECLSPEC_ALIGN(PAGE_SIZE) MSR_BITMAP MsrBitmap;
        DECLSPEC_ALIGN(PAGE_SIZE) EPT_TABLES Ept;
        DESCRIPTOR_TABLE_REGISTER_LONG Gdtr;
        DESCRIPTOR_TABLE_REGISTER_LONG Idtr;
        EptHandler* EptInterceptor;
    };

    struct VCPU_INFO
    {
        PRIVATE_VM_DATA* VmData;
        MTRR_INFO* MtrrInfo;
        VMX::VM_INSTRUCTION_ERROR Error;
        bool Status;
    };

    struct SHARED_VM_DATA
    {
        VCPU_INFO* Processors; // Array: VCPU_INFO Processors[ProcessorsCount]
        unsigned long long KernelCr3;
        unsigned int ProcessorsCount;
    };

    static SHARED_VM_DATA g_Shared = {};


    bool InterceptPage(
        unsigned long long PagePa,
        __in_opt unsigned long long OnReadPa,
        __in_opt unsigned long long OnWritePa,
        __in_opt unsigned long long OnExecutePa,
        __in_opt unsigned long long OnExecuteReadPa,
        __in_opt unsigned long long OnExecuteWritePa
    ) {
        struct INTERCEPT_INFO
        {
            unsigned long long Pa;
            unsigned long long R, W, X, RX, WX;
        };

        INTERCEPT_INFO Info = { PagePa, OnReadPa, OnWritePa, OnExecutePa, OnExecuteReadPa, OnExecuteWritePa };
        Callable::DpcOnEachCpu([](void* Arg)
        {
            VMCALLS::VmmCall([](void* Arg) -> unsigned long long
            {
                auto* Info = reinterpret_cast<INTERCEPT_INFO*>(Arg);
                g_Shared.Processors[KeGetCurrentProcessorNumber()].VmData->EptInterceptor->InterceptPage(Info->Pa, Info->R, Info->W, Info->X, Info->RX, Info->WX);
                return 0;
            }, Arg);
        }, &Info);

        return true;
    }

    void DeinterceptPage(unsigned long long PagePa)
    {
        Callable::DpcOnEachCpu([](void* Arg)
        {
            VMCALLS::VmmCall([](void* Arg) -> unsigned long long
            {
                auto Page = reinterpret_cast<unsigned long long>(Arg);
                g_Shared.Processors[KeGetCurrentProcessorNumber()].VmData->EptInterceptor->DeinterceptPage(Page);
                return 0;
            }, Arg);
        }, reinterpret_cast<void*>(PagePa));
    }

    static unsigned long long ExtractSegmentBaseAddress(const SEGMENT_DESCRIPTOR_LONG* SegmentDescriptor)
    {
        if (SegmentDescriptor->Generic.System == 0)
        {
            // System segment (16 bytes):
            auto* Descriptor = reinterpret_cast<const SYSTEM_SEGMENT_DESCRIPTOR_LONG*>(SegmentDescriptor);
            return (static_cast<unsigned long long>(Descriptor->Bitmap.BaseAddressHighest) << 32)
                | (static_cast<unsigned long long>(Descriptor->Bitmap.BaseAddressHigh) << 24)
                | (static_cast<unsigned long long>(Descriptor->Bitmap.BaseAddressMiddle) << 16)
                | (static_cast<unsigned long long>(Descriptor->Bitmap.BaseAddressLow));
        }
        else
        {
            // User segment (8 bytes):
            auto* Descriptor = reinterpret_cast<const USER_SEGMENT_DESCRIPTOR_LONG*>(SegmentDescriptor);
            return (static_cast<unsigned long long>(Descriptor->Generic.BaseAddressHigh) << 24)
                | (static_cast<unsigned long long>(Descriptor->Generic.BaseAddressMiddle) << 16)
                | (static_cast<unsigned long long>(Descriptor->Generic.BaseAddressLow));
        }
    }

    struct SEGMENT_INFO
    {
        unsigned long long BaseAddress;
        unsigned int Limit;
        SEGMENT_ACCESS_RIGHTS AccessRights;
        unsigned short Selector;
    };

    static void ParseSegmentInfo(
        const SEGMENT_DESCRIPTOR_LONG* Gdt,
        const SEGMENT_DESCRIPTOR_LONG* Ldt,
        unsigned short Selector,
        __out SEGMENT_INFO* Info
    ) {
        *Info = {};

        SEGMENT_SELECTOR SegmentSelector;
        SegmentSelector.Value = Selector;

        auto* SegmentDescriptor = SegmentSelector.Bitmap.TableIndicator == 0
            ? reinterpret_cast<const SEGMENT_DESCRIPTOR_LONG*>(&Gdt[SegmentSelector.Bitmap.SelectorIndex])
            : reinterpret_cast<const SEGMENT_DESCRIPTOR_LONG*>(&Ldt[SegmentSelector.Bitmap.SelectorIndex]);

        Info->BaseAddress = ExtractSegmentBaseAddress(SegmentDescriptor);
        Info->Limit = GetSegmentLimit(Selector);

        Info->AccessRights.Bitmap.SegmentType = SegmentDescriptor->Generic.Type;
        Info->AccessRights.Bitmap.S = SegmentDescriptor->Generic.System;
        Info->AccessRights.Bitmap.DPL = SegmentDescriptor->Generic.Dpl;
        Info->AccessRights.Bitmap.P = SegmentDescriptor->Generic.Present;
        Info->AccessRights.Bitmap.AVL = SegmentDescriptor->Generic.Available;
        Info->AccessRights.Bitmap.L = SegmentDescriptor->Generic.LongMode;
        Info->AccessRights.Bitmap.DB = SegmentDescriptor->Generic.System == 1 // If it is a user segment descriptor:
            ? reinterpret_cast<const USER_SEGMENT_DESCRIPTOR_LONG*>(SegmentDescriptor)->Generic.DefaultOperandSize
            : 0; // The DefaultOperandSize is not applicable to system segments and marked as reserved!
        Info->AccessRights.Bitmap.G = SegmentDescriptor->Generic.Granularity;
        Info->AccessRights.Bitmap.SegmentUnusable = static_cast<unsigned int>(!Info->AccessRights.Bitmap.P);
        
        Info->Selector = Selector;
    }

    inline unsigned long long GetVpid()
    {
        return static_cast<unsigned long long>(KeGetCurrentProcessorNumber()) + 1ull;
    }

    union CONTROLS_MASK
    {
        unsigned long long Value;
        struct
        {
            unsigned long long Allowed0Settings : 32;
            unsigned long long Allowed1Settings : 32;
        } Bitmap;
    };

    CONTROLS_MASK GetCr0Mask()
    {
        CONTROLS_MASK Mask = {};
        Mask.Bitmap.Allowed0Settings = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_CR0_FIXED0));
        Mask.Bitmap.Allowed1Settings = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_CR0_FIXED1));
        return Mask;
    }

    CONTROLS_MASK GetCr4Mask()
    {
        CONTROLS_MASK Mask = {};
        Mask.Bitmap.Allowed0Settings = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_CR4_FIXED0));
        Mask.Bitmap.Allowed1Settings = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_CR4_FIXED1));
        return Mask;
    }

    CONTROLS_MASK GetPinControlsMask(IA32_VMX_BASIC VmxBasic)
    {
        CONTROLS_MASK Mask = {};
        if (VmxBasic.Bitmap.AnyVmxControlsThatDefaultToOneMayBeZeroed) {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_TRUE_PINBASED_CTLS));
        } else {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_PINBASED_CTLS));
        }

        return Mask;
    }
    
    CONTROLS_MASK GetPrimaryControlsMask(IA32_VMX_BASIC VmxBasic)
    {
        CONTROLS_MASK Mask = {};
        if (VmxBasic.Bitmap.AnyVmxControlsThatDefaultToOneMayBeZeroed) {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_TRUE_PROCBASED_CTLS));
        } else {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_PROCBASED_CTLS));
        }
        
        return Mask;
    }

    CONTROLS_MASK GetVmexitControlsMask(IA32_VMX_BASIC VmxBasic)
    {
        CONTROLS_MASK Mask = {};
        if (VmxBasic.Bitmap.AnyVmxControlsThatDefaultToOneMayBeZeroed) {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_TRUE_EXIT_CTLS));
        } else {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_EXIT_CTLS));
        }
        
        return Mask;
    }

    CONTROLS_MASK GetVmentryControlsMask(IA32_VMX_BASIC VmxBasic)
    {
        CONTROLS_MASK Mask = {};
        if (VmxBasic.Bitmap.AnyVmxControlsThatDefaultToOneMayBeZeroed) {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_TRUE_ENTRY_CTLS));
        } else {
            Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_ENTRY_CTLS));
        }

        return Mask;
    }

    CONTROLS_MASK GetSecondaryControlsMask()
    {
        CONTROLS_MASK Mask = {};
        Mask.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_PROCBASED_CTLS2));
        return Mask;
    }
    
    template <typename T>
    static T ApplyMask(T VmxControlReg, CONTROLS_MASK Mask)
    {
        VmxControlReg.Value &= Mask.Bitmap.Allowed1Settings;
        VmxControlReg.Value |= Mask.Bitmap.Allowed0Settings;
        return VmxControlReg;
    }

    static size_t vmread(size_t field)
    {
        size_t value = 0;
        __vmx_vmread(field, &value);
        return value;
    }

    _IRQL_requires_(IPI_LEVEL)
    static bool VirtualizeProcessor(__inout SHARED_VM_DATA* Shared)
    {
        using namespace PhysicalMemory;

        volatile LONG IsVirtualized = FALSE;
        InterlockedExchange(&IsVirtualized, FALSE);

        volatile LONG ContextHasBeenRestored = FALSE;
        InterlockedExchange(&ContextHasBeenRestored, FALSE);
        
        volatile unsigned int CurrentProcessor = KeGetCurrentProcessorNumber();
        unsigned int Vpid = CurrentProcessor + 1;

        CONTEXT Context = {};
        Context.ContextFlags = CONTEXT_ALL;
        RtlCaptureContext(&Context);

        if (InterlockedCompareExchange(&IsVirtualized, TRUE, TRUE) == TRUE)
        {
            if (InterlockedCompareExchange(&ContextHasBeenRestored, FALSE, FALSE) == FALSE)
            {
                InterlockedExchange(&ContextHasBeenRestored, TRUE);
                RtlRestoreContext(&Context, NULL);
            }

            Shared->Processors[CurrentProcessor].Status = true;
            _mm_sfence();

            return true;
        }

        IA32_VMX_BASIC VmxBasicInfo = { __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_BASIC)) };

        PRIVATE_VM_DATA* Private = Shared->Processors[CurrentProcessor].VmData;
        if (!Private)
        {
            return false;
        }

        Private->Vmxon.RevisionId.Bitmap.VmcsRevisionId = VmxBasicInfo.Bitmap.VmcsRevision;
        Private->Vmcs.RevisionId.Bitmap.VmcsRevisionId = VmxBasicInfo.Bitmap.VmcsRevision;

        void* VmxonPa = GetPhysicalAddress(&Private->Vmxon);
        Private->VmmStack.Layout.InitialStack.Shared = Shared;
        Private->VmmStack.Layout.InitialStack.VmcsPa = GetPhysicalAddress(&Private->Vmcs);
        Private->VmmStack.Layout.InitialStack.Private = Private;

        CR0 Cr0 = { __readcr0() };
        Cr0 = ApplyMask(Cr0, GetCr0Mask());
        __writecr0(Cr0.Value);

        // Enable the VMX instructions set:
        CR4 Cr4 = { __readcr4() };
        Cr4.x64.Bitmap.VMXE = TRUE;
        Cr4.x64.Bitmap.PCIDE = TRUE;
        Cr4 = ApplyMask(Cr4, GetCr4Mask());
        __writecr4(Cr4.Value);

        unsigned char VmxStatus = 0;

        // Entering the VMX root-mode:
        VmxStatus =  __vmx_on(reinterpret_cast<unsigned long long*>(&VmxonPa));
        if (VmxStatus != 0)
        {
            return false;
        }

        // Resetting the guest VMCS:
        VmxStatus = __vmx_vmclear(reinterpret_cast<unsigned long long*>(&Private->VmmStack.Layout.InitialStack.VmcsPa));
        if (VmxStatus != 0)
        {
            __vmx_off();
            return false;
        }

        // Loading the VMCS as current for the processor:
        VmxStatus = __vmx_vmptrld(reinterpret_cast<unsigned long long*>(&Private->VmmStack.Layout.InitialStack.VmcsPa));
        if (VmxStatus != 0)
        {
            __vmx_off();
            return false;
        }

        __vmx_vmwrite(VMX::VMCS_FIELD_VMCS_LINK_POINTER_FULL, 0xFFFFFFFFFFFFFFFFULL);
        __vmx_vmwrite(VMX::VMCS_FIELD_VIRTUAL_PROCESSOR_IDENTIFIER, Vpid);

        /* CR0 was already read above */
        __vmx_vmwrite(VMX::VMCS_FIELD_CR0_READ_SHADOW, Cr0.x64.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CR0, Cr0.x64.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_CR0, Cr0.x64.Value);

        CR3 Cr3 = { __readcr3() };
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CR3, Cr3.x64.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_CR3, Shared->KernelCr3);

        /* CR4 was already read above */
        CR4 Cr4Mask = Cr4;
        __vmx_vmwrite(VMX::VMCS_FIELD_CR4_READ_SHADOW, Cr4.x64.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CR4, Cr4.x64.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_CR4, Cr4.x64.Value);

        DR7 Dr7 = { __readdr(7) };
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_DR7, Dr7.x64.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_IA32_DEBUGCTL_FULL, __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_DEBUGCTL)));

        __vmx_vmwrite(VMX::VMCS_FIELD_ADDRESS_OF_MSR_BITMAPS_FULL, reinterpret_cast<UINT64>(GetPhysicalAddress(Private->MsrBitmap.MsrBitmap)));

        DESCRIPTOR_TABLE_REGISTER_LONG Gdtr = {}, Idtr = {};
        _sgdt(&Gdtr);
        __sidt(&Idtr);
        Private->Gdtr = Gdtr;
        Private->Idtr = Idtr;

        SEGMENT_SELECTOR Tr = {}, Ldtr = {};
        _sldt(&Ldtr);
        _str(&Tr);

        const auto* Gdt = reinterpret_cast<const SEGMENT_DESCRIPTOR_LONG*>(Gdtr.BaseAddress);
        __assume(Gdt != nullptr);
        const auto* LdtDescriptorInGdt = reinterpret_cast<const SEGMENT_DESCRIPTOR_LONG*>(&Gdt[Ldtr.Bitmap.SelectorIndex]);
        const auto* Ldt = reinterpret_cast<const SEGMENT_DESCRIPTOR_LONG*>(ExtractSegmentBaseAddress(LdtDescriptorInGdt));

        // These fields must be zeroed in host state selector values:
        constexpr unsigned short RPL_MASK = 0b11; // Requested privilege level
        constexpr unsigned short TI_MASK = 0b100; // Table indicator
        constexpr unsigned short HOST_SELECTOR_MASK = TI_MASK | RPL_MASK;

        SEGMENT_INFO SegmentInfo = {};

        ParseSegmentInfo(Gdt, Ldt, Context.SegEs, OUT &SegmentInfo);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_ES_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_ES_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_ES_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_ES_BASE, SegmentInfo.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_ES_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);

        ParseSegmentInfo(Gdt, Ldt, Context.SegCs, OUT &SegmentInfo);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CS_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CS_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CS_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CS_BASE, SegmentInfo.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_CS_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);

        ParseSegmentInfo(Gdt, Ldt, Context.SegSs, OUT &SegmentInfo);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_SS_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_SS_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_SS_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_SS_BASE, SegmentInfo.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_SS_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);

        ParseSegmentInfo(Gdt, Ldt, Context.SegDs, OUT &SegmentInfo);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_DS_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_DS_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_DS_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_DS_BASE, SegmentInfo.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_DS_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);

        ParseSegmentInfo(Gdt, Ldt, Context.SegFs, OUT &SegmentInfo);
        unsigned long long FsBaseAddress = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_FS_BASE));
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_FS_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_FS_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_FS_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_FS_BASE, FsBaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_FS_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_FS_BASE, FsBaseAddress);

        ParseSegmentInfo(Gdt, Ldt, Context.SegGs, OUT &SegmentInfo);
        unsigned long long GsBaseAddress = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_GS_BASE));
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_GS_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_GS_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_GS_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_GS_BASE, GsBaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_GS_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_GS_BASE, GsBaseAddress);

        ParseSegmentInfo(Gdt, Ldt, Ldtr.Value, OUT &SegmentInfo);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_LDTR_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_LDTR_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_LDTR_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_LDTR_BASE, SegmentInfo.BaseAddress);

        ParseSegmentInfo(Gdt, Ldt, Tr.Value, OUT &SegmentInfo);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_TR_SELECTOR, SegmentInfo.Selector);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_TR_LIMIT, SegmentInfo.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_TR_ACCESS_RIGHTS, SegmentInfo.AccessRights.Value);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_TR_BASE, SegmentInfo.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_TR_SELECTOR, SegmentInfo.Selector & ~HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_TR_BASE, SegmentInfo.BaseAddress);

        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_GDTR_LIMIT, Gdtr.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_GDTR_BASE, Gdtr.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_GDTR_BASE, Gdtr.BaseAddress);

        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_IDTR_LIMIT, Idtr.Limit);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_IDTR_BASE, Idtr.BaseAddress);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_IDTR_BASE, Idtr.BaseAddress);

        EPTP Eptp = {};
        InitializeEptTables(IN Shared->Processors[CurrentProcessor].MtrrInfo, OUT &Private->Ept, OUT &Eptp);
        __vmx_vmwrite(VMX::VMCS_FIELD_EPT_POINTER_FULL, Eptp.Value);
        Private->EptInterceptor->CompleteInitialization(Eptp);

        PIN_BASED_VM_EXECUTION_CONTROLS PinControls = {};
        PinControls = ApplyMask(PinControls, GetPinControlsMask(VmxBasicInfo));
        __vmx_vmwrite(VMX::VMCS_FIELD_PIN_BASED_VM_EXECUTION_CONTROLS, PinControls.Value);

        PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS PrimaryControls = {};
        PrimaryControls.Bitmap.UseMsrBitmaps = TRUE;
        PrimaryControls.Bitmap.ActivateSecondaryControls = TRUE;
        PrimaryControls = ApplyMask(PrimaryControls, GetPrimaryControlsMask(VmxBasicInfo));
        __vmx_vmwrite(VMX::VMCS_FIELD_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, PrimaryControls.Value);

        VMEXIT_CONTROLS VmexitControls = {};
        VmexitControls.Bitmap.SaveDebugControls = TRUE;
        VmexitControls.Bitmap.HostAddressSpaceSize = TRUE;
        VmexitControls = ApplyMask(VmexitControls, GetVmexitControlsMask(VmxBasicInfo));
        __vmx_vmwrite(VMX::VMCS_FIELD_VMEXIT_CONTROLS, VmexitControls.Value);

        VMENTRY_CONTROLS VmentryControls = {};
        VmentryControls.Bitmap.LoadDebugControls = TRUE;
        VmentryControls.Bitmap.Ia32ModeGuest = TRUE;
        VmentryControls = ApplyMask(VmentryControls, GetVmentryControlsMask(VmxBasicInfo));
        __vmx_vmwrite(VMX::VMCS_FIELD_VMENTRY_CONTROLS, VmentryControls.Value);

        SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS SecondaryControls = {};
        SecondaryControls.Bitmap.EnableEpt = TRUE;
        SecondaryControls.Bitmap.EnableRdtscp = TRUE;
        SecondaryControls.Bitmap.EnableVpid = TRUE;
        SecondaryControls.Bitmap.EnableInvpcid = TRUE;
        SecondaryControls.Bitmap.EnableVmFunctions = TRUE;
        SecondaryControls.Bitmap.EptViolation = FALSE;
        SecondaryControls.Bitmap.EnableXsavesXrstors = TRUE;
        SecondaryControls = ApplyMask(SecondaryControls, GetSecondaryControlsMask());
        __vmx_vmwrite(VMX::VMCS_FIELD_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, SecondaryControls.Value);

        unsigned long long SysenterCs  = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_SYSENTER_CS));
        unsigned long long SysenterEsp = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_SYSENTER_ESP));
        unsigned long long SysenterEip = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_SYSENTER_EIP));

        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_IA32_SYSENTER_ESP, SysenterEsp);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_IA32_SYSENTER_EIP, SysenterEip);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RSP, Context.Rsp);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RIP, Context.Rip);
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RFLAGS, Context.EFlags);

        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_IA32_SYSENTER_CS, SysenterCs);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_IA32_SYSENTER_ESP, SysenterEsp);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_IA32_SYSENTER_EIP, SysenterEip);
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_RSP, reinterpret_cast<unsigned long long>(&Private->VmmStack.Layout.InitialStack));
        __vmx_vmwrite(VMX::VMCS_FIELD_HOST_RIP, reinterpret_cast<unsigned long long>(VmxVmmRun));

        InterlockedExchange(&IsVirtualized, TRUE);

        __vmx_vmlaunch();

        // If we're here - something went wrong:
        Shared->Processors[CurrentProcessor].Error = static_cast<VM_INSTRUCTION_ERROR>(vmread(VMX::VMCS_FIELD_VM_INSTRUCTION_ERROR));
        
        __vmx_off();
        
        return false;
    }

    void InjectEvent(INTERRUPTION_TYPE Type, INTERRUPT_VECTOR Vector, bool DeliverErrorCode, unsigned int ErrorCode)
    {
        VMENTRY_INTERRUPTION_INFORMATION Event = {};
        Event.Bitmap.VectorOfInterruptOrException = static_cast<unsigned int>(Vector) & 0xFF;
        Event.Bitmap.InterruptionType = static_cast<unsigned int>(Type) & 0b111;
        Event.Bitmap.DeliverErrorCode = DeliverErrorCode;
        Event.Bitmap.Valid = TRUE;
        __vmx_vmwrite(VMX::VMCS_FIELD_VMENTRY_INTERRUPTION_INFORMATION_FIELD, Event.Value);

        if (DeliverErrorCode)
        {
            __vmx_vmwrite(VMX::VMCS_FIELD_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
        }
    }

    void InjectMonitorTrapFlagVmExit()
    {
        // It is a special case of events injection:
        VMENTRY_INTERRUPTION_INFORMATION Event = {};
        Event.Bitmap.VectorOfInterruptOrException = 0;
        Event.Bitmap.InterruptionType = static_cast<unsigned int>(INTERRUPTION_TYPE::OtherEvent);
        Event.Bitmap.Valid = TRUE;
        __vmx_vmwrite(VMX::VMCS_FIELD_VMENTRY_INTERRUPTION_INFORMATION_FIELD, Event.Value);
    }

    void EnableMonitorTrapFlag()
    {
        VMX::PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS PrimaryControls = { static_cast<unsigned int>(vmread(VMX::VMCS_FIELD_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS)) };
        PrimaryControls.Bitmap.MonitorTrapFlag = TRUE;
        __vmx_vmwrite(VMX::VMCS_FIELD_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, PrimaryControls.Value);
    }

    void DisableMonitorTrapFlag()
    {
        VMX::PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS PrimaryControls = { static_cast<unsigned int>(vmread(VMX::VMCS_FIELD_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS)) };
        PrimaryControls.Bitmap.MonitorTrapFlag = FALSE;
        __vmx_vmwrite(VMX::VMCS_FIELD_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, PrimaryControls.Value);
    }

    void DisableGuestInterrupts()
    {
        RFLAGS Rflags = { vmread(VMX::VMCS_FIELD_GUEST_RFLAGS) };
        Rflags.Bitmap.Eflags.Bitmap.IF = FALSE;
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RFLAGS, Rflags.Value);
    }

    void EnableGuestInterrupts()
    {
        RFLAGS Rflags = { vmread(VMX::VMCS_FIELD_GUEST_RFLAGS) };
        Rflags.Bitmap.Eflags.Bitmap.IF = TRUE;
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RFLAGS, Rflags.Value);
    }

    bool IsMsrAllowed(unsigned int MsrIndex)
    {
        if (MsrIndex <= 0x1FFF || (MsrIndex >= 0xC0000000 && MsrIndex <= 0xC0001FFF))
        {
            // Intel MSR:
            return true;
        }
        else if (MsrIndex >= 0x40000000 && MsrIndex <= 0x4000109F)
        {
            // Hyper-V MSR:
            return true;
        }
        else
        {
            // Invalid MSR index:
            return false;
        }
    }

    // Returns NULL if RegNum is RSP:
    unsigned long long* GetRegPtr(unsigned char RegNum, __in GUEST_CONTEXT* Context)
    {
        switch (RegNum)
        {
        case 0:
            return &Context->Rax;
        case 1:
            return &Context->Rcx;
        case 2:
            return &Context->Rdx;
        case 3:
            return &Context->Rbx;
        case 4:
            // RSP (must be obtained by __vmx_vmread(VMCS_FIELD_GUEST_RSP)):
            return nullptr;
        case 5:
            return &Context->Rbp;
        case 6:
            return &Context->Rsi;
        case 7:
            return &Context->Rdi;
        case 8:
            return &Context->R8;
        case 9:
            return &Context->R9;
        case 10:
            return &Context->R10;
        case 11:
            return &Context->R11;
        case 12:
            return &Context->R12;
        case 13:
            return &Context->R13;
        case 14:
            return &Context->R14;
        case 15:
            return &Context->R15;
        default:
            return nullptr;
        }
    }

    namespace VmexitHandlers
    {
        using FnVmexitHandler = VMM_STATUS(*)(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction);

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS EmptyHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Context);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            __debugbreak();

            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS CpuidHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(RepeatInstruction);

            CPUID_REGS Regs = {};
            int Function = static_cast<int>(Context->Rax);
            if (Function == CPUID_VMM_SHUTDOWN)
            {
                Rip += vmread(VMX::VMCS_FIELD_VMEXIT_INSTRUCTION_LENGTH);

                size_t Rsp = vmread(VMX::VMCS_FIELD_GUEST_RSP);

                Context->Rax = reinterpret_cast<UINT64>(Private) & MAXUINT32; // Low part
                Context->Rbx = Rip; // Guest RIP
                Context->Rcx = Rsp; // Guest RSP
                Context->Rdx = reinterpret_cast<UINT64>(Private) >> 32; // High part

                _lgdt(&Private->Gdtr);
                __lidt(&Private->Idtr);

                CR3 Cr3 = {};
                Cr3.Value = vmread(VMX::VMCS_FIELD_GUEST_CR3);
                __writecr3(Cr3.Value);

                RFLAGS Rflags = {};
                Rflags.Value = vmread(VMX::VMCS_FIELD_GUEST_RFLAGS);
                __writeeflags(Rflags.Value);

                __vmx_off();

                RepeatInstruction = true;
                return VMM_STATUS::VMM_SHUTDOWN;
            }

            int SubLeaf = static_cast<int>(Context->Rcx);
            __cpuidex(Regs.Raw, Function, SubLeaf);

            switch (Function)
            {
            case CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID:
            {
                // Vendor = 'Hyper-Bridge' as RBX + RDX + RCX:
                Context->Rax = Regs.Regs.Eax;
                GetHvCpuName(Context->Rbx, Context->Rcx, Context->Rdx);
                break;
            }
            case 0x11223344:
            {
                // Example of events injection:
                InjectEvent(INTERRUPTION_TYPE::HardwareException, INTERRUPT_VECTOR::GeneralProtection, true, 0);
                break;
            }
            case static_cast<int>(HyperV::CPUID::MAX_LEAF_NUMBER_AND_VENDOR_ID) :
            {
                Context->Rax = static_cast<int>(HyperV::CPUID::INTERFACE_SIGNATURE);
                GetHvCpuName(Context->Rbx, Context->Rcx, Context->Rdx);
                break;
            }
            case static_cast<int>(HyperV::CPUID::INTERFACE_SIGNATURE) :
            {
                Context->Rax = '0#vH';
                Context->Rbx = 0;
                Context->Rcx = 0;
                Context->Rdx = 0;
                break;
            }
            default:
            {
                Context->Rax = Regs.Regs.Eax;
                Context->Rbx = Regs.Regs.Ebx;
                Context->Rcx = Regs.Regs.Ecx;
                Context->Rdx = Regs.Regs.Edx;
                break;
            }
            }

            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS XsetbvHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            _xsetbv(static_cast<unsigned int>(Context->Rcx), (Context->Rdx << 32u) | Context->Rax);
            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS EptViolationHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Context);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            VMX::EXIT_QUALIFICATION Info = { vmread(VMX::VMCS_FIELD_EXIT_QUALIFICATION) };
            unsigned long long AccessedPa = vmread(VMX::VMCS_FIELD_GUEST_PHYSICAL_ADDRESS_FULL);

            if (!(Info.EptViolations.GuestPhysicalReadable || Info.EptViolations.GuestPhysicalExecutable))
            {
                // The page is neither readable nor executable (acts as not present):
                InjectEvent(VMX::INTERRUPTION_TYPE::HardwareException, INTERRUPT_VECTOR::GeneralProtection, true, 0);
                return VMM_STATUS::VMM_CONTINUE;
            }

            bool Handled = false;
            
            if (Info.EptViolations.AccessedRead)
            {
                unsigned long long RipPa;
                if (AddressRange::IsUserAddress(reinterpret_cast<void*>(Rip)))
                {
                    __writecr3(vmread(VMX::VMCS_FIELD_GUEST_CR3));
                    RipPa = Supplementation::FastPhys::GetPhysAddressFast4KbUnsafe(Rip);
                    __writecr3(g_Shared.KernelCr3);
                }
                else
                {
                    RipPa = Supplementation::FastPhys::GetPhysAddressFast4KbUnsafe(Rip);
                }

                if (ALIGN_DOWN_BY(AccessedPa, PAGE_SIZE) == ALIGN_DOWN_BY(RipPa, PAGE_SIZE))
                {
                    unsigned long long InstructionLength = vmread(VMX::VMCS_FIELD_VMEXIT_INSTRUCTION_LENGTH);
                    Handled = Private->EptInterceptor->HandleExecuteRead(AccessedPa, reinterpret_cast<void*>(Rip + InstructionLength));
                    if (Handled)
                    {
                        // Perform a single step:
                        EnableMonitorTrapFlag();
                        DisableGuestInterrupts();
                    }
                }
                else
                {
                    Handled = Private->EptInterceptor->HandleRead(AccessedPa);
                }
            }
            else if (Info.EptViolations.AccessedWrite)
            {
                unsigned long long InstructionLength = vmread(VMX::VMCS_FIELD_VMEXIT_INSTRUCTION_LENGTH);

                unsigned long long RipPa;
                if (AddressRange::IsUserAddress(reinterpret_cast<void*>(Rip)))
                {
                    __writecr3(vmread(VMX::VMCS_FIELD_GUEST_CR3));
                    RipPa = Supplementation::FastPhys::GetPhysAddressFast4KbUnsafe(Rip);
                    __writecr3(g_Shared.KernelCr3);
                }
                else
                {
                    RipPa = Supplementation::FastPhys::GetPhysAddressFast4KbUnsafe(Rip);
                }

                if (ALIGN_DOWN_BY(AccessedPa, PAGE_SIZE) == ALIGN_DOWN_BY(RipPa, PAGE_SIZE))
                {
                    Handled = Private->EptInterceptor->HandleExecuteWrite(AccessedPa, reinterpret_cast<void*>(Rip + InstructionLength));
                }
                else
                {
                    Handled = Private->EptInterceptor->HandleWrite(AccessedPa, reinterpret_cast<void*>(Rip + InstructionLength));
                }

                if (Handled)
                {
                    // Perform a single step:
                    EnableMonitorTrapFlag();
                    DisableGuestInterrupts();
                }
            }
            else if (Info.EptViolations.AccessedExecute)
            {
                Handled = Private->EptInterceptor->HandleExecute(AccessedPa);
            }

            if (Handled)
            {
                RepeatInstruction = true;
            }
            else
            {
                InjectEvent(VMX::INTERRUPTION_TYPE::HardwareException, INTERRUPT_VECTOR::GeneralProtection, true, 0);
            }

            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS EptMisconfigurationHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Context);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            unsigned long long FailedPagePa = vmread(VMX::VMCS_FIELD_GUEST_PHYSICAL_ADDRESS_FULL);

            EPT_ENTRIES EptEntries = {};
            GetEptEntries(FailedPagePa, Private->Ept, EptEntries);

            UNREFERENCED_PARAMETER(EptEntries);

            __debugbreak();

            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS MonitorTrapFlagHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Context);

            Private->EptInterceptor->CompletePendingHandler(reinterpret_cast<void*>(Rip));
            DisableMonitorTrapFlag();
            EnableGuestInterrupts();
            RepeatInstruction = true;
            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS ExceptionOrNmiHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Context);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS VmcallHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            if (Context->R10 == HYPER_BRIDGE_SIGNATURE)
            {
                switch (static_cast<VMCALLS::VMCALL_INDEX>(Context->Rcx))
                {
                case VMCALLS::VMCALL_INDEX::VmmCall:
                {
                    unsigned long long(*Fn)(void* Arg) = reinterpret_cast<decltype(Fn)>(Context->Rdx);
                    void* Arg = reinterpret_cast<void*>(Context->R8);
                    bool SwitchToCallerAddressSpace = Context->R9 != 0;

                    unsigned long long Cr3 = 0;
                    if (SwitchToCallerAddressSpace)
                    {
                        Cr3 = __readcr3();
                        __writecr3(vmread(VMX::VMCS_FIELD_GUEST_CR3));
                    }

                    Context->Rax = Fn(Arg);

                    if (SwitchToCallerAddressSpace)
                    {
                        __writecr3(Cr3);
                    }
                    break;
                }
                default:
                {
                    Context->Rax = HYPER_BRIDGE_SIGNATURE;
                }
                }
            }
            else
            {
                HyperV::HYPERCALL_INPUT_VALUE InputValue = { Context->Rcx };
                switch (static_cast<HyperV::HYPERCALL_CODE>(InputValue.Bitmap.CallCode))
                {
                case HyperV::HYPERCALL_CODE::HvSwitchVirtualAddressSpace:
                case HyperV::HYPERCALL_CODE::HvFlushVirtualAddressSpace:
                case HyperV::HYPERCALL_CODE::HvFlushVirtualAddressList:
                case HyperV::HYPERCALL_CODE::HvCallFlushVirtualAddressSpaceEx:
                case HyperV::HYPERCALL_CODE::HvCallFlushVirtualAddressListEx:
                {
                    VMX::INVVPID_DESCRIPTOR InvvpidDesc = {};
                    __invvpid(VMX::INVVPID_TYPE::AllContextsInvalidation, &InvvpidDesc);
                    break;
                }
                case HyperV::HYPERCALL_CODE::HvCallFlushGuestPhysicalAddressSpace:
                case HyperV::HYPERCALL_CODE::HvCallFlushGuestPhysicalAddressList:
                {
                    // Acts as __invept():
                    INVEPT_DESCRIPTOR Desc = {};
                    Desc.Eptp = vmread(VMCS_FIELD_EPT_POINTER_FULL);
                    __invept(VMX::INVEPT_TYPE::GlobalInvalidation, &Desc);
                    break;
                }
                }

                // It is a Hyper-V hypercall - passing through:
                Context->Rax = __hyperv_vmcall(Context->Rcx, Context->Rdx, Context->R8, Context->R9);
            }

            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS RdmsrHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            unsigned long Msr = static_cast<unsigned long>(Context->Rcx);
            if (IsMsrAllowed(Msr))
            {
                // Allowed MSR:
                LARGE_INTEGER Value = {};
                Value.QuadPart = __readmsr(Msr);
                Context->Rdx = Value.HighPart;
                Context->Rax = Value.LowPart;
            }
            else
            {
                // It is unknown MSR (not Intel nor Hyper-V), returning 0:
                Context->Rdx = 0;
                Context->Rax = 0;
            }
            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS WrmsrHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            unsigned int Msr = static_cast<int>(Context->Rcx);
            if (IsMsrAllowed(Msr))
            {
                unsigned long long Value = (static_cast<unsigned long long>(Context->Rdx) << 32u)
                                         | (static_cast<unsigned long long>(Context->Rax));
                __writemsr(Msr, Value);
            }
            return VMM_STATUS::VMM_CONTINUE;
        }

        _IRQL_requires_same_
        _IRQL_requires_min_(DISPATCH_LEVEL)
        static VMM_STATUS VmxRelatedHandler(__inout PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context, unsigned long long Rip, __inout_opt bool& RepeatInstruction)
        {
            UNREFERENCED_PARAMETER(Private);
            UNREFERENCED_PARAMETER(Context);
            UNREFERENCED_PARAMETER(Rip);
            UNREFERENCED_PARAMETER(RepeatInstruction);

            RFLAGS Rflags = {};
            Rflags.Value = vmread(VMX::VMCS_FIELD_GUEST_RFLAGS);
            Rflags.Bitmap.Eflags.Bitmap.CF = TRUE;
            __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RFLAGS, Rflags.Value);

            return VMM_STATUS::VMM_CONTINUE;
        }

        // It is large enough to contain all possible handlers (the last handler has number 68 (EXIT_REASON_TPAUSE)):
        static FnVmexitHandler HandlersTable[72] = {};

        void InsertHandler(VMX::VMX_EXIT_REASON ExitReason, FnVmexitHandler Handler)
        {
            HandlersTable[static_cast<unsigned int>(ExitReason)] = Handler;
        }

        void InitHandlersTable()
        {
            for (auto i = 0u; i < ARRAYSIZE(HandlersTable); ++i)
            {
                HandlersTable[i] = EmptyHandler;
            }

            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_CPUID    , CpuidHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_XSETBV   , XsetbvHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_EPT_VIOLATION, EptViolationHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_EPT_MISCONFIGURATION, EptMisconfigurationHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_MONITOR_TRAP_FLAG, MonitorTrapFlagHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_EXCEPTION_OR_NMI, ExceptionOrNmiHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMCALL   , VmcallHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_RDMSR    , RdmsrHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_WRMSR    , WrmsrHandler);

            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMCLEAR , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMLAUNCH, VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMPTRLD , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMPTRST , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMREAD  , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMWRITE , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMXOFF  , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_VMXON   , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_INVVPID , VmxRelatedHandler);
            InsertHandler(VMX::VMX_EXIT_REASON::EXIT_REASON_INVEPT  , VmxRelatedHandler);

            _mm_sfence();
        }
    }

    _IRQL_requires_same_
    _IRQL_requires_min_(HIGH_LEVEL)
    extern "C" VMM_STATUS VmxVmexitHandler(PRIVATE_VM_DATA* Private, __inout GUEST_CONTEXT* Context)
    {
        /* Interrupts are locked */

        unsigned long long Rip = vmread(VMX::VMCS_FIELD_GUEST_RIP);

        EXIT_REASON ExitReason = {};
        ExitReason.Value = static_cast<unsigned int>(vmread(VMX::VMCS_FIELD_EXIT_REASON));

        bool RepeatInstruction = false;

        VMM_STATUS Status = VmexitHandlers::HandlersTable[ExitReason.Bitmap.BasicExitReason](Private, Context, Rip, RepeatInstruction);

        if (!RepeatInstruction)
        {
            // Go to the next instruction:
            Rip += vmread(VMX::VMCS_FIELD_VMEXIT_INSTRUCTION_LENGTH);
            __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_RIP, Rip);
        }

        return Status;
    }

    static void DbgPrintMtrrEptCacheLayout(__in const EPT_TABLES* Ept, __in const MTRR_INFO* MtrrInfo)
    {
        auto MemTypeToStr = [](MTRR_MEMORY_TYPE MemType) -> const char*
        {
            switch (MemType)
            {
            case MTRR_MEMORY_TYPE::Uncacheable: return "Uncacheable (0)";
            case MTRR_MEMORY_TYPE::WriteCombining: return "WriteCombining (1)";
            case MTRR_MEMORY_TYPE::WriteThrough: return "WriteThrough (4)";
            case MTRR_MEMORY_TYPE::WriteProtected: return "WriteProtected (5)";
            case MTRR_MEMORY_TYPE::WriteBack: return "WriteBack (6)";
            default:
                return "Unknown";
            }
        };

        MTRR_MEMORY_TYPE CurrentRangeType = MTRR_MEMORY_TYPE::Uncacheable;
        unsigned long long RangeBeginning = 0;
        for (unsigned int i = 0; i < _ARRAYSIZE(Ept->Pdpte); ++i)
        {
            for (unsigned int j = 0; j < _ARRAYSIZE(Ept->Pde[i]); ++j)
            {
                if (i == 0 && j == 0)
                {
                    for (unsigned int k = 0; k < _ARRAYSIZE(Ept->PteForFirstLargePage); ++k)
                    {
                        auto Page = Ept->PteForFirstLargePage[k].Page4Kb;
                        MTRR_MEMORY_TYPE MemType = static_cast<MTRR_MEMORY_TYPE>(Page.Type);
                        unsigned long long PagePa = Page.PagePhysicalPfn * PAGE_SIZE;
                        if (MemType != CurrentRangeType)
                        {
                            if ((PagePa - RangeBeginning) > 0)
                            {
                                DbgPrint("Physical range [%p..%p]: %s\r\n", reinterpret_cast<void*>(RangeBeginning), reinterpret_cast<void*>(PagePa - 1), MemTypeToStr(CurrentRangeType));
                            }
                            CurrentRangeType = MemType;
                            RangeBeginning = PagePa;
                        }
                    }
                }
                else
                {
                    constexpr unsigned long long PageSize = 2 * 1048576; // 2 Mb

                    auto Page = Ept->Pde[i][j].Page2Mb;
                    MTRR_MEMORY_TYPE MemType = static_cast<MTRR_MEMORY_TYPE>(Page.Type);
                    unsigned long long PagePa = Page.PagePhysicalPfn * PageSize;
                    if (MemType != CurrentRangeType)
                    {
                        if ((PagePa - RangeBeginning) > 0)
                        {
                            DbgPrint("Physical range [%p..%p]: %s\r\n", reinterpret_cast<void*>(RangeBeginning), reinterpret_cast<void*>(PagePa - 1), MemTypeToStr(CurrentRangeType));
                        }
                        CurrentRangeType = MemType;
                        RangeBeginning = PagePa;
                    }
                }
            }
        }

        DbgPrint("Physical range [%p..%p]: %s\r\n", reinterpret_cast<void*>(RangeBeginning), reinterpret_cast<void*>(512ull * 1024ull * 1048576ull - 1ull), MemTypeToStr(CurrentRangeType));

        DbgPrint("EptVpidCap      : 0x%I64X\r\n", MtrrInfo->EptVpidCap.Value);
        DbgPrint("MaxPhysAddrBits : 0x%I64X\r\n", MtrrInfo->MaxPhysAddrBits);
        DbgPrint("MtrrCap         : 0x%I64X\r\n", MtrrInfo->MtrrCap.Value);
        DbgPrint("MtrrDefType     : 0x%I64X\r\n", MtrrInfo->MtrrDefType.Value);
        DbgPrint("PhysAddrMask    : 0x%I64X\r\n", MtrrInfo->PhysAddrMask);
        DbgPrint("MTRR.Fixed [00000..7FFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFrom00000To7FFFF.Value);
        DbgPrint("MTRR.Fixed [80000..9FFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFrom80000To9FFFF.Value);
        DbgPrint("MTRR.Fixed [A0000..BFFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromA0000ToBFFFF.Value);
        DbgPrint("MTRR.Fixed [C0000..C7FFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromC0000ToC7FFF.Value);
        DbgPrint("MTRR.Fixed [C8000..CFFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromC8000ToCFFFF.Value);
        DbgPrint("MTRR.Fixed [D0000..D7FFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromD0000ToD7FFF.Value);
        DbgPrint("MTRR.Fixed [D8000..DFFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromD8000ToDFFFF.Value);
        DbgPrint("MTRR.Fixed [E0000..E7FFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromE0000ToE7FFF.Value);
        DbgPrint("MTRR.Fixed [E8000..EFFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromE8000ToEFFFF.Value);
        DbgPrint("MTRR.Fixed [F0000..F7FFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromF0000ToF7FFF.Value);
        DbgPrint("MTRR.Fixed [F8000..FFFFF]: 0x%I64X\r\n", MtrrInfo->Fixed.Ranges.RangeFromF8000ToFFFFF.Value);

        for (unsigned int i = 0; i < _ARRAYSIZE(MtrrInfo->Variable); ++i)
        {
            DbgPrint("MTRR.Variable[%u]: Base: 0x%I64X, Mask: 0x%I64X\r\n", i, MtrrInfo->Variable[i].PhysBase.Value, MtrrInfo->Variable[i].PhysMask.Value);
        }
    }

    static bool VirtualizeAllProcessors()
    {
        if (g_IsVirtualized) return true;

        // Virtualizing each processor:
        bool Status = Callable::CallInSystemContext([](PVOID Arg) -> bool
        {
            UNREFERENCED_PARAMETER(Arg);
            auto* Shared = reinterpret_cast<SHARED_VM_DATA*>(Arg);

            Shared->KernelCr3 = __readcr3();

            // Determining the max phys size:
            CPUID::Intel::VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES MaxAddrSizes = {};
            __cpuid(MaxAddrSizes.Regs.Raw, CPUID::Intel::CPUID_VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES);

            // Initializing MTRRs shared between all processors:
            MTRR_INFO MtrrInfo;
            memset(&MtrrInfo, 0, sizeof(MtrrInfo));
            InitMtrr(&MtrrInfo);

            ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
            Shared->Processors = VirtualMemory::AllocArray<VCPU_INFO>(ProcessorsCount);
            for (ULONG i = 0; i < ProcessorsCount; ++i)
            {
                auto Proc = &Shared->Processors[i];
                Proc->VmData = reinterpret_cast<PRIVATE_VM_DATA*>(AllocPhys(sizeof(PRIVATE_VM_DATA), MmCached, MaxAddrSizes.Bitmap.PhysicalAddressBits));
                if (!Shared->Processors[i].VmData)
                {
                    for (ULONG j = 0; j < ProcessorsCount; ++j)
                    {
                        if (Shared->Processors[j].VmData)
                        {
                            FreePhys(Shared->Processors[j].VmData);
                        }
                    }
                    VirtualMemory::FreePoolMemory(Shared->Processors);
                    Shared->Processors = NULL;
                    return false;
                }
                Proc->MtrrInfo = &MtrrInfo;
                Proc->VmData->EptInterceptor = new EptHandler(&Proc->VmData->Ept);
            }

            VmexitHandlers::InitHandlersTable();

            KeIpiGenericCall([](ULONG_PTR Arg) -> ULONG_PTR
            {
                auto* Shared = reinterpret_cast<SHARED_VM_DATA*>(Arg);
                VirtualizeProcessor(Shared);
                return TRUE;
            }, reinterpret_cast<ULONG_PTR>(Shared));

            bool Status = true;
            for (ULONG i = 0; i < ProcessorsCount; ++i)
            {
                Status &= Shared->Processors[i].Status;
                if (!Status)
                {
                    break;
                }
            }

            if (Status)
            {
                DbgPrintMtrrEptCacheLayout(&Shared->Processors[0].VmData->Ept, Shared->Processors[0].MtrrInfo);
            }
            else
            {
                DevirtualizeAllProcessors();
                VirtualMemory::FreePoolMemory(Shared->Processors);
                Shared->Processors = NULL;
            }

            return Status;
        }, &g_Shared);

        g_IsVirtualized = Status;

        return Status;
    }

    static void FreePrivateVmData(void* Private)
    {
        auto* Data = reinterpret_cast<VMX::PRIVATE_VM_DATA*>(Private);
        delete Data->EptInterceptor;
        Supplementation::FreePhys(Private);
    }

    static bool IsVmxSupported()
    {
        CPUID_REGS Regs = {};

        // Check the 'GenuineIntel' vendor name:
        __cpuid(Regs.Raw, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (Regs.Regs.Ebx != 'uneG' || Regs.Regs.Edx != 'Ieni' || Regs.Regs.Ecx != 'letn') return false;

        // Support by processor:
        __cpuid(Regs.Raw, CPUID::Intel::CPUID_FEATURE_INFORMATION);
        if (!reinterpret_cast<CPUID::FEATURE_INFORMATION*>(&Regs)->Intel.VMX) return false;

        // Check the VMX is locked in BIOS:
        IA32_FEATURE_CONTROL MsrFeatureControl = {};
        MsrFeatureControl.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_FEATURE_CONTROL));

        if (MsrFeatureControl.Bitmap.LockBit == FALSE) return false;

        return true;
    }
}
#endif


namespace Hypervisor
{
    bool IsVirtualized()
    {
#ifdef _AMD64_
        return g_IsVirtualized;
#else
        return false;
#endif
    }

    bool Virtualize()
    {
#ifdef _AMD64_
        if (IsVirtualized()) return false;

        CPU_VENDOR CpuVendor = GetCpuVendor();
        if (CpuVendor == CPU_VENDOR::cpuUnknown) return false;

        bool Status = false;

        switch (CpuVendor) {
        case CPU_VENDOR::cpuIntel:
        {
            if (!VMX::IsVmxSupported()) return false;
            Status = VMX::VirtualizeAllProcessors();
            break;
        }
        case CPU_VENDOR::cpuAmd:
        {
            if (!SVM::IsSvmSupported()) return false;
            Status = SVM::VirtualizeAllProcessors();
            break;
        }
        }

        return Status;
#else
        return false;
#endif
    }

    bool Devirtualize()
    {
#ifdef _AMD64_
        DevirtualizeAllProcessors();
        return true;
#else
        return false;
#endif
    }

    bool InterceptPage(
        unsigned long long Pa,
        unsigned long long ReadPa,
        unsigned long long WritePa,
        unsigned long long ExecutePa,
        unsigned long long ExecuteReadPa,
        unsigned long long ExecuteWritePa
    ) {
#ifdef _AMD64_
        CPU_VENDOR CpuVendor = GetCpuVendor();
        switch (CpuVendor)
        {
        case CPU_VENDOR::cpuIntel:
        {
            return VMX::InterceptPage(Pa, ReadPa, WritePa, ExecutePa, ExecuteReadPa, ExecuteWritePa);
        }
        default:
        {
            // Not supported:
            return false;
        }
        }
#else
        // Unreferenced parameters:
        Pa; ReadPa; WritePa; ExecutePa; ExecuteReadPa; ExecuteWritePa;
        return false;
#endif
    }

    bool DeinterceptPage(unsigned long long Pa)
    {
#ifdef _AMD64_
        CPU_VENDOR CpuVendor = GetCpuVendor();
        switch (CpuVendor)
        {
        case CPU_VENDOR::cpuIntel:
        {
            VMX::DeinterceptPage(Pa);
            return true;
        }
        default:
        {
            // Not supported:
            return false;
        }
        }
#else
        Pa;
        return false;
#endif
    }
}