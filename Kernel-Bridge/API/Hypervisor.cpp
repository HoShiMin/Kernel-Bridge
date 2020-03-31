/*
    Inspired by SimpleSvm project by Satoshi Tanda:
    https://github.com/tandasat/SimpleSvm
*/

#ifdef _AMD64_

//#include <intrin.h>

#include <ntifs.h>
#include "MemoryUtils.h"

#include "Hypervisor.h"
#include "PTE.h"
#include "Registers.h"
#include "CPUID.h"
#include "Segmentation.h"
#include "SVM.h"
#include "VMX.h"

extern "C" void _enable();
extern "C" void _disable();

extern "C" void _sgdt(__out void* Gdtr);
extern "C" void __sidt(__out void* Idtr);

extern "C" unsigned long long __readmsr(unsigned long Index);
extern "C" void __writemsr(unsigned long Index, unsigned long long Value);

extern "C" void __writeeflags(unsigned long long RFlags);

extern "C" void __cpuid(__out CPUID_REGS* Info, int FunctionIdEax);

extern "C" unsigned long long __readcr0();
extern "C" unsigned long long __readcr2();
extern "C" unsigned long long __readcr3();
extern "C" unsigned long long __readcr4();

extern "C" void __writecr4(unsigned long long Cr4);

extern "C" void __svm_clgi();
extern "C" void __svm_invlpga(void* Va, int ASID);
extern "C" void __svm_skinit(int SLB);
extern "C" void __svm_stgi();
extern "C" void __svm_vmload(size_t VmcbPa);
extern "C" void __svm_vmrun(size_t VmcbPa);
extern "C" void __svm_vmsave(size_t VmcbPa);

extern "C" NTSYSAPI VOID NTAPI RtlCaptureContext(OUT PCONTEXT Context);

// Magic value, defined by hypervisor, triggers #VMEXIT and VMM shutdown:
constexpr unsigned int CPUID_VMM_SHUTDOWN = 0x1EE7C0DE;

// Exit action for the SvmVmexitHandler/VmxVmexitHandler:
enum class VMM_STATUS : bool {
    VMM_SHUTDOWN = false, // Devirtualize processor
    VMM_CONTINUE = true   // Continue execution in the virtualized environment
};

struct GUEST_CONTEXT {
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

namespace Supplementation {
    static PVOID AllocPhys(SIZE_T Size, MEMORY_CACHING_TYPE CachingType = MmCached) {
        PVOID Memory = PhysicalMemory::AllocPhysicalMemorySpecifyCache(
            0,
            reinterpret_cast<PVOID64>(MAXDWORD32),
            0,
            Size,
            CachingType
        );
        if (Memory) RtlSecureZeroMemory(Memory, Size);
        return Memory;
    }

    static VOID FreePhys(PVOID Memory) {
        PhysicalMemory::FreePhysicalMemory(Memory);
    }

    static bool ExecuteInSystemContext(bool(*Callback)(PVOID Arg), PVOID Arg = NULL) {
        HANDLE hThread = NULL;
        
        struct PARAMS {
            bool(*Callback)(PVOID Arg);
            PVOID Arg;
            bool Result;
        } Params = {};
        Params.Callback = Callback;
        Params.Arg = Arg;

        OBJECT_ATTRIBUTES ObjectAttributes;
        InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        NTSTATUS Status = PsCreateSystemThread(
            &hThread, 
            GENERIC_ALL, 
            &ObjectAttributes, 
            NULL, 
            NULL, 
            [](PVOID Arg) {
                __try {
                    PARAMS* Params = reinterpret_cast<PARAMS*>(Arg);
                    Params->Result = Params->Callback(Params->Arg);
                    PsTerminateSystemThread(STATUS_SUCCESS);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
                }
            },
            &Params
        );

        if (NT_SUCCESS(Status)) {
            ZwWaitForSingleObject(hThread, FALSE, NULL);
            ZwClose(hThread);
            return Params.Result;
        }

        return false;
    }

    static bool ExecuteOnEachProcessor(bool(*Callback)(PVOID Arg, ULONG ProcessorNumber), PVOID Arg = NULL) {
        ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        for (ULONG i = 0; i < ProcessorsCount; i++) {
            PROCESSOR_NUMBER ProcessorNumber = {};
            KeGetProcessorNumberFromIndex(i, &ProcessorNumber);

            GROUP_AFFINITY Affinity = {}, PreviousAffinity = {};
            Affinity.Group = ProcessorNumber.Group;
            Affinity.Mask = 1LL << ProcessorNumber.Number;
            KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);

            bool Status = Callback(Arg, i);

            KeRevertToUserGroupAffinityThread(&PreviousAffinity);

            if (!Status) return false;
        }
        return true;
    }
}

namespace SVM {
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
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.P = TRUE; // Present
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.RW = TRUE; // Writeable
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.US = TRUE; // User
            Npt->Pdpe[i].x64.NonPageSize.Page2Mb.PD = reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pde[i][0])) >> PAGE_SHIFT;

            for (int j = 0; j < _ARRAYSIZE(Npt->Pde[i]); j++) {
                Npt->Pde[i][j].x64.Page2Mb.P = TRUE; // Present
                Npt->Pde[i][j].x64.Page2Mb.RW = TRUE; // Writeable
                Npt->Pde[i][j].x64.Page2Mb.US = TRUE; // User
                Npt->Pde[i][j].x64.Page2Mb.PS = TRUE; // Large page
                Npt->Pde[i][j].x64.Page2Mb.PhysicalPageBase = i * _ARRAYSIZE(Npt->Pde[i]) + j;
            }
        }

        return Npt;
    }

    static void FreeNestedPagingTables(IN NESTED_PAGING_TABLES* Npt) {
        FreePhys(Npt);
    }

    // Defined in the VMM.asm:
    extern "C" void SvmVmmRun(void* InitialVmmStackPointer);

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

    union VM_CR {
        unsigned long long Value;
        struct {
            unsigned long long DPD : 1;
            unsigned long long R_INIT : 1;
            unsigned long long DIS_A20M : 1;
            unsigned long long LOCK : 1;
            unsigned long long SVMDIS : 1; // When set, EFER.SVME must be zero
            unsigned long long Reserved : 59;
        } Bitmap;
    };

    enum AMD_MSR : unsigned int {
        MSR_PAT   = 0x00000277, // Extension of the page tables in SVM (nested paging)
        MSR_EFER  = 0xC0000080, // Etended Feature Enable Register
        MSR_STAR  = 0xC0000081, // Legacy mode: address of a SYSCALL instruction
        MSR_LSTAR = 0xC0000081, // Long mode: address of a SYSCALL instruction
        MSR_CSTAR = 0xC0000081, // Compatibility mode: address of a SYSCALL instruction
        MSR_VM_CR = 0xC0010114, // Controls global aspects of SVM
        MSR_VM_HSAVE_PA = 0xC0010117, // Physical address of a 4KB block of memory where VMRUN saves host state, and from which #VMEXIT reloads host state
    };

    // Shared between all processors:
    struct SHARED_VM_DATA {
        NESTED_PAGING_TABLES* Npt;
        MSRPM* Msrpm;
        bool Virtualized;
    };

    // Unique for each processor:
    struct PRIVATE_VM_DATA {
        DECLSPEC_ALIGN(PAGE_SIZE) VMCB Guest;
        DECLSPEC_ALIGN(PAGE_SIZE) VMCB Host;
        DECLSPEC_ALIGN(PAGE_SIZE) unsigned char HostStateArea[PAGE_SIZE];
        union {
            struct INITIAL_VMM_STACK_LAYOUT {
                PVOID GuestVmcbPa;
                PVOID HostVmcbPa;
                PRIVATE_VM_DATA* Private;
            };
            DECLSPEC_ALIGN(PAGE_SIZE) unsigned char VmmStack[KERNEL_STACK_SIZE];
            struct {
                unsigned char FreeSpace[KERNEL_STACK_SIZE - sizeof(INITIAL_VMM_STACK_LAYOUT)];
                INITIAL_VMM_STACK_LAYOUT InitialStack;
            } Layout;
        } VmmStack;
    };

    static SHARED_VM_DATA SharedVmData = {};

    static MSRPM* BuildMsrpm() {
        return reinterpret_cast<MSRPM*>(AllocPhys(sizeof(MSRPM)));
    }

    void FreeMsrpm(MSRPM* Msrpm) {
        FreePhys(Msrpm);
    }

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

    void InjectEvent(VMCB* Guest, unsigned char Vector, unsigned char Type, unsigned int Code) {
        EVENTINJ Event = {};
        Event.Bitmap.Vector = Vector;
        Event.Bitmap.Type = Type;
        Event.Bitmap.ErrorCodeValid = TRUE;
        Event.Bitmap.Valid = TRUE;
        Event.Bitmap.ErrorCode = Code;
        Guest->ControlArea.EventInjection = Event.Value;
    }

    void InjectEvent(VMCB* Guest, unsigned char Vector, unsigned char Type) {
        EVENTINJ Event = {};
        Event.Bitmap.Vector = Vector;
        Event.Bitmap.Type = Type;
        Event.Bitmap.Valid = TRUE;
        Guest->ControlArea.EventInjection = Event.Value;
    }

    extern "C" VMM_STATUS SvmVmexitHandler(PRIVATE_VM_DATA* Private, GUEST_CONTEXT* Context) {
        // Load the host state:
        __svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.HostVmcbPa));
        
        // Restore the guest's RAX that was overwritten by host's RAX on #VMEXIT:
        Context->Rax = Private->Guest.StateSaveArea.Rax;

        VMM_STATUS Status = VMM_STATUS::VMM_CONTINUE;
        switch (Private->Guest.ControlArea.ExitCode) {
        case VMEXIT_CPUID: {
            CPUID_REGS Regs = {};
            int Function = static_cast<int>(Context->Rax);
            int SubLeaf = static_cast<int>(Context->Rcx);
            __cpuidex(Regs.Raw, Function, SubLeaf);

            switch (Function) {
            case CPUID_VMM_SHUTDOWN:
                // Shutdown was triggered:
                Status = VMM_STATUS::VMM_SHUTDOWN;
                break;
            case CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID: {
                // Vendor = 'Hyper-Bridge' as RBX + RDX + RCX:
                Context->Rax = Regs.Regs.Eax;
                Context->Rbx = 'epyH';
                Context->Rcx = 'egdi';
                Context->Rdx = 'rB-r';
                break;
            }
            default: {
                Context->Rax = Regs.Regs.Eax;
                Context->Rbx = Regs.Regs.Ebx;
                Context->Rcx = Regs.Regs.Ecx;
                Context->Rdx = Regs.Regs.Edx;
                break;
            }
            }
            break;
        }
        case VMEXIT_MSR: {
            if ((Context->Rcx & MAXUINT32) == MSR_EFER && Private->Guest.ControlArea.ExitInfo1) {
                EFER Efer = {};
                Efer.Value = ((Context->Rdx & MAXUINT32) << 32) | (Context->Rax & MAXUINT32);
                if (!Efer.Bitmap.SecureVirtualMachineEnable) {
                    InjectEvent(&Private->Guest, 13, 3, 0); // #GP (Vector = 13, Type = Exception)
                    break;
                }
                Private->Guest.StateSaveArea.Efer = Efer.Value;
            }
            break;
        }
        case VMEXIT_VMRUN: {
            InjectEvent(&Private->Guest, 13, 3, 0); // #GP (Vector = 13, Type = Exception)
            break;
        }
        }

        if (Status == VMM_STATUS::VMM_SHUTDOWN) {
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
            Efer.Value = __readmsr(MSR_EFER);
            Efer.Bitmap.SecureVirtualMachineEnable = FALSE;
            __writemsr(MSR_EFER, Efer.Value);

            // Restoring the EFlags:
            __writeeflags(Private->Guest.StateSaveArea.Rflags);
        }

        Private->Guest.StateSaveArea.Rax = Context->Rax;
        
        // Go to the next instruction:
        Private->Guest.StateSaveArea.Rip = Private->Guest.ControlArea.NextRip;

        return Status;
    }

    static bool VirtualizeProcessor(const SHARED_VM_DATA* Shared, OUT PRIVATE_VM_DATA* Private);
    static bool VirtualizeAllProcessors(OUT SHARED_VM_DATA* Shared);
    static bool DevirtualizeProcessor();
    static bool DevirtualizeAllProcessors(SHARED_VM_DATA* Shared);

    // Virtualize the current processor (core):
    static bool VirtualizeProcessor(const SHARED_VM_DATA* Shared, OUT PRIVATE_VM_DATA* Private) {
        using namespace PhysicalMemory;

        static volatile bool IsVirtualized = false;
        IsVirtualized = false;

        CONTEXT Context = {};
        Context.ContextFlags = CONTEXT_ALL;
        RtlCaptureContext(&Context);

        if (IsVirtualized) return true;

        // Enable the SVM by setting up the EFER.SVME bit:
        EFER Efer = {};
        Efer.Value = __readmsr(MSR_EFER);
        Efer.Bitmap.SecureVirtualMachineEnable = TRUE;
        __writemsr(MSR_EFER, Efer.Value);

        // Interceptions:
        Private->Guest.ControlArea.InterceptCpuid = TRUE;
        Private->Guest.ControlArea.InterceptVmrun = TRUE;
        Private->Guest.ControlArea.InterceptMsr = TRUE;
        Private->Guest.ControlArea.MsrpmBasePa = reinterpret_cast<UINT64>(GetPhysicalAddress(Shared->Msrpm));

        // Guest Address Space ID:
        Private->Guest.ControlArea.GuestAsid = 1;

        // Nested paging:
        Private->Guest.ControlArea.NpEnable = TRUE;
        Private->Guest.ControlArea.NestedPageTableCr3 = reinterpret_cast<UINT64>(GetPhysicalAddress(&Shared->Npt->Pml4e));

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
        Private->Guest.StateSaveArea.GuestPat = __readmsr(MSR_PAT);

        PVOID GuestVmcbPa = GetPhysicalAddress(&Private->Guest);
        PVOID HostVmcbPa = GetPhysicalAddress(&Private->Host);

        // Store state to the guest VMCB:
        __svm_vmsave(reinterpret_cast<size_t>(GuestVmcbPa));

        // Store the address of the HostStateArea:
        __writemsr(MSR_VM_HSAVE_PA, reinterpret_cast<UINT64>(GetPhysicalAddress(Private->HostStateArea)));

        // Store state to the host VMCB to load it after the #VMEXIT:
        __svm_vmsave(reinterpret_cast<size_t>(HostVmcbPa));

        // Ok, let's go:
        IsVirtualized = true;
        Private->VmmStack.Layout.InitialStack.GuestVmcbPa = GuestVmcbPa;
        Private->VmmStack.Layout.InitialStack.HostVmcbPa = HostVmcbPa;
        Private->VmmStack.Layout.InitialStack.Private = Private;
        SvmVmmRun(&Private->VmmStack.Layout.InitialStack);
        
        // If SvmVmmRun returns to here, something goes wrong:
        return false;
    }

    // Virtualize all processors:
    static bool VirtualizeAllProcessors(OUT SHARED_VM_DATA* Shared) {
        using namespace Supplementation;

        if (Shared->Virtualized) return false; // Already virtualized!

        Shared->Npt = BuildNestedPagingTables();
        if (!Shared->Npt) return false;

        Shared->Msrpm = BuildMsrpm();
        if (!Shared->Msrpm) {
            FreeNestedPagingTables(Shared->Npt);
            return false;
        }

        // Virtualizing each processor:
        bool Status = ExecuteInSystemContext([](PVOID Shared) -> bool {
            return ExecuteOnEachProcessor([](PVOID Shared, ULONG ProcessorNumber) -> bool {
                UNREFERENCED_PARAMETER(ProcessorNumber);
                PRIVATE_VM_DATA* Private = reinterpret_cast<PRIVATE_VM_DATA*>(AllocPhys(sizeof(*Private)));
                bool Status = VirtualizeProcessor(reinterpret_cast<SHARED_VM_DATA*>(Shared), Private);
                if (!Status) FreePhys(Private);
                return Status;
            }, Shared);
        }, Shared);

        if (!Status)
            DevirtualizeAllProcessors(Shared);

        Shared->Virtualized = Status;
        return Status;
    }

    static bool DevirtualizeProcessor() {
        // Trigger the #VMEXIT with the predefined arguments:
        CPUID_REGS Regs = {};
        __cpuid(&Regs, CPUID_VMM_SHUTDOWN);
        if (Regs.Regs.Ecx != CPUID_VMM_SHUTDOWN) return false; // Processor not virtualized!

        // Processor is devirtualized now:
        //  Info.Eax -> PRIVATE_VM_DATA* Private LOW
        //  Info.Ebx -> Vmexit RIP
        //  Info.Ecx -> VMEXIT_SIGNATURE
        //  Info.Edx -> PRIVATE_VM_DATA* Private HIGH

        auto Private = reinterpret_cast<PRIVATE_VM_DATA*>(
            (static_cast<UINT64>(Regs.Regs.Edx) << 32) |
            (static_cast<UINT64>(Regs.Regs.Eax))
        );

        FreePhys(Private);

        return true;
    }

    static bool DevirtualizeAllProcessors(SHARED_VM_DATA* Shared) {
        if (!Shared->Virtualized) return false; // Not virtualized!

        ExecuteInSystemContext([](PVOID Arg) -> bool {
            UNREFERENCED_PARAMETER(Arg);
            return ExecuteOnEachProcessor([](PVOID Argument, ULONG ProcessorNumber) -> bool {
                UNREFERENCED_PARAMETER(Argument);
                UNREFERENCED_PARAMETER(ProcessorNumber);
                return DevirtualizeProcessor();
            });
        });

        FreeNestedPagingTables(Shared->Npt);
        FreeMsrpm(Shared->Msrpm);

        *Shared = {};
        return true;
    }

    static bool IsSvmSupported() {
        CPUID_REGS Regs = {};
        
        // Check the 'AuthenticAMD' vendor name:
        __cpuid(&Regs, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (Regs.Regs.Ebx != 'htuA' || Regs.Regs.Edx != 'itne' || Regs.Regs.Ecx != 'DMAc') return false;

        // Check the AMD SVM (AMD-V) support:
        constexpr unsigned int CPUID_FN80000001_ECX_SVM = 1 << 2;
        __cpuid(&Regs, CPUID::Generic::CPUID_EXTENDED_FEATURE_INFORMATION);
        if ((Regs.Regs.Ecx & CPUID_FN80000001_ECX_SVM) == 0) return false;

        // Check the Nested Paging support (AMD-RVI):
        constexpr unsigned int CPUID_FN8000000A_EDX_NESTED_PAGING = 1 << 0;
        __cpuid(&Regs, CPUID::AMD::CPUID_SVM_FEATURES);
        if ((Regs.Regs.Edx & CPUID_FN8000000A_EDX_NESTED_PAGING) == 0) return false;

        // Check that the EFER.SVME is writeable (we can enable the SVM):
        VM_CR VmCr = {};
        VmCr.Value = __readmsr(MSR_VM_CR);
        if (VmCr.Bitmap.SVMDIS) return false;

        return true;
    }

    static bool IsVirtualized(const SHARED_VM_DATA* Shared) {
        return Shared->Virtualized;
    }
}

//#define VMX_SUPPORT

#ifdef VMX_SUPPORT
namespace VMX {
    using namespace Supplementation;

    enum class INTEL_MSR {
        IA32_FEATURE_CONTROL = 0x0000003A,
        IA32_VMX_BASIC = 0x00000480,
    };

    union IA32_FEATURE_CONTROL {
        unsigned long long Value;
        struct {
            unsigned long long LockBit : 1;
            unsigned long long EnableVmxInsideSmx : 1;
            unsigned long long EnableVmxOutsideSmx : 1;
            unsigned long long Reserved0 : 5;
            unsigned long long SenterLocalFunctionEnables : 7;
            unsigned long long SenterGlobalEnable : 1;
            unsigned long long Reserved1 : 1;
            unsigned long long SgxLaunchControlEnable : 1;
            unsigned long long SgxGlobalEnable : 1;
            unsigned long long Reserved2 : 1;
            unsigned long long LmceOn : 1;
            unsigned long long Reserved3 : 43;
        } Bitmap;
    };

    union IA32_VMX_BASIC {
        unsigned long long Value;
        struct {
            unsigned long long VmcsRevision : 31;
            unsigned long long Reserved0 : 1;
            unsigned long long VmxonVmcsRegionsSize : 13;
            unsigned long long Reserved1 : 3;
            unsigned long long PhysicalAddressesWidth : 1; // 0 = Processor's physical-address width (always 0 on Intel64), 1 = 32-bit
            unsigned long long DualMonitorTreatmentOfSmiAndSmm : 1;
            unsigned long long MemoryType : 4; // 0 = Uncacheable, 6 = Write-back, 1..5 and 7..15 aren't used
            unsigned long long InsOutsReporting : 1;
            unsigned long long AnyVmxControlsThatDefaultToOneMayBeZeroed : 1;
            unsigned long long CanUseVMEntryToDeliverHardwareException : 1;
            unsigned long long Reserved2 : 7;
        };
    };

    // Defined in the VMM.asm:
    extern "C" void VmxVmmRun(void* InitialVmmStackLayout);

    // Shared between all processors:
    struct SHARED_VM_DATA {
        
        bool Virtualized;
    };

    static SHARED_VM_DATA SharedVmData = {};

    // Unique for each processor:
    struct PRIVATE_VM_DATA {
        DECLSPEC_ALIGN(PAGE_SIZE) VMCS Vmxon; // VMXON structure is the same as VMCS with the same size
        DECLSPEC_ALIGN(PAGE_SIZE) VMCS Vmcs;
        
        union {
            DECLSPEC_ALIGN(PAGE_SIZE) unsigned char VmmStack[KERNEL_STACK_SIZE];
            struct {
                struct INITIAL_VMM_STACK_LAYOUT {
                    PVOID VmxonPa;
                    PVOID VmcsPa;
                    PRIVATE_VM_DATA* Private;
                };
                unsigned char FreeSpace[KERNEL_STACK_SIZE - sizeof(INITIAL_VMM_STACK_LAYOUT)];
                INITIAL_VMM_STACK_LAYOUT InitialStack;
            } Layout;
        } VmmStack;
    };

    extern "C" VMM_STATUS VmxVmexitHandler(PRIVATE_VM_DATA* Private, GUEST_CONTEXT* Context) {

    }

    static bool VirtualizeProcessor(const SHARED_VM_DATA* Shared) {
        using namespace PhysicalMemory;

        static volatile bool IsVirtualized = false;
        IsVirtualized = false;

        CONTEXT Context = {};
        Context.ContextFlags = CONTEXT_ALL;
        RtlCaptureContext(&Context);

        if (IsVirtualized) return true;

        // Enable the VMX instructions set:
        CR4 Cr4 = {};
        Cr4.Value = __readcr4();
        Cr4.x64.Bitmap.VMXE = TRUE;
        __writecr4(Cr4.Value);

        IA32_VMX_BASIC VmxBasicInfo = {};
        VmxBasicInfo.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_VMX_BASIC));
        unsigned int VmxonVmcsSize = VmxBasicInfo.VmxonVmcsRegionsSize;

        // Both 'cacheable' and 'write-back' are MmCached:
        MEMORY_CACHING_TYPE CachingType = VmxBasicInfo.MemoryType ? MmCached : MmNonCached;

        PRIVATE_VM_DATA* Private = reinterpret_cast<PRIVATE_VM_DATA*>(AllocPhys(sizeof(PRIVATE_VM_DATA), CachingType));

        Private->Vmxon.RevisionId.Bitmap.VmcsRevisionId = VmxBasicInfo.VmcsRevision;
        Private->Vmcs.RevisionId.Bitmap.VmcsRevisionId = VmxBasicInfo.VmcsRevision;

        Private->VmmStack.Layout.InitialStack.VmxonPa = GetPhysicalAddress(&Private->Vmxon);
        Private->VmmStack.Layout.InitialStack.VmcsPa = GetPhysicalAddress(&Private->Vmcs);
        Private->VmmStack.Layout.InitialStack.Private = Private;

        // Entering the VMX root-mode:
        __vmx_on(reinterpret_cast<unsigned long long*>(&Private->VmmStack.Layout.InitialStack.VmxonPa));

        // Loading the VMCS as current for the processor:
        __vmx_vmptrld(reinterpret_cast<unsigned long long*>(&Private->VmmStack.Layout.InitialStack.VmcsPa));

        
        __vmx_vmwrite(VMX::VMCS_FIELD_VMCS_LINK_POINTER_FULL, 0xFFFFFFFFFFFFFFFF);

        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CR0, __readcr0());
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CR3, __readcr3());
        __vmx_vmwrite(VMX::VMCS_FIELD_GUEST_CR4, __readcr4());
        //__vmx_vmwrite(VMX::VMCS_FIELD_GUEST_ES_BASE, __reades);


        return true;
    }

    static bool DevirtualizeProcessor() {

    }

    static bool VirtualizeAllProcessors(OUT SHARED_VM_DATA* Shared) {
        // Virtualizing each processor:
        bool Status = ExecuteInSystemContext([](PVOID Shared) -> bool {
            return ExecuteOnEachProcessor([](PVOID Shared, ULONG ProcessorNumber) -> bool {
                UNREFERENCED_PARAMETER(ProcessorNumber);
                return VirtualizeProcessor(reinterpret_cast<SHARED_VM_DATA*>(Shared));
            }, Shared);
        }, Shared);
        return Status;
    }

    static bool IsVmxSupported() {
        CPUID_REGS Regs = {};

        // Check the 'GenuineIntel' vendor name:
        __cpuid(&Regs, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (Regs.Regs.Ebx != 'uneG' || Regs.Regs.Edx != 'Ieni' || Regs.Regs.Ecx != 'letn') return false;

        // Support by processor:
        __cpuid(&Regs, CPUID::Intel::CPUID_FEATURE_INFORMATION);
        if (!reinterpret_cast<CPUID::FEATURE_INFORMATION*>(&Regs)->Intel.VMX) return false;

        // Check the VMX is locked in BIOS:
        IA32_FEATURE_CONTROL MsrFeatureControl = {};
        MsrFeatureControl.Value = __readmsr(static_cast<unsigned long>(INTEL_MSR::IA32_FEATURE_CONTROL));

        if (MsrFeatureControl.Bitmap.LockBit) return false;

        return true;
    }
}
#endif

#endif

namespace Hypervisor {

#ifdef _AMD64_
    enum class CPU_VENDOR {
        cpuIntel,
        cpuAmd,
        cpuUnknown
    };

    CPU_VENDOR GetCpuVendor() {
        CPUID_REGS Regs;
        __cpuid(&Regs, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (Regs.Regs.Ebx != 'uneG' || Regs.Regs.Edx != 'Ieni' || Regs.Regs.Ecx != 'letn') return CPU_VENDOR::cpuIntel;
        if (Regs.Regs.Ebx != 'htuA' || Regs.Regs.Edx != 'itne' || Regs.Regs.Ecx != 'DMAc') return CPU_VENDOR::cpuAmd;
        return CPU_VENDOR::cpuUnknown;
    }
#endif


    bool IsVirtualized() {
#ifdef _AMD64_
        return SVM::IsVirtualized(&SVM::SharedVmData);
#else
        return false;
#endif
    }

    bool Virtualize() {
#ifdef _AMD64_
        CPU_VENDOR CpuVendor = GetCpuVendor();
        if (CpuVendor == CPU_VENDOR::cpuUnknown) return false;

        switch (CpuVendor) {
#ifdef VMX_SUPPORT
        case CPU_VENDOR::cpuIntel: {
            if (!VMX::IsVmxSupported()) return false;
            return VMX::VirtualizeAllProcessors(&VMX::SharedVmData);
            break;
        }
#endif
        case CPU_VENDOR::cpuAmd: {
            if (!SVM::IsSvmSupported()) return false;
            return SVM::VirtualizeAllProcessors(&SVM::SharedVmData);
        }
        }
#endif
        return false;
    }

    bool Devirtualize() {
#ifdef _AMD64_
        if (SVM::IsVirtualized(&SVM::SharedVmData)) {
            return SVM::DevirtualizeAllProcessors(&SVM::SharedVmData);
        }
#endif
        return false;
    }
}