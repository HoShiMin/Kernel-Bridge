#pragma once

namespace Intel
{
    enum class INTEL_MSR : unsigned int {
        IA32_FEATURE_CONTROL = 0x0000003A,
        IA32_SYSENTER_CS = 0x00000174,
        IA32_SYSENTER_ESP = 0x00000175,
        IA32_SYSENTER_EIP = 0x00000176,
        IA32_EFER = 0xC0000080,
        IA32_STAR = 0xC0000081,
        IA32_LSTAR = 0xC0000082,
        IA32_CSTAR = 0xC0000083,
        IA32_FS_BASE = 0xC0000100,
        IA32_GS_BASE = 0xC0000101,
        IA32_KERNEL_GS_BASE = 0xC0000102,
        IA32_DEBUGCTL = 0x000001D9,

        // MTRR:
        IA32_MTRRCAP = 0xFE,
        IA32_MTRR_DEF_TYPE = 0x2FF,
        IA32_MTRR_PHYSBASE0 = 0x200,
        IA32_MTRR_PHYSMASK0 = 0x201,
        IA32_MTRR_PHYSBASE1 = 0x202,
        IA32_MTRR_PHYSMASK1 = 0x203,
        IA32_MTRR_PHYSBASE2 = 0x204,
        IA32_MTRR_PHYSMASK2 = 0x205,
        IA32_MTRR_PHYSBASE3 = 0x206,
        IA32_MTRR_PHYSMASK3 = 0x207,
        IA32_MTRR_PHYSBASE4 = 0x208,
        IA32_MTRR_PHYSMASK4 = 0x209,
        IA32_MTRR_PHYSBASE5 = 0x20A,
        IA32_MTRR_PHYSMASK5 = 0x20B,
        IA32_MTRR_PHYSBASE6 = 0x20C,
        IA32_MTRR_PHYSMASK6 = 0x20D,
        IA32_MTRR_PHYSBASE7 = 0x20E,
        IA32_MTRR_PHYSMASK7 = 0x20F,
        IA32_MTRR_PHYSBASE8 = 0x210,
        IA32_MTRR_PHYSMASK8 = 0x211,
        IA32_MTRR_PHYSBASE9 = 0x212,
        IA32_MTRR_PHYSMASK9 = 0x213,
        IA32_MTRR_FIX64K_00000 = 0x250,
        IA32_MTRR_FIX16K_80000 = 0x258,
        IA32_MTRR_FIX16K_A0000 = 0x259,
        IA32_MTRR_FIX4K_C0000 = 0x268,
        IA32_MTRR_FIX4K_C8000 = 0x269,
        IA32_MTRR_FIX4K_D0000 = 0x26A,
        IA32_MTRR_FIX4K_D8000 = 0x26B,
        IA32_MTRR_FIX4K_E0000 = 0x26C,
        IA32_MTRR_FIX4K_E8000 = 0x26D,
        IA32_MTRR_FIX4K_F0000 = 0x26E,
        IA32_MTRR_FIX4K_F8000 = 0x26F,

        // VMX-related MSRs:
        IA32_VMX_BASIC = 0x00000480,
        IA32_VMX_PINBASED_CTLS = 0x481,
        IA32_VMX_PROCBASED_CTLS = 0x482,
        IA32_VMX_EXIT_CTLS = 0x483,
        IA32_VMX_ENTRY_CTLS = 0x484,
        IA32_VMX_MISC = 0x485,
        IA32_VMX_CR0_FIXED0 = 0x486,
        IA32_VMX_CR0_FIXED1 = 0x487,
        IA32_VMX_CR4_FIXED0 = 0x488,
        IA32_VMX_CR4_FIXED1 = 0x489,
        IA32_VMX_VMCS_ENUM = 0x48A,
        IA32_VMX_PROCBASED_CTLS2 = 0x48B,
        IA32_VMX_EPT_VPID_CAP = 0x48C,
        IA32_VMX_TRUE_PINBASED_CTLS = 0x48D,
        IA32_VMX_TRUE_PROCBASED_CTLS = 0x48E,
        IA32_VMX_TRUE_EXIT_CTLS = 0x48F,
        IA32_VMX_TRUE_ENTRY_CTLS = 0x490,
        IA32_VMX_VMFUNC = 0x491
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
    static_assert(sizeof(IA32_FEATURE_CONTROL) == sizeof(unsigned long long), "Size of IA32_FEATURE_CONTROL != sizeof(unsigned long long)");

    union IA32_EFER {
        unsigned long long Value;
        struct {
            unsigned long long SCE : 1; // Syscall enable (R/W) - enables syscall/sysret instructions in 64-bit mode 
            unsigned long long Reserved0 : 7;
            unsigned long long LME : 1; // Enables IA-32e mode operation (R/W)
            unsigned long long Reserved1 : 1;
            unsigned long long LMA : 1; // IA32-e mode active (R)
            unsigned long long NXE : 1; // Execute Disable bit Enable (R/W)
            unsigned long long Reserved2 : 52;
        } Bitmap;
    };
    static_assert(sizeof(IA32_EFER) == sizeof(unsigned long long), "Size of IA32_EFER != sizeof(unsigned long long)");

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
        } Bitmap;
    };
    static_assert(sizeof(IA32_VMX_BASIC) == sizeof(unsigned long long), "Size of IA32_VMX_BASIC != sizeof(unsigned long long)");

    union IA32_VMX_EPT_VPID_CAP {
        unsigned long long Value;
        struct {
            unsigned long long ExecuteOnlyTranslationsSupportByEpt : 1;
            unsigned long long Reserved0 : 5;
            unsigned long long PageWalkLength4Support : 1;
            unsigned long long Reserved1 : 1;
            unsigned long long UncacheableEptSupport : 1;
            unsigned long long Reserved2 : 5;
            unsigned long long WriteBackEptSupport : 1;
            unsigned long long Reserved3 : 1;
            unsigned long long EptPde2MbSupport : 1;
            unsigned long long EptPdpte1GbSupport : 1;
            unsigned long long Reserved4 : 2;
            unsigned long long InveptSupport : 1;
            unsigned long long AccessedDirtyFlagsSupported : 1;
            unsigned long long EptViolationsSupport : 1;
            unsigned long long SupervisorShadowStackControlSupported : 1;
            unsigned long long Reserved5 : 1;
            unsigned long long SingleContextInveptTypeSupported : 1;
            unsigned long long AllContextInveptTypeSupported : 1;
            unsigned long long Reserved6 : 5;
            unsigned long long InvvpidSupported : 1;
            unsigned long long Reserved7 : 7;
            unsigned long long IndividualAddressInvvpidTypeSupported : 1;
            unsigned long long SingleContextInvvpidTypeSupported : 1;
            unsigned long long AllContextInvvpidTypeSupported : 1;
            unsigned long long SingleContextRetainingGlobalsInvvpidTypeSupported : 1;
            unsigned long long Reserved8 : 20;
        } Bitmap;
    };
    static_assert(sizeof(IA32_VMX_EPT_VPID_CAP) == sizeof(unsigned long long), "Size of IA32_VMX_EPT_VPID_CAP != sizeof(unsigned long long)");

    union IA32_MTRRCAP {
        unsigned long long Value;
        struct {
            unsigned long long VCNT : 8; // Variable range registers count
            unsigned long long FIX : 1; // Fixed range registers supported
            unsigned long long Reserved0 : 1;
            unsigned long long WC : 1; // Write combining
            unsigned long long SMRR : 1; // System-management range registers
            unsigned long long PRMRR : 1; // Processor-reserved memory range registers (starting with 7th Gen and 8th Gen Intel Core processors)
            unsigned long long Reserved1 : 51;
        } Bitmap;
    };
    static_assert(sizeof(IA32_MTRRCAP) == sizeof(unsigned long long), "Size of IA32_MTRRCAP != sizeof(unsigned long long)");

    enum class MTRR_MEMORY_TYPE {
        Uncacheable = 0x00,
        WriteCombining = 0x01,
        // 0x02 and 0x03 are reserved
        WriteThrough = 0x04,
        WriteProtected = 0x05,
        WriteBack = 0x06,
        // 0x07..0xFF are reserved
    };

    union IA32_MTRR_DEF_TYPE {
        unsigned long long Value;
        struct {
            unsigned long long Type : 3; // Default memory type (the only valid values are 0, 1, 4, 5, and 6), look at the MTRR_MEMORY_TYPE
            unsigned long long Reserved0 : 7;
            unsigned long long FE : 1; // Fixed MTRRs enabled
            unsigned long long E : 1; // MTRRs enabled
            unsigned long long Reserved1 : 52;
        } Bitmap;
    };
    static_assert(sizeof(IA32_MTRR_DEF_TYPE) == sizeof(unsigned long long), "Size of IA32_MTRR_DEF_TYPE != sizeof(unsigned long long)");

    union IA32_MTRR_FIX64K {
        unsigned long long Value;
        struct { // Maps the 512-Kbyte address range (0..7FFFF) divided into eight 64-Kbyte sub-ranges:
            unsigned long long TypeOf64KbRange0 : 8; // 00000..0FFFF
            unsigned long long TypeOf64KbRange1 : 8; // 10000..1FFFF
            unsigned long long TypeOf64KbRange2 : 8; // 20000..2FFFF
            unsigned long long TypeOf64KbRange3 : 8; // 30000..3FFFF
            unsigned long long TypeOf64KbRange4 : 8; // 40000..4FFFF
            unsigned long long TypeOf64KbRange5 : 8; // 50000..5FFFF
            unsigned long long TypeOf64KbRange6 : 8; // 60000..6FFFF
            unsigned long long TypeOf64KbRange7 : 8; // 70000..7FFFF
        } Bitmap, Range00000;
    };
    static_assert(sizeof(IA32_MTRR_FIX64K) == sizeof(unsigned long long), "Size of IA32_MTRR_FIX64K != sizeof(unsigned long long)");

    union IA32_MTRR_FIX16K {
        unsigned long long Value;
        struct {
            unsigned long long TypeOf16KbRange0 : 8; // 80000..83FFF  |  A0000..A3FFF
            unsigned long long TypeOf16KbRange1 : 8; // 84000..87FFF  |  A4000..A7FFF
            unsigned long long TypeOf16KbRange2 : 8; // 88000..8BFFF  |  A8000..ABFFF
            unsigned long long TypeOf16KbRange3 : 8; // 8C000..8FFFF  |  AC000..AFFFF
            unsigned long long TypeOf16KbRange4 : 8; // 90000..93FFF  |  B0000..B3FFF
            unsigned long long TypeOf16KbRange5 : 8; // 94000..97FFF  |  B4000..B7FFF
            unsigned long long TypeOf16KbRange6 : 8; // 98000..9BFFF  |  B8000..BBFFF
            unsigned long long TypeOf16KbRange7 : 8; // 9C000..9FFFF  |  BC000..BFFFF
        } Bitmap, Range80000, RangeA0000;
    };
    static_assert(sizeof(IA32_MTRR_FIX16K) == sizeof(unsigned long long), "Size of IA32_MTRR_FIX16K != sizeof(unsigned long long)");

    union IA32_MTRR_FIX4K {
        unsigned long long Value;
        struct {
            unsigned long long TypeOf4KbRange0 : 8; // [C..F]0000..[C..F]0FFF  |  [C..F]8000..[C..F]8FFF
            unsigned long long TypeOf4KbRange1 : 8; // [C..F]1000..[C..F]1FFF  |  [C..F]9000..[C..F]9FFF
            unsigned long long TypeOf4KbRange2 : 8; // [C..F]2000..[C..F]2FFF  |  [C..F]A000..[C..F]AFFF
            unsigned long long TypeOf4KbRange3 : 8; // [C..F]3000..[C..F]3FFF  |  [C..F]B000..[C..F]BFFF
            unsigned long long TypeOf4KbRange4 : 8; // [C..F]4000..[C..F]4FFF  |  [C..F]C000..[C..F]CFFF
            unsigned long long TypeOf4KbRange5 : 8; // [C..F]5000..[C..F]5FFF  |  [C..F]D000..[C..F]DFFF
            unsigned long long TypeOf4KbRange6 : 8; // [C..F]6000..[C..F]6FFF  |  [C..F]E000..[C..F]EFFF
            unsigned long long TypeOf4KbRange7 : 8; // [C..F]7000..[C..F]7FFF  |  [C..F]F000..[C..F]FFFF
        } Bitmap,
            RangeC0000, RangeC8000,
            RangeD0000, RangeD8000,
            RangeE0000, RangeE8000,
            RangeF0000, RangeF8000;
    };
    static_assert(sizeof(IA32_MTRR_FIX4K) == sizeof(unsigned long long), "Size of IA32_MTRR_FIX4K != sizeof(unsigned long long)");

    union MTRR_FIXED_GENERIC {
        unsigned long long Value;
        struct {
            unsigned long long Range0 : 8;
            unsigned long long Range1 : 8;
            unsigned long long Range2 : 8;
            unsigned long long Range3 : 8;
            unsigned long long Range4 : 8;
            unsigned long long Range5 : 8;
            unsigned long long Range6 : 8;
            unsigned long long Range7 : 8;
        } Generic;
        IA32_MTRR_FIX64K Fix64k;
        IA32_MTRR_FIX16K Fix16k;
        IA32_MTRR_FIX4K  Fix4k;
    };
    static_assert(sizeof(MTRR_FIXED_GENERIC) == sizeof(unsigned long long), "Size of MTRR_FIXED_GENERIC != sizeof(unsigned long long)");

    union IA32_MTRR_PHYSBASE {
        unsigned long long Value;
        struct {
            unsigned long long Type : 8; // Memory type for range
            unsigned long long Reserved : 4;
            unsigned long long PhysBasePfn : 52; // 36-bit or MAXPHYSADDR length (depending on CPUID(0x80000008)), all other bits are reserved
        } Bitmap;
    };
    static_assert(sizeof(IA32_MTRR_PHYSBASE) == sizeof(unsigned long long), "Size of IA32_MTRR_PHYSBASE != sizeof(unsigned long long)");

    union IA32_MTRR_PHYSMASK {
        unsigned long long Value;
        struct {
            unsigned long long Reserved : 11;
            unsigned long long V : 1; // Valid
            unsigned long long PhysMaskPfn : 52; // 36-bit or MAXPHYSADDR length (depending on CPUID(0x80000008)), all other bits are reserved
        } Bitmap;
    };
    static_assert(sizeof(IA32_MTRR_PHYSMASK) == sizeof(unsigned long long), "Size of IA32_MTRR_PHYSMASK != sizeof(unsigned long long)");
}

namespace AMD
{
    enum class AMD_MSR : unsigned int {
        MSR_PAT = 0x00000277, // Extension of the page tables in SVM (nested paging)
        MSR_EFER = 0xC0000080, // Etended Feature Enable Register
        MSR_STAR = 0xC0000081, // Legacy mode: address of a SYSCALL instruction
        MSR_LSTAR = 0xC0000081, // Long mode: address of a SYSCALL instruction
        MSR_CSTAR = 0xC0000081, // Compatibility mode: address of a SYSCALL instruction
        MSR_VM_CR = 0xC0010114, // Controls global aspects of SVM
        MSR_VM_HSAVE_PA = 0xC0010117, // Physical address of a 4KB block of memory where VMRUN saves host state, and from which #VMEXIT reloads host state
    };

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
    static_assert(sizeof(EFER) == sizeof(unsigned long long), "Size of EFER != sizeof(unsigned long long)");

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
    static_assert(sizeof(VM_CR) == sizeof(unsigned long long), "Size of VM_CR != sizeof(unsigned long long)");
}