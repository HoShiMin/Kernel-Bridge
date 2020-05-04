#pragma once

union CPUID_REGS {
    int Raw[4];
    struct {
        unsigned int Eax;
        unsigned int Ebx;
        unsigned int Ecx;
        unsigned int Edx;
    } Regs;
};
static_assert(sizeof(CPUID_REGS) == sizeof(int) * 4, "Size of CPUID_REGS != sizeof(int[4])");

namespace CPUID {
    namespace Generic {
        enum CPUID_FUNCTIONS { // EAX values:
            // Standard CPUID functions:
            CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID = 0x00000000,
            CPUID_FEATURE_INFORMATION = 0x00000001,
            CPUID_MONITOR_MWAIT_PARAMETERS = 0x00000005,
            CPUID_THERMAL_POWER_MANAGEMENT = 0x00000006,
            CPUID_STRUCTURED_EXTENDED_FEATURE_ENUMERATION = 0x00000007,

            // Extended CPUID functions:
            CPUID_MAXIMUM_EXTENDED_FUNCTION_NUMBER_AND_VENDOR_ID = 0x80000000,
            CPUID_EXTENDED_FEATURE_INFORMATION = 0x80000001,
            CPUID_PROCESSOR_BRAND_STRING_0 = 0x80000002,
            CPUID_PROCESSOR_BRAND_STRING_1 = 0x80000003,
            CPUID_PROCESSOR_BRAND_STRING_2 = 0x80000004,
        };
    }

    namespace Intel {
        enum CPUID_FUNCTIONS { // EAX values:
            // Standard CPUID functions:
            CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID = 0x00000000,
            CPUID_FEATURE_INFORMATION = 0x00000001,
            CPUID_CACHE_DESCRIPTORS = 0x00000002,
            CPUID_PROCESSOR_SERIAL_NUMBER = 0x00000003,
            CPUID_DETERMINISTIC_CACHE_PARAMETERS = 0x00000004,
            CPUID_MONITOR_MWAIT_PARAMETERS = 0x00000005,
            CPUID_THERMAL_POWER_MANAGEMENT = 0x00000006,
            CPUID_STRUCTURED_EXTENDED_FEATURE_ENUMERATION = 0x00000007,
            // 0x00000008 is reserved
            CPUID_DIRECT_CACHE_ACCESS_PARAMETERS = 0x00000009,
            CPUID_ARCHITECTUAL_PERFORMANCE_MONITOR_FEATURES = 0x0000000A,
            CPUID_X2APIC_FEATURES = 0x0000000B,
            // 0x0000000C is reserved
            CPUID_XSAVE_FEATURES = 0x0000000D,

            // Extended CPUID functions:
            CPUID_LARGEST_EXTENDED_FUNCTION = 0x80000000,
            CPUID_EXTENDED_FEATURE_INFORMATION = 0x80000001,
            CPUID_PROCESSOR_BRAND_STRING_0 = 0x80000002,
            CPUID_PROCESSOR_BRAND_STRING_1 = 0x80000003,
            CPUID_PROCESSOR_BRAND_STRING_2 = 0x80000004,
            // 0x80000005 is reserved
            CPUID_EXTENDED_L2_CACHE_FEATURES = 0x80000006,
            CPUID_ADVANCED_POWER_MANAGEMENT = 0x80000007,
            CPUID_VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES = 0x80000008
        };
    }

    namespace AMD {
        enum CPUID_FUNCTIONS { // EAX values:
            // Standard CPUID functions:
            CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID = 0x00000000,
            CPUID_FEATURE_INFORMATION = 0x00000001,
            // 0x00000002..0x00000004 are reserved
            CPUID_MONITOR_MWAIT_PARAMETERS = 0x00000005,
            CPUID_THERMAL_POWER_MANAGEMENT = 0x00000006,
            CPUID_STRUCTURED_EXTENDED_FEATURE_ENUMERATION = 0x00000007,
            // 0x00000008..0x0000000C are reserved
            CPUID_PROCESSOR_EXTENDED_STATE_ENUMERATION = 0x0000000C,
            // 0x40000000..0x400000FF are reserved for hypervisor use

            // Extended CPUID functions:
            CPUID_MAXIMUM_EXTENDED_FUNCTION_NUMBER_AND_VENDOR_ID = 0x80000000,
            CPUID_EXTENDED_FEATURE_INFORMATION = 0x80000001,
            CPUID_PROCESSOR_BRAND_STRING_0 = 0x80000002,
            CPUID_PROCESSOR_BRAND_STRING_1 = 0x80000003,
            CPUID_PROCESSOR_BRAND_STRING_2 = 0x80000004,
            CPUID_L1_AND_TLB = 0x80000005,
            CPUID_L2_L3_TLB = 0x80000006,
            CPUID_POWER_MANAGEMENT_AND_RAS_CAPABILITIES = 0x80000007,
            CPUID_CAPACITY_AND_EXTENDED_FEATURES = 0x80000008,
            // 0x80000009 is reserved
            CPUID_SVM_FEATURES = 0x8000000A,
            // 0x8000000B..0x80000018 are reserved
            CPUID_TLB_CHARACTERISTICS_FOR_1GB_PAGES = 0x80000019,
            CPUID_INSTRUCTION_OPTIMIZATIONS = 0x8000001A,
            CPUID_INSTRUCTION_BASED_SAMPLING_CAPABILITIES = 0x8000001B,
            CPUID_LIGHTWEIGHT_PROFILING_CAPABILITIES = 0x8000001C,
            CPUID_CACHE_TOPOLOGY_INFORMATION = 0x8000001D,
            CPUID_PROCESSOR_TOPOLOGY_INFORMATION = 0x8000001E,
            CPUID_ENCRYPTED_MEMORY_CAPABILITIES = 0x8000001F
        };
    }

    union MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID {
        CPUID_REGS Regs;
        struct {
            unsigned int LargestStandardFunctionNumber;
            unsigned int VendorPart1; // 'uneG' || 'htuA'
            unsigned int VendorPart3; // 'letn' || 'DMAc' --> 'GenuineIntel' or 'AuthenticAMD' (EAX + EDX + ECX)
            unsigned int VendorPart2; // 'Ieni' || 'itne'
        } Bitmap;
    };
    static_assert(sizeof(MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID) == sizeof(CPUID_REGS), "Size of MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID != sizeof(int[4])");

    union MAXIMUM_EXTENDED_FUNCTION_NUMBER_AND_VENDOR_ID {
        CPUID_REGS Regs;
        struct {
            unsigned int LargestExtendedFunctionNumber;
            unsigned int VendorPart1; // 'uneG' || 'htuA'
            unsigned int VendorPart3; // 'letn' || 'DMAc' --> 'GenuineIntel' or 'AuthenticAMD' (EAX + EDX + ECX)
            unsigned int VendorPart2; // 'Ieni' || 'itne'
        } Bitmap;
    };
    static_assert(sizeof(MAXIMUM_EXTENDED_FUNCTION_NUMBER_AND_VENDOR_ID) == sizeof(CPUID_REGS), "Size of MAXIMUM_EXTENDED_FUNCTION_NUMBER_AND_VENDOR_ID != sizeof(int[4])");

    union FEATURE_INFORMATION {
        CPUID_REGS Regs;
        struct {
            // EAX:
            unsigned int Stepping : 4;
            unsigned int Model : 4;
            unsigned int FamilyId : 4;
            unsigned int ProcessorType : 2;
            unsigned int Reserved0 : 2;
            unsigned int ExtendedModelId : 4;
            unsigned int ExtendedFamilyId : 8;
            unsigned int Reserved1 : 4;

            // EBX:
            unsigned int BrandIndex : 8;
            unsigned int ClflushLineSize : 8; // Value * 8 = cache line size in bytes
            unsigned int LogicalProcessorCount : 8; // Valid only if CPUID.1.EDX.HTT == 1
            unsigned int InitialApicId : 8;

            // ECX:
            unsigned int SSE3 : 1;
            unsigned int PCLMULQDQ : 1;
            unsigned int DTES64 : 1; // 64-bit DS area
            unsigned int MONITOR : 1;
            unsigned int DS_CPL : 1; // CPL qualified debug store
            unsigned int VMX : 1;
            unsigned int SMX : 1;
            unsigned int EIST : 1; // Enhanced Intel Speed-Step
            unsigned int TM2 : 1; // Thermal monitor 2
            unsigned int SSSE3 : 1;
            unsigned int CNXT_ID : 1; // L1 context ID
            unsigned int SDBG : 1; // Support of IA32_DEBUG_INTERFACE MSR
            unsigned int FMA : 1;
            unsigned int CMPXCHG16B : 1;
            unsigned int xTPRUpdateControl : 1; // Support of IA32_MISC_ENABLE changing
            unsigned int PDCM : 1; // Perfmon and debug capability: support of MSR IA32_PERF_CAPABILITIES
            unsigned int Reserved2 : 1;
            unsigned int PCID : 1; // Process-context identifiers: support of setting the CR4.PCIDE to 1
            unsigned int DSA : 1; // Ability to prefetch data from a memory mapped device
            unsigned int SSE41 : 1;
            unsigned int SSE42 : 1;
            unsigned int x2APIC : 1; // Support of x2APIC feature
            unsigned int MOVBE : 1;
            unsigned int POPCNT : 1;
            unsigned int TSCDeadline : 1; // Indicates that the processor's local APIC timer supports one-shot operation using a TSC deadline value
            unsigned int AESNI : 1;
            unsigned int XSAVE : 1;
            unsigned int OSXSAVE : 1;
            unsigned int AVX : 1;
            unsigned int F16C : 1;
            unsigned int RDRAND : 1;
            unsigned int NotUsed : 1; // Always returns 0

            // EDX:
            unsigned int FPU : 1;
            unsigned int VME : 1; // Virtual 8086-mode enhancements (including CR4.VME, CR4.PVI, EFLAGS.VIF and EFLAGS.VIP, etc.)
            unsigned int DE : 1; // Debugging extensions
            unsigned int PSE : 1; // Page size extension
            unsigned int TSC : 1; // Time stamp counter
            unsigned int MSR : 1; // RDMSR/WRMSR support
            unsigned int PAE : 1; // Physical address extensions support
            unsigned int MCE : 1; // Machine check exception
            unsigned int CX8 : 1; // CMPXCHG8B
            unsigned int APIC : 1;
            unsigned int Reserved3 : 1;
            unsigned int SEP : 1; // SYSENTER/SYSEXIT instructions support
            unsigned int MTRR : 1; // Memory-Type Range Registers support
            unsigned int PGE : 1; // Page global bit (CR4.PGE bit controls this feature)
            unsigned int MCA : 1; // Machine check architecture
            unsigned int CMOV : 1; // Conditional move instruction support
            unsigned int PAT : 1; // Page attribute table
            unsigned int PSE36 : 1; // 36-bit page size extension
            unsigned int PSN : 1; // Support of 96-bit processor serial number
            unsigned int CLFSH : 1; // CLFLUSH instruction support
            unsigned int Reserved4 : 1;
            unsigned int DS : 1; // Debug store
            unsigned int ACPI : 1; // Thermal Monitor and Software Controlled Clock Facilities
            unsigned int MMX : 1;
            unsigned int FXSR : 1; // FXSAVE and FXRSTOR support
            unsigned int SSE : 1;
            unsigned int SSE2 : 1;
            unsigned int SS : 1; // Self-snoop
            unsigned int HTT : 1; // Max APIC IDs reserved field is Valid (CPUID.1.EBX.LogicalProcessorCount is valid)
            unsigned int TM : 1; // Thermal monitor
            unsigned int Reserved5 : 1;
            unsigned int PBE : 1; // Pending break enable
        } Intel;
        struct {
            // EAX:
            unsigned int Stepping : 4;
            unsigned int Model : 4;
            unsigned int FamilyId : 4;
            unsigned int Reserved0 : 4;
            unsigned int ExtendedModelId : 4;
            unsigned int ExtendedFamilyId : 8;
            unsigned int Reserved1 : 4;

            // EBX:
            unsigned int BrandIndex : 8;
            unsigned int ClflushLineSize : 8; // Value * 8 = cache line size in bytes
            unsigned int LogicalProcessorCount : 8; // Valid only if CPUID.1.EDX.HTT == 1
            unsigned int InitialApicId : 8;

            // ECX:
            unsigned int SSE3 : 1;
            unsigned int PCLMULQDQ : 1;
            unsigned int Reserved2 : 1;
            unsigned int MONITOR : 1;
            unsigned int Reserved3 : 5;
            unsigned int SSSE3 : 1;
            unsigned int Reserved4 : 2;
            unsigned int FMA : 1;
            unsigned int CMPXCHG16B : 1;
            unsigned int Reserved5 : 5;
            unsigned int SSE41 : 1;
            unsigned int SSE42 : 1;
            unsigned int Reserved6 : 1;
            unsigned int MOVBE : 1;
            unsigned int POPCNT : 1;
            unsigned int Reserved7 : 1;
            unsigned int AES : 1;
            unsigned int XSAVE : 1;
            unsigned int OSXSAVE : 1;
            unsigned int AVX : 1;
            unsigned int F16C : 1;
            unsigned int RDRAND : 1;
            unsigned int ReservedForHvGuestStatus : 1; // Reserved for use by hypervisor to indicate guest status

            // EDX:
            unsigned int FPU : 1;
            unsigned int VME : 1; // Virtual 8086-mode enhancements (including CR4.VME, CR4.PVI, EFLAGS.VIF and EFLAGS.VIP, etc.)
            unsigned int DE : 1; // Debugging extensions
            unsigned int PSE : 1; // Page size extension
            unsigned int TSC : 1; // Time stamp counter
            unsigned int MSR : 1; // RDMSR/WRMSR support
            unsigned int PAE : 1; // Physical address extensions support
            unsigned int MCE : 1; // Machine check exception
            unsigned int CMPXCHG8B : 1;
            unsigned int APIC : 1;
            unsigned int Reserved8 : 1;
            unsigned int SysEnterSysExit : 1; // SYSENTER/SYSEXIT instructions support
            unsigned int MTRR : 1; // Memory-Type Range Registers support
            unsigned int PGE : 1; // Page global bit (CR4.PGE bit controls this feature)
            unsigned int MCA : 1; // Machine check architecture
            unsigned int CMOV : 1; // Conditional move instruction support
            unsigned int PAT : 1; // Page attribute table
            unsigned int PSE36 : 1; // 36-bit page size extension
            unsigned int Reserved9 : 1;
            unsigned int CLFSH : 1; // CLFLUSH instruction support
            unsigned int Reserved10 : 3;
            unsigned int MMX : 1;
            unsigned int FXSR : 1; // FXSAVE and FXRSTOR support
            unsigned int SSE : 1;
            unsigned int SSE2 : 1;
            unsigned int Reserved11 : 1;
            unsigned int HTT : 1; // Max APIC IDs reserved field is Valid (CPUID.1.EBX.LogicalProcessorCount is valid)
            unsigned int Reserved12 : 3;
        } Generic, AMD;
    };
    static_assert(sizeof(FEATURE_INFORMATION) == sizeof(CPUID_REGS), "Size of FEATURE_INFORMATION != sizeof(int[4])");

    union EXTENDED_FEATURE_INFORMATION {
        CPUID_REGS Regs;
        struct {
            // EAX:
            unsigned int Stepping : 4;
            unsigned int Model : 4;
            unsigned int FamilyId : 4;
            unsigned int Reserved0 : 4;
            unsigned int ExtendedModelId : 4;
            unsigned int ExtendedFamilyId : 8;
            unsigned int Reserved1 : 4;

            // EBX:
            unsigned int Reserved2 : 32;

            // ECX:
            unsigned int LahfSahf : 1;
            unsigned int Reserved3 : 4;
            unsigned int LZCNT : 1;
            unsigned int Reserved4 : 2;
            unsigned int PREFETCHW : 1;
            unsigned int Reserved5 : 23;

            // EDX:
            unsigned int Reserved6 : 11;
            unsigned int SysCallSysRet : 1;
            unsigned int Reserved7 : 8;
            unsigned int NX : 1;
            unsigned int Reserved8 : 5;
            unsigned int Page1Gb : 1; // 1-Gb large page support
            unsigned int RDTSCP : 1;
            unsigned int Reserved9 : 1;
            unsigned int LongMode : 1; // 64-bit mode
            unsigned int Reserved10 : 2;
        } Generic;
        struct {
            // EAX:
            unsigned int Stepping : 4;
            unsigned int Model : 4;
            unsigned int FamilyId : 4;
            unsigned int Reserved0 : 4;
            unsigned int ExtendedModelId : 4;
            unsigned int ExtendedFamilyId : 8;
            unsigned int Reserved1 : 4;

            // EBX:
            unsigned int Reserved2 : 32;

            // ECX:
            unsigned int LahfSahf : 1;
            unsigned int Reserved3 : 4;
            unsigned int LZCNT : 1;
            unsigned int Reserved4 : 2;
            unsigned int PREFETCHW : 1;
            unsigned int Reserved5 : 23;

            // EDX:
            unsigned int Reserved6 : 11;
            unsigned int SysCallSysRet : 1;
            unsigned int Reserved7 : 8;
            unsigned int NX : 1;
            unsigned int Reserved8 : 5;
            unsigned int Page1Gb : 1; // 1-Gb large page support
            unsigned int RdtscpIa32TscAux : 1;
            unsigned int Reserved9 : 1;
            unsigned int IA64 : 1; // Intel64 Architecture support
            unsigned int Reserved10 : 2;
        } Intel;
        struct {
            // EAX:
            unsigned int Stepping : 4;
            unsigned int Model : 4;
            unsigned int FamilyId : 4;
            unsigned int Reserved0 : 4;
            unsigned int ExtendedModelId : 4;
            unsigned int ExtendedFamilyId : 8;
            unsigned int Reserved1 : 4;

            // EBX:
            unsigned int BrandId : 16;
            unsigned int Reserved2 : 12;
            unsigned int PkgType : 4;

            // ECX:
            unsigned int LahfSahf : 1;
            unsigned int CmpLegacy : 1; // Core multiprocessing legacy mode
            unsigned int SVM : 1; // Secure virtual machine
            unsigned int ExtApicSpace : 1;
            unsigned int AltMovCr8 : 1; // "lock mov cr0" means "mov cr8"
            unsigned int ABM : 1; // Advanced bit manipulation
            unsigned int SSE4A : 1; // EXTRQ, INSERTQ, MOVNTSS, and MOVNTSD instruction support
            unsigned int MisAlignSse : 1; // Misaligned SSE mode
            unsigned int _3DNowPrefetch : 1; // PREFETCH and PREFETCHW instruction support
            unsigned int OSVW : 1; // OS visible workaround
            unsigned int IBS : 1; // Instruction based sampling
            unsigned int XOP : 1; // Extended operation support
            unsigned int SKINIT : 1; // SKINIT and STGI are supported, independent of the value of MSRC000_0080[SVME]
            unsigned int WDT : 1; // Watchdog time support
            unsigned int Reserved3 : 1;
            unsigned int LWP : 1; // Lightweight profiling support
            unsigned int FMA4 : 1;
            unsigned int Reserved4 : 1;
            unsigned int Reserved5 : 1;
            unsigned int NodeId : 1;
            unsigned int Reserved6 : 1;
            unsigned int TBM : 1; // Trailing bit manipulation instruction support
            unsigned int TopologyExtension : 1;
            unsigned int Reserved7 : 9;

            // EDX:
            unsigned int FPU : 1;
            unsigned int VME : 1; // Virtual 8086-mode enhancements (including CR4.VME, CR4.PVI, EFLAGS.VIF and EFLAGS.VIP, etc.)
            unsigned int DE : 1; // Debugging extensions
            unsigned int PSE : 1; // Page size extension
            unsigned int TSC : 1; // Time stamp counter
            unsigned int MSR : 1; // RDMSR/WRMSR support
            unsigned int PAE : 1; // Physical address extensions support
            unsigned int MCE : 1; // Machine check exception
            unsigned int CMPXCHG8B : 1;
            unsigned int APIC : 1;
            unsigned int Reserved8 : 1;
            unsigned int SysCallSysRet : 1; // SYSCALL/SYSRET instructions support
            unsigned int MTRR : 1; // Memory-Type Range Registers support
            unsigned int PGE : 1; // Page global bit (CR4.PGE bit controls this feature)
            unsigned int MCA : 1; // Machine check architecture
            unsigned int CMOV : 1; // Conditional move instruction support
            unsigned int PAT : 1; // Page attribute table
            unsigned int PSE36 : 1; // 36-bit page size extension
            unsigned int Reserved9 : 2;
            unsigned int NX : 1; // No-execute page protection
            unsigned int Reserved10 : 1;
            unsigned int MmxExt : 1;
            unsigned int MMX : 1;
            unsigned int FXSR : 1; // FXSAVE and FXRSTOR support
            unsigned int FFXSR : 1;  // FXSAVE and FXRSTOR instruction optimizations
            unsigned int Page1Gb : 1; // 1-Gb large page support
            unsigned int RDTSCP : 1;
            unsigned int Reserved11 : 1;
            unsigned int LM : 1; // Long-mode
            unsigned int _3DNowExt : 1;
            unsigned int _3DNow : 1;
        } AMD;
    };
    static_assert(sizeof(EXTENDED_FEATURE_INFORMATION) == sizeof(CPUID_REGS), "Size of EXTENDED_FEATURE_INFORMATION != sizeof(int[4])");

    union PROCESSOR_BRAND_STRING_0 {
        CPUID_REGS Regs;
        struct {
            unsigned int Part0;
            unsigned int Part1;
            unsigned int Part2;
            unsigned int Part3;
        } ProcessorName;
    };
    static_assert(sizeof(PROCESSOR_BRAND_STRING_0) == sizeof(CPUID_REGS), "Size of PROCESSOR_BRAND_STRING_0 != sizeof(int[4])");

    union PROCESSOR_BRAND_STRING_1 {
        CPUID_REGS Regs;
        struct {
            unsigned int Part4;
            unsigned int Part5;
            unsigned int Part6;
            unsigned int Part7;
        } ProcessorName;
    };
    static_assert(sizeof(PROCESSOR_BRAND_STRING_1) == sizeof(CPUID_REGS), "Size of PROCESSOR_BRAND_STRING_1 != sizeof(int[4])");

    union PROCESSOR_BRAND_STRING_2 {
        CPUID_REGS Regs;
        struct {
            unsigned int Part8;
            unsigned int Part9;
            unsigned int Part10;
            unsigned int Part11;
        } ProcessorName;
    };
    static_assert(sizeof(PROCESSOR_BRAND_STRING_2) == sizeof(CPUID_REGS), "Size of PROCESSOR_BRAND_STRING_2 != sizeof(int[4])");

    namespace Intel {
        union VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES {
            CPUID_REGS Regs;
            struct {
                // EAX:
                unsigned int PhysicalAddressBits : 8;
                unsigned int LinearAddressBits : 8;
                unsigned int Reserved0 : 16;
                
                unsigned int Reserved1 : 32; // EBX
                unsigned int Reserved2 : 32; // ECX
                unsigned int Reserved3 : 32; // EDX
            } Bitmap;
        };
        static_assert(sizeof(VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES) == sizeof(CPUID_REGS), "Size of VIRTUAL_AND_PHYSICAL_ADDRESS_SIZES != sizeof(int[4])");
    }
}