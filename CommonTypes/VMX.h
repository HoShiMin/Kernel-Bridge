#pragma once

namespace VMX {
    struct VMCS {
        union {
            unsigned int Value;
            struct {
                unsigned int VmcsRevisionId : 31;
                unsigned int ShadowVmcsIndicator : 1;
            } Bitmap;
        } RevisionId;
        unsigned int VmxAbortIndicator;
        unsigned char VmcsData[0x1000 - sizeof(RevisionId) - sizeof(VmxAbortIndicator)];
    };
    static_assert(sizeof(VMCS) == 0x1000, "Size of VMCS != 4096 bytes");

    union VMCS_COMPONENT_ENCODING {
        unsigned int Value;
        struct {
            unsigned int AccessType : 1; // 0 = full, 1 = high; must be full for 16-bit, 32-bit, and natural-width fields
            unsigned int Index : 9;
            unsigned int Type : 2; // 0 = control, 1 = VMexit information, 2 = guest state, 3 = host state
            unsigned int Reserved0 : 1; // Must be zero
            unsigned int Width : 2; // 0 = 16-bit, 1 = 64-bit, 2 = 32-bit, 3 = natural width
            unsigned int Reserved1 : 17; // Must be zero
        } Bitmap;
    };
    static_assert(sizeof(VMCS_COMPONENT_ENCODING) == sizeof(unsigned int), "Size of VMCS_COMPONENT_ENCODING != sizeof(unsigned int)");

    enum VMCS_FIELD_ENCODING : decltype(VMCS_COMPONENT_ENCODING::Value) {
        // 16-bit control fields:
        VMCS_FIELD_VIRTUAL_PROCESSOR_IDENTIFIER = 0x00000000,
        VMCS_FIELD_POSTED_INTERRUPT_NOTIFICATION_VECTOR = 0x00000002,
        VMCS_FIELD_EPTP_INDEX = 0x00000004,

        // 16-bit guest-state fields:
        VMCS_FIELD_GUEST_ES_SELECTOR = 0x00000800,
        VMCS_FIELD_GUEST_CS_SELECTOR = 0x00000802,
        VMCS_FIELD_GUEST_SS_SELECTOR = 0x00000804,
        VMCS_FIELD_GUEST_DS_SELECTOR = 0x00000806,
        VMCS_FIELD_GUEST_FS_SELECTOR = 0x00000808,
        VMCS_FIELD_GUEST_GS_SELECTOR = 0x0000080A,
        VMCS_FIELD_GUEST_LDTR_SELECTOR = 0x0000080C,
        VMCS_FIELD_GUEST_TR_SELECTOR = 0x0000080E,
        VMCS_FIELD_GUEST_INTERRUPT_STATUS = 0x00000810,
        VMCS_FIELD_PML_INDEX = 0x00000820,

        // 16-bit host-state fields:
        VMCS_FIELD_HOST_ES_SELECTOR = 0x00000C00,
        VMCS_FIELD_HOST_CS_SELECTOR = 0x00000C02,
        VMCS_FIELD_HOST_SS_SELECTOR = 0x00000C04,
        VMCS_FIELD_HOST_DS_SELECTOR = 0x00000C06,
        VMCS_FIELD_HOST_FS_SELECTOR = 0x00000C08,
        VMCS_FIELD_HOST_GS_SELECTOR = 0x00000C0A,
        VMCS_FIELD_HOST_TR_SELECTOR = 0x00000C0C,

        // 64-bit control fields:
        VMCS_FIELD_ADDRESS_OF_IO_BITMAP_A_FULL = 0x00002000,
        VMCS_FIELD_ADDRESS_OF_IO_BITMAP_A_HIGH = 0x00002001,
        VMCS_FIELD_ADDRESS_OF_IO_BITMAP_B_FULL = 0x00002002,
        VMCS_FIELD_ADDRESS_OF_IO_BITMAP_B_HIGH = 0x00002003,
        VMCS_FIELD_ADDRESS_OF_MSR_BITMAPS_FULL = 0x00002004,
        VMCS_FIELD_ADDRESS_OF_MSR_BITMAPS_HIGH = 0x00002005,
        VMCS_FIELD_VMEXIT_MSR_STORE_ADDRESS_FULL = 0x00002006,
        VMCS_FIELD_VMEXIT_MSR_STORE_ADDRESS_HIGH = 0x00002007,
        VMCS_FIELD_VMEXIT_MSR_LOAD_ADDRESS_FULL = 0x00002008,
        VMCS_FIELD_VMEXIT_MSR_LOAD_ADDRESS_HIGH = 0x00002009,
        VMCS_FIELD_VMENTRY_MSR_LOAD_ADDRESS_FULL = 0x0000200A,
        VMCS_FIELD_VMENTRY_MSR_LOAD_ADDRESS_HIGH = 0x0000200B,
        VMCS_FIELD_EXECUTIVE_VMCS_POINTER_FULL = 0x0000200C,
        VMCS_FIELD_EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200D,
        VMCS_FIELD_PML_ADDRESS_FULL = 0x0000200E,
        VMCS_FIELD_PML_ADDRESS_HIGH = 0x0000200F,
        VMCS_FIELD_TSC_OFFSET_FULL = 0x00002010,
        VMCS_FIELD_TSC_OFFSET_HIGH = 0x00002011,
        VMCS_FIELD_VIRTUAL_APIC_ADDRESS_FULL = 0x00002012,
        VMCS_FIELD_VIRTUAL_APIC_ADDRESS_HIGH = 0x00002013,
        VMCS_FIELD_APIC_ACCESS_ADDRESS_FULL = 0x00002014,
        VMCS_FIELD_APIC_ACCESS_ADDRESS_HIGH = 0x00002015,
        VMCS_FIELD_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL = 0x00002016,
        VMCS_FIELD_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH = 0x00002017,
        VMCS_FIELD_VM_FUNCTIONS_CONTROL_FULL = 0x00002018,
        VMCS_FIELD_VM_FUNCTIONS_CONTROL_HIGH = 0x00002019,
        VMCS_FIELD_EPT_POINTER_FULL = 0x0000201A,
        VMCS_FIELD_EPT_POINTER_HIGH = 0x0000201B,
        VMCS_FIELD_EOI_EXIT_BITMAP_0_FULL = 0x0000201C,
        VMCS_FIELD_EOI_EXIT_BITMAP_0_HIGH = 0x0000201D,
        VMCS_FIELD_EOI_EXIT_BITMAP_1_FULL = 0x0000201E,
        VMCS_FIELD_EOI_EXIT_BITMAP_1_HIGH = 0x0000201F,
        VMCS_FIELD_EOI_EXIT_BITMAP_2_FULL = 0x00002020,
        VMCS_FIELD_EOI_EXIT_BITMAP_2_HIGH = 0x00002021,
        VMCS_FIELD_EOI_EXIT_BITMAP_3_FULL = 0x00002022,
        VMCS_FIELD_EOI_EXIT_BITMAP_3_HIGH = 0x00002023,
        VMCS_FIELD_EPTP_LIST_ADDRESS_FULL = 0x00002024,
        VMCS_FIELD_EPTP_LIST_ADDRESS_HIGH = 0x00002025,
        VMCS_FIELD_VMREAD_BITMAP_ADDRESS_FULL = 0x00002026,
        VMCS_FIELD_VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,
        VMCS_FIELD_VMWRITE_BITMAP_ADDRESS_FULL = 0x00002028,
        VMCS_FIELD_VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,
        VMCS_FIELD_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL = 0x0000202A,
        VMCS_FIELD_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_HIGH = 0x0000202B,
        VMCS_FIELD_XSS_EXITING_BITMAP_FULL = 0x0000202C,
        VMCS_FIELD_XSS_EXITING_BITMAP_HIGH = 0x0000202D,
        VMCS_FIELD_ENCLS_EXITING_BITMAP_FULL = 0x0000202E,
        VMCS_FIELD_ENCLS_EXITING_BITMAP_HIGH = 0x0000202F,
        VMCS_FIELD_SUBPAGE_PERMISSION_TABLE_POINTER_FULL = 0x00002030,
        VMCS_FIELD_SUBPAGE_PERMISSION_TABLE_POINTER_HIGH = 0x00002031,
        VMCS_FIELD_TSC_MULTIPLIER_FULL = 0x00002032,
        VMCS_FIELD_TSC_MULTIPLIER_HIGH = 0x00002033,

        // 64-bit read-only data fields:
        VMCS_FIELD_GUEST_PHYSICAL_ADDRESS_FULL = 0x00002400,
        VMCS_FIELD_GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,

        // 64-bit guest state fields:
        VMCS_FIELD_VMCS_LINK_POINTER_FULL = 0x00002800,
        VMCS_FIELD_VMCS_LINK_POINTER_HIGH = 0x00002801,
        VMCS_FIELD_GUEST_IA32_DEBUGCTL_FULL = 0x00002802,
        VMCS_FIELD_GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
        VMCS_FIELD_GUEST_IA32_PAT_FULL = 0x00002804,
        VMCS_FIELD_GUEST_IA32_PAT_HIGH = 0x00002805,
        VMCS_FIELD_GUEST_IA32_EFER_FULL = 0x00002806,
        VMCS_FIELD_GUEST_IA32_EFER_HIGH = 0x00002807,
        VMCS_FIELD_GUEST_IA32_PERF_GLOBAL_CTRL_FULL = 0x00002808,
        VMCS_FIELD_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
        VMCS_FIELD_GUEST_PDPTE_0_FULL = 0x0000280A,
        VMCS_FIELD_GUEST_PDPTE_0_HIGH = 0x0000280B,
        VMCS_FIELD_GUEST_PDPTE_1_FULL = 0x0000280C,
        VMCS_FIELD_GUEST_PDPTE_1_HIGH = 0x0000280D,
        VMCS_FIELD_GUEST_PDPTE_2_FULL = 0x0000280E,
        VMCS_FIELD_GUEST_PDPTE_2_HIGH = 0x0000280F,
        VMCS_FIELD_GUEST_PDPTE_3_FULL = 0x00002810,
        VMCS_FIELD_GUEST_PDPTE_3_HIGH = 0x00002811,
        VMCS_FIELD_GUEST_IA32_BNDCFGS_FULL = 0x00002812,
        VMCS_FIELD_GUEST_IA32_BNDCFGS_HIGH = 0x00002813,

        // 64-bit host-state fields:
        VMCS_FIELD_HOST_IA32_PAT_FULL = 0x00002C00,
        VMCS_FIELD_HOST_IA32_PAT_HIGH = 0x00002C01,
        VMCS_FIELD_HOST_IA32_EFER_FULL = 0x00002C02,
        VMCS_FIELD_HOST_IA32_EFER_HIGH = 0x00002C03,
        VMCS_FIELD_HOST_IA32_PERF_GLOBAL_CTRL_FULL = 0x00002C04,
        VMCS_FIELD_HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002C05,

        // 32-bit control fields:
        VMCS_FIELD_PIN_BASED_VM_EXECUTION_CONTROLS = 0x00004000,
        VMCS_FIELD_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x00004002,
        VMCS_FIELD_EXCEPTION_BITMAP = 0x00004004,
        VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
        VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
        VMCS_FIELD_CR3_TARGET_COUNT = 0x0000400A,
        VMCS_FIELD_VMEXIT_CONTROLS = 0x0000400C,
        VMCS_FIELD_VMEXIT_MSR_STORE_COUNT = 0x0000400E,
        VMCS_FIELD_VMEXIT_MSR_LOAD_COUNT = 0x00004010,
        VMCS_FIELD_VMENTRY_CONTROLS = 0x00004012,
        VMCS_FIELD_VMENTRY_MSR_LOAD_COUNT = 0x00004014,
        VMCS_FIELD_VMENTRY_INTERRUPTION_INFORMATION_FIELD = 0x00004016,
        VMCS_FIELD_VMENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
        VMCS_FIELD_VMENTRY_INSTRUCTION_LENGTH = 0x0000401A,
        VMCS_FIELD_TPR_THRESHOLD = 0x0000401C,
        VMCS_FIELD_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x0000401E,
        VMCS_FIELD_PLE_GAP = 0x00004020,
        VMCS_FIELD_PLE_WINDOW = 0x00004022,

        // 32-bit read-only data fields:
        VMCS_FIELD_VM_INSTRUCTION_ERROR = 0x00004400,
        VMCS_FIELD_EXIT_REASON = 0x00004402,
        VMCS_FIELD_VMEXIT_INTERRUPTION_INFORMATION = 0x00004404,
        VMCS_FIELD_VMEXIT_INTERRUPTION_ERROR_CODE = 0x00004406,
        VMCS_FIELD_IDT_VECTORING_INFORMATION_FIELD = 0x00004408,
        VMCS_FIELD_IDT_VECTORING_ERROR_CODE = 0x0000440A,
        VMCS_FIELD_VMEXIT_INSTRUCTION_LENGTH = 0x0000440C,
        VMCS_FIELD_VMEXIT_INSTRUCTION_INFORMATION = 0x0000440E,

        // 32-bit guest-state fields:
        VMCS_FIELD_GUEST_ES_LIMIT = 0x00004800,
        VMCS_FIELD_GUEST_CS_LIMIT = 0x00004802,
        VMCS_FIELD_GUEST_SS_LIMIT = 0x00004804,
        VMCS_FIELD_GUEST_DS_LIMIT = 0x00004806,
        VMCS_FIELD_GUEST_FS_LIMIT = 0x00004808,
        VMCS_FIELD_GUEST_GS_LIMIT = 0x0000480A,
        VMCS_FIELD_GUEST_LDTR_LIMIT = 0x0000480C,
        VMCS_FIELD_GUEST_TR_LIMIT = 0x0000480E,
        VMCS_FIELD_GUEST_GDTR_LIMIT = 0x00004810,
        VMCS_FIELD_GUEST_IDTR_LIMIT = 0x00004812,
        VMCS_FIELD_GUEST_ES_ACCESS_RIGHTS = 0x00004814,
        VMCS_FIELD_GUEST_CS_ACCESS_RIGHTS = 0x00004816,
        VMCS_FIELD_GUEST_SS_ACCESS_RIGHTS = 0x00004818,
        VMCS_FIELD_GUEST_DS_ACCESS_RIGHTS = 0x0000481A,
        VMCS_FIELD_GUEST_FS_ACCESS_RIGHTS = 0x0000481C,
        VMCS_FIELD_GUEST_GS_ACCESS_RIGHTS = 0x0000481E,
        VMCS_FIELD_GUEST_LDTR_ACCESS_RIGHTS = 0x00004820,
        VMCS_FIELD_GUEST_TR_ACCESS_RIGHTS = 0x00004822,
        VMCS_FIELD_GUEST_INTERRUPTIBILITY_STATE = 0x00004824,
        VMCS_FIELD_GUEST_ACTIVITY_STATE = 0x00004826,
        VMCS_FIELD_GUEST_SMBASE = 0x00004828,
        VMCS_FIELD_GUEST_IA32_SYSENTER_CS = 0x0000482A,
        VMCS_FIELD_VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,

        // 32-bit host-state fields:
        VMCS_FIELD_HOST_IA32_SYSENTER_CS = 0x00004C00,

        // Natural-width control fields:
        VMCS_FIELD_CR0_GUEST_HOST_MASK = 0x00006000,
        VMCS_FIELD_CR4_GUEST_HOST_MASK = 0x00006002,
        VMCS_FIELD_CR0_READ_SHADOW = 0x00006004,
        VMCS_FIELD_CR4_READ_SHADOW = 0x00006006,
        VMCS_FIELD_CR3_TARGET_VALUE_0 = 0x00006008,
        VMCS_FIELD_CR3_TARGET_VALUE_1 = 0x0000600A,
        VMCS_FIELD_CR3_TARGET_VALUE_2 = 0x0000600C,
        VMCS_FIELD_CR3_TARGET_VALUE_3 = 0x0000600E,

        // Natural-width read-only data fields:
        VMCS_FIELD_EXIT_QUALIFICATION = 0x00006400,
        VMCS_FIELD_IO_RCX = 0x00006402,
        VMCS_FIELD_IO_RSI = 0x00006404,
        VMCS_FIELD_IO_RDI = 0x00006406,
        VMCS_FIELD_IO_RIP = 0x00006408,

        // Natural-width guest-state fields:
        VMCS_FIELD_GUEST_CR0 = 0x00006800,
        VMCS_FIELD_GUEST_CR3 = 0x00006802,
        VMCS_FIELD_GUEST_CR4 = 0x00006804,
        VMCS_FIELD_GUEST_ES_BASE = 0x00006806,
        VMCS_FIELD_GUEST_CS_BASE = 0x00006808,
        VMCS_FIELD_GUEST_SS_BASE = 0x0000680A,
        VMCS_FIELD_GUEST_DS_BASE = 0x0000680C,
        VMCS_FIELD_GUEST_FS_BASE = 0x0000680E,
        VMCS_FIELD_GUEST_GS_BASE = 0x00006810,
        VMCS_FIELD_GUEST_LDTR_BASE = 0x00006812,
        VMCS_FIELD_GUEST_TR_BASE = 0x00006814,
        VMCS_FIELD_GUEST_GDTR_BASE = 0x00006816,
        VMCS_FIELD_GUEST_IDTR_BASE = 0x00006818,
        VMCS_FIELD_GUEST_DR7 = 0x0000681A,
        VMCS_FIELD_GUEST_RSP = 0x0000681C,
        VMCS_FIELD_GUEST_RIP = 0x0000681E,
        VMCS_FIELD_GUEST_RFLAGS = 0x00006820,
        VMCS_FIELD_GUEST_PENDING_DEBUG_EXCEPTIONS = 0x00006822,
        VMCS_FIELD_GUEST_IA32_SYSENTER_ESP = 0x00006824,
        VMCS_FIELD_GUEST_IA32_SYSENTER_EIP = 0x00006826,

        // Natural-width host-state fields:
        VMCS_FIELD_HOST_CR0 = 0x00006C00,
        VMCS_FIELD_HOST_CR3 = 0x00006C02,
        VMCS_FIELD_HOST_CR4 = 0x00006C04,
        VMCS_FIELD_HOST_FS_BASE = 0x00006C06,
        VMCS_FIELD_HOST_GS_BASE = 0x00006C08,
        VMCS_FIELD_HOST_TR_BASE = 0x00006C0A,
        VMCS_FIELD_HOST_GDTR_BASE = 0x00006C0C,
        VMCS_FIELD_HOST_IDTR_BASE = 0x00006C0E,
        VMCS_FIELD_HOST_IA32_SYSENTER_ESP = 0x00006C10,
        VMCS_FIELD_HOST_IA32_SYSENTER_EIP = 0x00006C12,
        VMCS_FIELD_HOST_RSP = 0x00006C14,
        VMCS_FIELD_HOST_RIP = 0x00006C16
    };

    enum VMX_EXIT_REASON {
        EXIT_REASON_EXCEPTION_OR_NMI = 0,
        EXIT_REASON_EXTERNAL_INTERRUPT = 1,
        EXIT_REASON_TRIPLE_FAULT = 2,
        EXIT_REASON_INIT_SIGNAL = 3,
        EXIT_REASON_SIPI = 4, // Startup IPI
        EXIT_REASON_IO_SMI = 5,
        EXIT_REASON_OTHER_SMI = 6,
        EXIT_REASON_INTERRUPT_WINDOW = 7,
        EXIT_REASON_NMI_WINDOW = 8,
        EXIT_REASON_TASK_SWITCH = 9,
        EXIT_REASON_CPUID = 10,
        EXIT_REASON_GETSEC = 11,
        EXIT_REASON_HLT = 12,
        EXIT_REASON_INVD = 13,
        EXIT_REASON_INVLPG = 14,
        EXIT_REASON_RDPMC = 15,
        EXIT_REASON_RDTSC = 16,
        EXIT_REASON_RSM = 17,
        EXIT_REASON_VMCALL = 18,
        EXIT_REASON_VMCLEAR = 19,
        EXIT_REASON_VMLAUNCH = 20,
        EXIT_REASON_VMPTRLD = 21,
        EXIT_REASON_VMPTRST = 22,
        EXIT_REASON_VMREAD = 23,
        EXIT_REASON_VMRESUME = 24,
        EXIT_REASON_VMWRITE = 25,
        EXIT_REASON_VMXOFF = 26,
        EXIT_REASON_VMXON = 27,
        EXIT_REASON_CR_ACCESS = 28,
        EXIT_REASON_DR_ACCESS = 29,
        EXIT_REASON_IO_INSTRUCTION = 30,
        EXIT_REASON_RDMSR = 31,
        EXIT_REASON_WRMSR = 32,
        EXIT_REASON_INVALID_GUEST_STATE = 33,
        EXIT_REASON_MSR_LOADING_FAILURE = 34,
        EXIT_REASON_MWAIT = 36,
        EXIT_REASON_MONITOR_TRAP_FLAG = 37,
        EXIT_REASON_MONITOR = 39,
        EXIT_REASON_PAUSE = 40,
        EXIT_REASON_MACHINE_CHECK_EVENT_FAILURE = 41,
        EXIT_REASON_TPR_BELOW_THRESHOLD = 43,
        EXIT_REASON_APIC_ACCESS = 44,
        EXIT_REASON_VIRTUALIZED_EOI = 45,
        EXIT_REASON_GDTR_OR_IDTR_ACCESS = 46,
        EXIT_REASON_LDTR_OR_TR_ACCESS = 47,
        EXIT_REASON_EPT_VIOLATION = 48,
        EXIT_REASON_EPT_MISCONFIGURATION = 49,
        EXIT_REASON_INVEPT = 50,
        EXIT_REASON_RDTSCP = 51,
        EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED = 52,
        EXIT_REASON_INVVPID = 53,
        EXIT_REASON_WBINVD = 54,
        EXIT_REASON_XSETBV = 55,
        EXIT_REASON_APIC_WRITE = 56,
        EXIT_REASON_RDRAND = 57,
        EXIT_REASON_INVPCID = 58,
        EXIT_REASON_VNFUNC = 59,
        EXIT_REASON_ENCLS = 60,
        EXIT_REASON_RDSEED = 61,
        EXIT_REASON_PAGE_MODIFICATION_LOG_FULL = 62,
        EXIT_REASON_XSAVES = 63,
        EXIT_REASON_XRSTORS = 64,
        EXIT_REASON_PCOMMIT = 65,
        EXIT_REASON_SPP_RELATED_EVENT = 66
    };

    // Extended-Page-Table Pointer:
    union EPTP {
        unsigned long long Value;
        struct {
            unsigned long long EptMemoryType : 3; // 0 = Uncacheable, 6 = Write-back, other values are reserved
            unsigned long long PageWalkLength : 3; // This value is 1 less than the EPT page-walk length
            unsigned long long AccessedAndDirtyFlagsSupport : 1; // Setting this control to 1 enables accessed and dirty flags for EPT (check IA32_VMX_EPT_VPID_CAP)
            unsigned long long Reserved0 : 5;
            unsigned long long EptPml4ePhysicalAddress : 52; // Maximum supported physical address width: CPUID(EAX = 0x80000008) -> EAX[7:0]
        } Bitmap;
    };
    static_assert(sizeof(EPTP) == sizeof(unsigned long long), "Size of EPTP != sizeof(unsigned long long)");

    // Describes 512-GByte region:
    union EPT_PML4E {
        unsigned long long Value;
        struct {
            unsigned long long ReadAccess : 1;
            unsigned long long WriteAccess : 1;
            unsigned long long ExecuteAccess : 1;
            unsigned long long Reserved0 : 5; // Must be zero
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Ignored0 : 1;
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Ignored1 : 1;
            unsigned long long EptPdptePhysicalAddress : 40; // Maximum supported physical address width: CPUID(EAX = 0x80000008) -> EAX[7:0]
            unsigned long long Ignored2 : 12;
        } Page1Gb, Page2Mb, Page4Kb, Generic;
    };
    static_assert(sizeof(EPT_PML4E) == sizeof(unsigned long long), "Size of EPT_PML4E != sizeof(unsigned long long)");

    union EPT_PDPTE {
        unsigned long long Value;
        struct {
            unsigned long long ReadAccess : 1;
            unsigned long long WriteAccess : 1;
            unsigned long long ExecuteAccess : 1;
            unsigned long long Type : 3;
            unsigned long long IgnorePat : 1;
            unsigned long long LargePage : 1; // Must be 1 (otherwise, this entry references an EPT page directory)
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Dirty : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Ignored0 : 1;
            unsigned long long Reserved0 : 18; // Must be zero
            unsigned long long PagePhysicalAddress : 22; // Physical address of the 1-GByte page referenced by this entry
            unsigned long long Ignored1 : 11;
            unsigned long long SuppressVe : 1; // Ignored if "EPT-violation #VE" VM-execution control is 0
        } Page1Gb;
        struct {
            unsigned long long ReadAccess : 1;
            unsigned long long WriteAccess : 1;
            unsigned long long ExecuteAccess : 1;
            unsigned long long Reserved0 : 5; // Must be zero
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Ignored0 : 1;
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Ignored1 : 1;
            unsigned long long Reserved1 : 18; // Must be zero
            unsigned long long EptPdePhysicalAddress : 22;
            unsigned long long Ignored2 : 12;
        } Page2Mb, Page4Kb;
    };
    static_assert(sizeof(EPT_PDPTE) == sizeof(unsigned long long), "Size of EPT_PDPTE != sizeof(unsigned long long)");

    union EPT_PDE {
        unsigned long long Value;
        struct {
            unsigned long long ReadAccess : 1;
            unsigned long long WriteAccess : 1;
            unsigned long long ExecuteAccess : 1;
            unsigned long long Type : 3;
            unsigned long long IgnorePat : 1;
            unsigned long long LargePage : 1; // Must be 1 (otherwise, this entry references an EPT page directory)
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Dirty : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Ignored0 : 1;
            unsigned long long Reserved0 : 9; // Must be zero
            unsigned long long PagePhysicalAddress : 31; // Physical address of the 2-MByte page referenced by this entry
            unsigned long long Ignored1 : 11;
            unsigned long long SuppressVe : 1; // Ignored if "EPT-violation #VE" VM-execution control is 0
        } Page2Mb;
        struct {
            unsigned long long ReadAccess : 1;
            unsigned long long WriteAccess : 1;
            unsigned long long ExecuteAccess : 1;
            unsigned long long Reserved0 : 4; // Must be zero
            unsigned long long LargePage : 1; // // Must be 0 (otherwise, this entry references a 2-MByte page)
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Ignored0 : 1;
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Ignored1 : 1;
            unsigned long long EptPtePhysicalAddress : 40;
            unsigned long long Ignored : 12;
        } Page4Kb;
    };
    static_assert(sizeof(EPT_PDE) == sizeof(unsigned long long), "Size of EPT_PDE != sizeof(unsigned long long)");

    union EPT_PTE {
        unsigned long long Value;
        struct {
            unsigned long long ReadAccess : 1;
            unsigned long long WriteAccess : 1;
            unsigned long long ExecuteAccess : 1;
            unsigned long long Type : 3;
            unsigned long long IgnorePat : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Dirty : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Ignored1 : 1;
            unsigned long long PagePhysicalAddress : 40;
            unsigned long long Ignored2 : 9;
            unsigned long long SubPageWritePermissions : 1; // Ignored if "sub-page write permissions for EPT" VM-execution control is 0
            unsigned long long Ignored3 : 1;
            unsigned long long SuppressVe : 1; // Ignored if "EPT-violation #VE" VM-execution control is 0
        } Page4Kb;
    };
    static_assert(sizeof(EPT_PTE) == sizeof(unsigned long long), "Size of EPT_PTE != sizeof(unsigned long long)");
}