#pragma once

namespace VMX
{
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
        VMCS_FIELD_PML_INDEX = 0x00000812,

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
        VMCS_FIELD_GUEST_IA32_RTIT_CTL_FULL = 0x00002814,
        VMCS_FIELD_GUEST_IA32_RTIT_CTL_HIGH = 0x00002815,

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
        VMCS_FIELD_GUEST_LINEAR_ADDRESS = 0x0000640A,

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
        VMCS_FIELD_GUEST_IA32_S_CET = 0x00006828,
        VMCS_FIELD_GUEST_SSP = 0x0000682A,
        VMCS_FIELD_GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR = 0x0000682C,

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
        VMCS_FIELD_HOST_RIP = 0x00006C16,
        VMCS_FIELD_HOST_IA32_S_CET = 0x00006C18,
        VMCS_FIELD_HOST_SSP = 0x00006C1A,
        VMCS_FIELD_HOST_IA32_INTERRUPT_SSP_TABLE_ADDR = 0x00006C1C,
    };

    enum class VMX_EXIT_REASON : unsigned int {
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
        EXIT_REASON_SPP_RELATED_EVENT = 66,
        EXIT_REASON_UMWAIT = 67,
        EXIT_REASON_TPAUSE = 68,
    };

    union MSR_BITMAP {
        unsigned char MsrBitmap[4096];
        struct {
            unsigned char Read00000000to00001FFF[1024];
            unsigned char ReadC0000000toC0001FFF[1024];
            unsigned char Write00000000to00001FFF[1024];
            unsigned char WriteC0000000toC0001FFF[1024];
        } Bitmap;
    };
    static_assert(sizeof(MSR_BITMAP) == 4096, "Size of MSR_BITMAP != 4096 bytes");

    enum VM_INSTRUCTION_ERROR : unsigned int {
        VmcallExecutedInVmxRootOperation = 1,
        VmclearWithInvalidPhysicalAddress = 2,
        VmclearWithVmxonPointer = 3,
        VmlaunchWithNonClearVmcs = 4,
        VmresumeWithNonLaunchedVmcs = 5,
        VmresumeAfterVmxoff = 6,
        VmentryWithInvalidControlFields = 7,
        VmentryWithInvalidHostStateFields = 8,
        VmptrldWithInvalidPhysicalAddress = 9,
        VmptrldWithVmxonPointer = 10,
        VmptrldWithIncorrectVmcsRevisionIdentifier = 11,
        VmreadVmwriteFromToUnsupportedVmcsComponent = 12,
        VmwriteToReadonlyVmcsComponent = 13,
        VmxonExecutedInVmxRootOperation = 15,
        VmentryWithInvalidExecutiveVmcsPointer = 16,
        VmentryWithNonLaunchedExecutiveVmcs = 17,
        VmentryWithExecutiveVmcsPointerNotVmxonPointer = 18,
        VmcallWithNonClearVmcs = 19,
        VmcallWithInvalidVmexitControlFields = 20,
        VmcallWithIncorrectMsegRevisionIdentifier = 22,
        VmxoffUnderDualMonitorTreatmentOfSmisAndSmm = 23,
        VmcallWithInvalidSmmMonitorFeatures = 24,
        VmentryWithInvalidVmExecutionControlFieldsInExecutiveVmcs = 25,
        VmentryWithEventsBlockedByMovSs = 26,
        InvalidOperandToInveptInvvpid = 28
    };

    union SEGMENT_ACCESS_RIGHTS {
        unsigned int Value;
        struct {
            unsigned int SegmentType : 4;
            unsigned int S : 1; // Descriptor type (0 = system, 1 = code or data)
            unsigned int DPL : 2; // Descriptor privilege level
            unsigned int P : 1; // Segment present
            unsigned int Reserved0 : 4;
            unsigned int AVL : 1; // Available for use by system software
            unsigned int L : 1; // Reserved except for CS, 64-bit mode active (for CS only)
            unsigned int DB : 1; // Default operation size (0 = 16-bit segment, 1 = 32-bit segment)
            unsigned int G : 1; // Granularity
            unsigned int SegmentUnusable : 1; // 0 = usable, 1 = unusable
            unsigned int Reserved1 : 15;
        } Bitmap;
    };
    static_assert(sizeof(SEGMENT_ACCESS_RIGHTS) == sizeof(unsigned int), "Size of SEGMENT_ACCESS_RIGHTS != sizeof(unsigned int)");

    // Consult with the IA32_VMX_PINBASED_CTLS and IA32_VMX_TRUE_PINBASED_CTLS
    // to determine how to set the reserved bits properly if you need it:
    union PIN_BASED_VM_EXECUTION_CONTROLS {
        unsigned int Value;
        struct {
            unsigned int ExternalInterruptExiting : 1;
            unsigned int ReservedBit1 : 1; // Must be 1
            unsigned int ReservedBit2 : 1; // Must be 1
            unsigned int NmiExiting : 1;
            unsigned int ReservedBit4 : 1; // Must be 1
            unsigned int VirtualNmis : 1;
            unsigned int ActivateVmxPreemptionTimer : 1;
            unsigned int ProcessPostedInterrupts : 1;
            unsigned int ReservedBit8 : 1;
            unsigned int ReservedBit9 : 1;
            unsigned int ReservedBit10 : 1;
            unsigned int ReservedBit11 : 1;
            unsigned int ReservedBit12 : 1;
            unsigned int ReservedBit13 : 1;
            unsigned int ReservedBit14 : 1;
            unsigned int ReservedBit15 : 1;
            unsigned int ReservedBit16 : 1;
            unsigned int ReservedBit17 : 1;
            unsigned int ReservedBit18 : 1;
            unsigned int ReservedBit19 : 1;
            unsigned int ReservedBit20 : 1;
            unsigned int ReservedBit21 : 1;
            unsigned int ReservedBit22 : 1;
            unsigned int ReservedBit23 : 1;
            unsigned int ReservedBit24 : 1;
            unsigned int ReservedBit25 : 1;
            unsigned int ReservedBit26 : 1;
            unsigned int ReservedBit27 : 1;
            unsigned int ReservedBit28 : 1;
            unsigned int ReservedBit29 : 1;
            unsigned int ReservedBit30 : 1;
            unsigned int ReservedBit31 : 1;
        } Bitmap;
    };
    static_assert(sizeof(PIN_BASED_VM_EXECUTION_CONTROLS) == sizeof(unsigned int), "Size of PIN_BASED_VM_EXECUTION_CONTROLS != sizeof(unsigned int)");

    // Consult with the IA32_VMX_PROCBASED_CTLS and IA32_VMX_TRUE_PROCBASED_CTLS
    // to determine how to set the reserved bits:
    union PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS {
        unsigned int Value;
        struct {
            unsigned int ReservedBit0 : 1;
            unsigned int ReservedBit1 : 1; // Must be 1
            unsigned int InterruptWindowExiting : 1;
            unsigned int UseTscOffsetting : 1;
            unsigned int ReservedBit4 : 1; // Must be 1
            unsigned int ReservedBit5 : 1; // Must be 1
            unsigned int ReservedBit6 : 1; // Must be 1
            unsigned int HltExiting : 1;
            unsigned int ReservedBit8 : 1; // Must be 1
            unsigned int InvlpgExiting : 1;
            unsigned int MwaitExiting : 1;
            unsigned int RdpmcExiting : 1;
            unsigned int RdtscExiting : 1;
            unsigned int ReservedBit13 : 1; // Must be 1
            unsigned int ReservedBit14 : 1; // Must be 1
            unsigned int Cr3LoadExiting : 1; // Must be 1
            unsigned int Cr3StoreExiting : 1; // Must be 1
            unsigned int ReservedBit17 : 1;
            unsigned int ReservedBit18 : 1;
            unsigned int Cr8LoadExiting : 1;
            unsigned int Cr8StoreExiting : 1;
            unsigned int UseTprShadow : 1;
            unsigned int NmiWindowExiting : 1;
            unsigned int MovDrExiting : 1;
            unsigned int UnconditionalIoExiting : 1;
            unsigned int UseIoBitmaps : 1;
            unsigned int ReservedBit26 : 1; // Must be 1
            unsigned int MonitorTrapFlag : 1;
            unsigned int UseMsrBitmaps : 1;
            unsigned int MonitorExiting : 1;
            unsigned int PauseExiting : 1;
            unsigned int ActivateSecondaryControls : 1;
        } Bitmap;
    };
    static_assert(sizeof(PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS) == sizeof(unsigned int), "Size of PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS != sizeof(unsigned int)");

    // Consult with the IA32_VMX_EXIT_CTLS and IA32_VMX_TRUE_EXIT_CTLS
    // to determine how to set the reserved bits:
    union VMEXIT_CONTROLS {
        unsigned int Value;
        struct {
            unsigned int ReservedBit0 : 1;
            unsigned int ReservedBit1 : 1;
            unsigned int SaveDebugControls : 1; // Whether DR7 and the IA32_DEBUGCTL are saved on VM exit
            unsigned int ReservedBit3 : 1;
            unsigned int ReservedBit4 : 1;
            unsigned int ReservedBit5 : 1;
            unsigned int ReservedBit6 : 1;
            unsigned int ReservedBit7 : 1;
            unsigned int ReservedBit8 : 1;
            unsigned int HostAddressSpaceSize : 1; // Whether a logical processor is in 64-bit mode after the next VM exit, its value is loaded into CS.L, IA32_EFER.LME and IA32_EFER.LMA on every VM exit
            unsigned int ReservedBit10 : 1;
            unsigned int ReservedBit11 : 1;
            unsigned int LoadIa32PerfGlobalCtrl : 1; // Whether the IA32_PERF_GLOBAL_CTL is loaded on VM exit
            unsigned int ReservedBit13 : 1;
            unsigned int ReservedBit14 : 1;
            unsigned int AcknowledgeInterruptOnExit : 1;
            unsigned int ReservedBit16 : 1;
            unsigned int ReservedBit17 : 1;
            unsigned int SaveIa32Pat : 1;
            unsigned int LoadIa32Pat : 1;
            unsigned int SaveIa32Efer : 1;
            unsigned int LoadIa32Efer : 1;
            unsigned int SaveVmxPreemptionTimerValue : 1;
            unsigned int ClearIa32Bndcfgs : 1;
            unsigned int ConcealVmxFromPt : 1;
            unsigned int ClearIa32RtitCtl : 1;
            unsigned int ReservedBit26 : 1;
            unsigned int ReservedBit27 : 1;
            unsigned int LoadCetState : 1;
            unsigned int ReservedBit29 : 1;
            unsigned int ReservedBit30 : 1;
            unsigned int ReservedBit31 : 1;
        } Bitmap;
    };
    static_assert(sizeof(VMEXIT_CONTROLS) == sizeof(unsigned int), "Size of VMEXIT_CONTROLS != sizeof(unsigned int)");

    // Consult with the IA32_VMX_ENTRY_CTLS and IA32_VMX_TRUE_ENTRY_CTLS
    // to determine how to set the reserved bits:
    union VMENTRY_CONTROLS {
        unsigned int Value;
        struct {
            unsigned int ReservedBit0 : 1;
            unsigned int ReservedBit1 : 1;
            unsigned int LoadDebugControls : 1; // Whether DR7 and the IA32_DEBUGCTL are loaded on VM entry
            unsigned int ReservedBit3 : 1;
            unsigned int ReservedBit4 : 1;
            unsigned int ReservedBit5 : 1;
            unsigned int ReservedBit6 : 1;
            unsigned int ReservedBit7 : 1;
            unsigned int ReservedBit8 : 1;
            unsigned int Ia32ModeGuest : 1; // Whether a logical processor is in IA-32e mode on VM entry, its value loaded into IA32_EFER.LMA as part of VM entry
            unsigned int EntryToSmm : 1;
            unsigned int DeactivateDualMonitorTreatment : 1;
            unsigned int ReservedBit12 : 1;
            unsigned int LoadIa32PerfGlobalCtrl : 1;
            unsigned int LoadIa32Pat : 1;
            unsigned int LoadIa32Efer : 1;
            unsigned int LoadIa32BndCfgs : 1;
            unsigned int ConcealVmxFromPt : 1;
            unsigned int LoadIa32RtitCtl : 1;
            unsigned int ReservedBit19 : 1;
            unsigned int LoadCetState : 1;
            unsigned int ReservedBit21 : 1;
            unsigned int ReservedBit22 : 1;
            unsigned int ReservedBit23 : 1;
            unsigned int ReservedBit24 : 1;
            unsigned int ReservedBit25 : 1;
            unsigned int ReservedBit26 : 1;
            unsigned int ReservedBit27 : 1;
            unsigned int ReservedBit28 : 1;
            unsigned int ReservedBit29 : 1;
            unsigned int ReservedBit30 : 1;
            unsigned int ReservedBit31 : 1;
        } Bitmap;
    };
    static_assert(sizeof(VMENTRY_CONTROLS) == sizeof(unsigned int), "Size of VMENTRY_CONTROLS != sizeof(unsigned int)");

    // Consult with the IA32_VMX_PROCBASED_CTLS2 to determine
    // which bits may be set to 1:
    union SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS {
        unsigned int Value;
        struct {
            unsigned int VirtualizeApicAccesses : 1;
            unsigned int EnableEpt : 1;
            unsigned int DescriptorTableExiting : 1;
            unsigned int EnableRdtscp : 1;
            unsigned int Virtualizex2ApicMode : 1;
            unsigned int EnableVpid : 1;
            unsigned int WbinvdExiting : 1;
            unsigned int UnrestrictedGuest : 1;
            unsigned int ApicRegisterVirtualization : 1;
            unsigned int VirtualInterruptDelivery : 1;
            unsigned int PauseLoopExiting : 1;
            unsigned int RdrandExiting : 1;
            unsigned int EnableInvpcid : 1;
            unsigned int EnableVmFunctions : 1;
            unsigned int VmcsShadowing : 1;
            unsigned int EnableEnclsExiting : 1;
            unsigned int RdseedExiting : 1;
            unsigned int EnablePml : 1;
            unsigned int EptViolation : 1;
            unsigned int ConcealVmxFromPt : 1;
            unsigned int EnableXsavesXrstors : 1;
            unsigned int ReservedBit21 : 1; // Reserved to 0
            unsigned int ModBasedExecuteControlForEpt : 1;
            unsigned int SubPageWritePermissionsForEpt : 1;
            unsigned int IntelPtUsesGuestPhysicalAddresses : 1;
            unsigned int UseTscScaling : 1;
            unsigned int EnableUserWaitAndPause : 1;
            unsigned int ReservedBit27 : 1; // Reserved to 0
            unsigned int EnableEnclvExiting : 1;
            unsigned int ReservedBit29 : 1; // Reserved to 0
            unsigned int ReservedBit30 : 1; // Reserved to 0
            unsigned int ReservedBit31 : 1; // Reserved to 0
        } Bitmap;
    };
    static_assert(sizeof(SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS) == sizeof(unsigned int), "Size of SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS != sizeof(unsigned int)");

    enum class INTERRUPTION_TYPE {
        ExternalInterrupt = 0,
        Reserved = 1,
        NonMaskableInterrupt = 2, // NMI
        HardwareException = 3, // e.g. #PF
        SoftwareInterrupt = 4, // INT n, #BP, #OF (overflow)
        PrivilegedSoftwareException = 5, // INT1 (#DB)
        SoftwareException = 6, // INT3 or INT0
        OtherEvent = 7
    };

    union VMENTRY_INTERRUPTION_INFORMATION {
        unsigned int Value;
        struct {
            unsigned int VectorOfInterruptOrException : 8; // Which entry in the IDT is used or which other event is injected
            unsigned int InterruptionType : 3; // See the INTERRUPTION_TYPE enum above
            unsigned int DeliverErrorCode : 1; // 0 - do not deliver, 1 - deliver (pushed an error code on the guest stack)
            unsigned int Reserved : 19;
            unsigned int Valid : 1;
        } Bitmap;
    };
    static_assert(sizeof(VMENTRY_INTERRUPTION_INFORMATION) == sizeof(unsigned int), "Size of VMENTRY_INTERRUPTION_INFORMATION != sizeof(unsigned int)");

    union EXIT_REASON {
        unsigned int Value;
        struct {
            unsigned int BasicExitReason : 16; // See the VMX_EXIT_REASON enum above
            unsigned int AlwaysClearedToZero : 1;
            unsigned int ReservedAsZero0 : 10;
            unsigned int VmexitWasIncidentToEnclaveMode : 1;
            unsigned int PendingMtfVmexit : 1;
            unsigned int VmexitFromVmxRootOperation : 1;
            unsigned int ReservedAsZero1 : 1;
            unsigned int VmentryFailure : 1; // 0 - true VM exit, 1 - VM-entry failure
        } Bitmap;
    };
    static_assert(sizeof(EXIT_REASON) == sizeof(unsigned int), "Size of EXIT_REASON != sizeof(unsigned int)");

    union VMEXIT_INTERRUPTION_INFORMATION {
        unsigned int Value;
        struct {
            unsigned int VectorOfInterruptOrException : 8; // Which entry in the IDT is used or which other event is injected
            unsigned int InterruptionType : 3; // See the INTERRUPTION_TYPE enum above
            unsigned int ErrorCodeValid : 1; // 0 - invalid, 1 - valid
            unsigned int NmiUnblockingDueToIret : 1;
            unsigned int Reserved : 18;
            unsigned int Valid : 1;
        } Bitmap;
    };
    static_assert(sizeof(VMEXIT_INTERRUPTION_INFORMATION) == sizeof(unsigned int), "Size of VMEXIT_INTERRUPTION_INFORMATION != sizeof(unsigned int)");

    union IDT_VECTORING_INFORMATION {
        unsigned int Value;
        struct {
            unsigned int VectorOfInterruptOrException : 8; // Which entry in the IDT is used or which other event is injected
            unsigned int InterruptionType : 3; // See the INTERRUPTION_TYPE enum above
            unsigned int Undefined : 1; // 0 - invalid, 1 - valid
            unsigned int NmiUnblockingDueToIret : 1;
            unsigned int Reserved : 18;
            unsigned int Valid : 1;
        } Bitmap;
    };
    static_assert(sizeof(IDT_VECTORING_INFORMATION) == sizeof(unsigned int), "Size of IDT_VECTORING_INFORMATION != sizeof(unsigned int)");

    union EXIT_QUALIFICATION {
        unsigned long long Value;
        struct {
            unsigned long long BreakpointConditions : 4; // B0..B3 conditions in DR7
            unsigned long long Reserved0 : 9;
            unsigned long long BD : 1; // Debug register access detected
            unsigned long long BS : 1; // Single instruction (RFLAGS.TF == 1 && IA32_DEBUGCTL.BTF == 0) or branch (RFLAGS.TF == IA32_DEBUGCTL.BTF == 1)
            unsigned long long Reserved1 : 1;
            unsigned long long RTM : 1; // #DB or #BP occured inside an RTM region
            unsigned long long Reserved2 : 47;
        } DebugExceptions;
        struct {
            unsigned long long LinearAddress;
        } Invlpg;
        struct {
            unsigned long long InstructionDisplacementField;
        } Invept, Invpcid, Invvpid,
          Lgdt, Lidt, Lldt, Ltr,
          Sgdt, Sidt, Sldt, Str,
          Vmclear, Vmptrld, Vmptrst, Vmread, Vmwrite, Vmxon,
          Xrstors, Xsaves;
        struct {
            unsigned long long SelectorOfTss : 16; // To which the guest attempted to switch
            unsigned long long Reserved0 : 14;
            unsigned long long SourceOfTaskSwitchInitiation : 2; // 0 = CALL, 1 = IRET, 2 = JMP, 3 = Task gate in IDT
            unsigned long long Reserved1 : 32;
        } TaskSwitch;
        struct {
            unsigned long long NumberOfControlRegister : 4; // 0 for CLTS and LMSW
            unsigned long long AccessType : 2; // 0 = MOV to CR, 1 = MOV from CR, 2 = CLTS, 3 = LMSW
            unsigned long long LmswOperandType : 1; // 0 = register, 1 = memory (0 for MOV CR and CLTS)
            unsigned long long Reserved0 : 1;
            unsigned long long Register : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned long long Reserved1 : 4;
            unsigned long long LmswSourceData : 16; // For CLTS and MOV CR cleared to 0
            unsigned long long Reserved2 : 32;
        } ControlRegistersAccess;
        struct {
            unsigned long long NumberOfDebugRegister : 3;
            unsigned long long Reserved0 : 1;
            unsigned long long DirectionOfAccess : 1; // 0 = MOV to DR, 1 = MOV from DR
            unsigned long long Reserved1 : 3;
            unsigned long long Register : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned long long Reserved2 : 52;
        } MovDr;
        struct {
            unsigned long long SizeOfAccess : 3; // 0 = 1-byte, 1 = 2-byte, 3 = 4-byte
            unsigned long long Direction : 1; // 0 = OUT, 1 = IN
            unsigned long long StringInstruction : 1; // 0 = not string instruction, 1 = string instruction
            unsigned long long RepPrefixed : 1; // 0 = no REP, 1 = prefixed with REP
            unsigned long long OperandEncoding : 1; // 0 = DX, 1 = immediate
            unsigned long long Reserved0 : 9;
            unsigned long long PortNumber : 16; // As specified in DX or in an immediate operand
            unsigned long long Reserved1 : 32;
        } IoInstructions;
        struct {
            unsigned long long OffsetInApicPage : 12; // Undefined if the APIC-access VM exit is due a guest-physical access
            unsigned long long AccessType : 4; // 0 = linear access for a data read during instruction execution
                                               // 1 = linear access for a data write during instruction execution
                                               // 2 = linear access for an instruction fetch
                                               // 3 = linear access (read or write) during event delivery
                                               // 10 = guest-physical access during event delivery
                                               // 15 = guest-physical access for an instruction fetch or during instruction execution
            unsigned long long AsynchronousAndNotEventDelivery : 1;
            unsigned long long Reserved0 : 47;
        } ApicAccess;
        struct {
            unsigned long long AccessedRead : 1;
            unsigned long long AccessedWrite : 1;
            unsigned long long AccessedExecute : 1;
            unsigned long long GuestPhysicalReadable : 1;
            unsigned long long GuestPhysicalWriteable : 1;
            unsigned long long GuestPhysicalExecutable : 1;
            unsigned long long GuestPhysicalUserExecutable : 1;
            unsigned long long GuestLinearAddressFieldIsValid : 1;
            unsigned long long AccessToGuestPhysicalAddress : 1; // Only valid if 'GuestLinearAddressFieldIsValid' equals 1
            unsigned long long UserModeLinearAddress : 1;
            unsigned long long TranslatesToReadWritePage : 1; // 0 = Readonly, 1 = ReadWrite
            unsigned long long TranslatesToNonExecutablePage : 1; // 0 = Executable, 1 = Non-executable
            unsigned long long NmiUnblockingDueToIret : 1;
            unsigned long long IsShadowStackAccess : 1;
            unsigned long long TranslatesToShadowStackPage : 1;
            unsigned long long Reserved0 : 1;
            unsigned long long AsynchronousAndNotEventDelivery : 1;
            unsigned long long Reserved1 : 47;
        } EptViolations;
    };
    static_assert(sizeof(EXIT_QUALIFICATION) == sizeof(unsigned long long), "Size of EXIT_QUALIFICATIOn != sizeof(unsigned long long)");

    // Extended-Page-Table Pointer:
    union EPTP {
        unsigned long long Value;
        struct {
            unsigned long long EptMemoryType : 3; // 0 = Uncacheable, 6 = Write-back, other values are reserved
            unsigned long long PageWalkLength : 3; // This value is 1 less than the EPT page-walk length
            unsigned long long AccessedAndDirtyFlagsSupport : 1; // Setting this control to 1 enables accessed and dirty flags for EPT (check IA32_VMX_EPT_VPID_CAP)
            unsigned long long EnforcementOfAccessRightsForSupervisorShadowStack : 1;
            unsigned long long Reserved0 : 4;
            unsigned long long EptPml4ePhysicalPfn : 52; // Maximum supported physical address width: CPUID(EAX = 0x80000008) -> EAX[7:0]
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
            unsigned long long EptPdptePhysicalPfn : 40; // Maximum supported physical address width: CPUID(EAX = 0x80000008) -> EAX[7:0]
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
            unsigned long long Reserved0 : 4;
            unsigned long long LargePage : 1;
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Reserved1 : 1;
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Reserved2 : 53;
        } Generic;
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
            unsigned long long PagePhysicalPfn : 22; // Physical address of the 1-GByte page referenced by this entry
            unsigned long long Ignored1 : 8;
            unsigned long long SupervisorShadowStackAccess : 1; // Ignored if bit 7 of EPTP is 0
            unsigned long long Ignored2 : 2;
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
            unsigned long long EptPdePhysicalPfn : 40;
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
            unsigned long long Reserved0 : 4; // Must be zero
            unsigned long long LargePage : 1;
            unsigned long long Accessed : 1; // Ignored if bit 6 of EPTP is 0
            unsigned long long Reserved1 : 1;
            unsigned long long UserModeExecuteAccess : 1; // Ignored if "mode-based execute control for EPT" VM-execution control is 0
            unsigned long long Reserved2 : 53;
        } Generic;
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
            unsigned long long PagePhysicalPfn : 31; // Physical address of the 2-MByte page referenced by this entry
            unsigned long long Ignored1 : 8;
            unsigned long long SupervisorShadowStackAccess : 1; // Ignored if bit 7 of EPTP is 0
            unsigned long long Ignored2 : 2;
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
            unsigned long long EptPtePhysicalPfn : 40;
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
            unsigned long long PagePhysicalPfn : 40;
            unsigned long long Ignored2 : 8;
            unsigned long long SupervisorShadowStackAccess : 1; // Ignored if bit 7 of EPTP is 0
            unsigned long long SubPageWritePermissions : 1; // Ignored if "sub-page write permissions for EPT" VM-execution control is 0
            unsigned long long Ignored3 : 1;
            unsigned long long SuppressVe : 1; // Ignored if "EPT-violation #VE" VM-execution control is 0
        } Page4Kb;
    };
    static_assert(sizeof(EPT_PTE) == sizeof(unsigned long long), "Size of EPT_PTE != sizeof(unsigned long long)");

    enum class INVEPT_TYPE : unsigned int {
        SingleContextInvalidation = 1,
        GlobalInvalidation = 2
    };

    struct INVEPT_DESCRIPTOR {
        unsigned long long Eptp;
        unsigned long long Reserved;
    };
    static_assert(sizeof(INVEPT_DESCRIPTOR) == 2 * sizeof(unsigned long long), "Size of INVEPT_DESCRIPTOR != 2 * sizeof(unsigned long long)");

    enum class INVVPID_TYPE : unsigned int {
        IndividualAddressInvalidation = 0,
        SingleContextInvalidation = 1,
        AllContextsInvalidation = 2,
        SingleContextInvalidationExceptGlobal = 3
    };

    struct INVVPID_DESCRIPTOR {
        unsigned long long Vpid : 16;
        unsigned long long Reserved : 48;
        unsigned long long LinearAddress;
    };
    static_assert(sizeof(INVVPID_DESCRIPTOR) == 2 * sizeof(unsigned long long), "Size of INVVPID_DESCRIPTOR != 2 * sizeof(unsigned long long)");

    union INSTRUCTION_INFORMATION_FIELD {
        unsigned int Value;
        struct {
            unsigned int Undefined0 : 7;
            unsigned int AddressSize : 3; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int Undefined1 : 5;
            unsigned int SegmentRegister : 3; // 0 = ES, 1 = CS, 2 = SS, 3 = DS, 4 = FS, 5 = GS
            unsigned int Undefined2 : 14;
        } Ins, Outs;
        struct {
            unsigned int Scaling : 2; // 0 = No scaling, 1 = Scale by 2, 2 = Scale by 4, 3 = Scale by 8
            unsigned int Undefined0 : 5;
            unsigned int AddressSize : 3; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int ClearedTo0 : 1;
            unsigned int Undefined1 : 4;
            unsigned int SegmentRegister : 3; // 0 = ES, 1 = CS, 2 = SS, 3 = DS, 4 = FS, 5 = GS
            unsigned int IndexReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int IndexRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int BaseReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int BaseRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int Reg2 : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
        } Invept, Invpcid, Invvpid;
        struct {
            unsigned int Scaling : 2; // 0 = No scaling, 1 = Scale by 2, 2 = Scale by 4, 3 = Scale by 8
            unsigned int Undefined0 : 5;
            unsigned int AddressSize : 3; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int ClearedTo0 : 1;
            unsigned int OperandSize : 1; // 0 = 16-bit, 1 = 32-bit
            unsigned int Undefined1 : 3;
            unsigned int SegmentRegister : 3; // 0 = ES, 1 = CS, 2 = SS, 3 = DS, 4 = FS, 5 = GS
            unsigned int IndexReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int IndexRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int BaseReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int BaseRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int InstructionIdentity : 2; // 0 = SGDT, 1 = SIDT, 2 = LGDT, 3 = LIDT
            unsigned int Undefined2 : 2;
        } Lidt, Lgdt, Sidt, Sgdt;
        struct {
            unsigned int Scaling : 2; // 0 = No scaling, 1 = Scale by 2, 2 = Scale by 4, 3 = Scale by 8
            unsigned int Undefined0 : 1;
            unsigned int Reg1 : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int AddressSize : 3; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int MemReg : 1; // 0 = Memory, 1 = Register
            unsigned int Undefined1 : 4;
            unsigned int SegmentRegister : 3; // 0 = ES, 1 = CS, 2 = SS, 3 = DS, 4 = FS, 5 = GS
            unsigned int IndexReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int IndexRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int BaseReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int BaseRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int InstructionIdentity : 2; // 0 = SLDT, 1 = STR, 2 = LLDT, 3 = LTR
            unsigned int Undefined2 : 2;
        } Lldt, Ltr, Sldt, Str;
        struct {
            unsigned int Undefined0 : 3;
            unsigned int OperandRegister : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int Undefined1 : 4;
            unsigned int OperandSize : 2; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int Undefined2 : 19;
        } Rdrand, Rdseed, Tpause, Umwait;
        struct {
            unsigned int Scaling : 2; // 0 = No scaling, 1 = Scale by 2, 2 = Scale by 4, 3 = Scale by 8
            unsigned int Undefined0 : 5;
            unsigned int AddressSize : 3; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int ClearedTo0 : 1;
            unsigned int Undefined1 : 4;
            unsigned int SegmentRegister : 3; // 0 = ES, 1 = CS, 2 = SS, 3 = DS, 4 = FS, 5 = GS
            unsigned int IndexReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int IndexRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int BaseReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int BaseRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int Undefined2 : 4;
        } Vmclear, Vmptrld, Vmptrst, Vmxon, Xrstors, Xsaves;
        struct {
            unsigned int Scaling : 2; // 0 = No scaling, 1 = Scale by 2, 2 = Scale by 4, 3 = Scale by 8
            unsigned int Undefined0 : 1;
            unsigned int Reg1 : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int AddressSize : 3; // 0 = 16-bit, 1 = 32-bit, 2 = 64-bit
            unsigned int MemReg : 1; // 0 = Memory, 1 = Register
            unsigned int Undefined1 : 4;
            unsigned int SegmentRegister : 3; // 0 = ES, 1 = CS, 2 = SS, 3 = DS, 4 = FS, 5 = GS
            unsigned int IndexReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int IndexRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int BaseReg : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
            unsigned int BaseRegInvalid : 1; // 0 = Valid, 1 = Invalid
            unsigned int Reg2 : 4; // 0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, 4 = RSP, 5 = RBP, 6 = RSI, 7 = RDI, 8..15 = R8..R15
        } Vmread, Vmwrite;
    };
    static_assert(sizeof(INSTRUCTION_INFORMATION_FIELD) == sizeof(unsigned int), "Size of INSTRUCTION_INFORMATION_FIELD != sizeof(unsigned int)");
}