#pragma once

// Hyper-V conformance requirements:
// https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs

namespace HyperV
{
    // Version 6.0b (Feb. 2020)

    union HYPERCALL_INPUT_VALUE
    {
        unsigned long long Value;
        struct
        {
            unsigned long long CallCode : 16; // HYPERCALL_CODE
            unsigned long long Fast : 1;
            unsigned long long VariableHeaderSize : 9;
            unsigned long long IsNested : 1;
            unsigned long long Reserved0 : 5;
            unsigned long long RepCount : 12;
            unsigned long long Reserved1 : 4;
            unsigned long long RepStartIndex : 12;
            unsigned long long Reserved2 : 4;
        } Bitmap;
    };
    static_assert(sizeof(HYPERCALL_INPUT_VALUE) == sizeof(unsigned long long), "Size of HYPERCALL_INPUT_VALUE != sizeof(unsigned long long)");

    union HYPERCALL_RESULT_VALUE
    {
        unsigned long long Value;
        struct
        {
            unsigned long long Result : 16; // HV_STATUS
            unsigned long long Reserved0 : 16;
            unsigned long long RepsComplete : 12;
            unsigned long long Reserved1 : 20;
        } Bitmap;
    };
    static_assert(sizeof(HYPERCALL_RESULT_VALUE) == sizeof(unsigned long long), "Size of HYPERCALL_RESULT_VALUE != sizeof(unsigned long long)");

    enum class HYPERCALL_CODE
    {
        HvSwitchVirtualAddressSpace = 0x0001,
        HvFlushVirtualAddressSpace = 0x0002,
        HvFlushVirtualAddressList = 0x0003,
        HvGetLogicalProcessorRunTime = 0x0004,
        // 0x0005..0x0007 are reserved
        HvCallNotifyLongSpinWait = 0x0008,
        HvCallParkedVirtualProcessors = 0x0009,
        HvCallSyntheticClusterIpi = 0x000B,
        HvCallModifyVtlProtectionMask = 0x000C,
        HvCallEnablePartitionVtl = 0x000D,
        HvCallDisablePartitionVtl = 0x000E,
        HvCallEnableVpVtl = 0x000F,
        HvCallDisableVpVtl = 0x0010,
        HvCallVtlCall = 0x0011,
        HvCallVtlReturn = 0x0012,
        HvCallFlushVirtualAddressSpaceEx = 0x0013,
        HvCallFlushVirtualAddressListEx = 0x0014,
        HvCallSendSyntheticClusterIpiEx = 0x0015,
        // 0x0016..0x003F are reserved
        HvCreatePartition = 0x0040,
        HvInitializePartition = 0x0041,
        HvFinalizePartition = 0x0042,
        HvDeletePartition = 0x0043,
        HvGetPartitionProperty = 0x0044,
        HvSetPartitionProperty = 0x0045,
        HvGetPartitionId = 0x0046,
        HvGetNextChildPartition = 0x0047,
        HvDepositMemory = 0x0048,
        HvWithdrawMemory = 0x0049,
        HvGetMemoryBalance = 0x004A,
        HvMapGpaPages = 0x004B,
        HvUnmapGpaPages = 0x004C,
        HvInstallIntercept = 0x004D,
        HvCreateVp = 0x004E,
        HvDeleteVp = 0x004F,
        HvGetVpRegisters = 0x0050,
        HvSetVpRegisters = 0x0051,
        HvTranslateVirtualAddress = 0x0052,
        HvReadGpa = 0x0053,
        HvWriteGpa = 0x0054,
        // 0x0055 is deprecated
        HvClearVirtualInterrupt = 0x0056,
        // 0x0057 is deprecated
        HvDeletePort = 0x0058,
        HvConnectPort = 0x0059,
        HvGetPortProperty = 0x005A,
        HvDisconnectPort = 0x005B,
        HvPostMessage = 0x005C,
        HvSignalEvent = 0x005D,
        HvSavePartitionState = 0x005E,
        HvRestorePartitionState = 0x005F,
        HvInitializeEventLogBufferGroup = 0x0060,
        HvFinalizeEventLogBufferGroup = 0x0061,
        HvCreateEventLogBuffer = 0x0062,
        HvDeleteEventLogBuffer = 0x0063,
        HvMapEventLogBuffer = 0x0064,
        HvUnmapEventLogBuffer = 0x0065,
        HvSetEventLogGroupSources = 0x0066,
        HvReleaseEventLogBuffer = 0x0067,
        HvFlushEventLogBuffer = 0x0068,
        HvPostDebugData = 0x0069,
        HvRetrieveDebugData = 0x006A,
        HvResetDebugSession = 0x006B,
        HvMapStatsPage = 0x006C,
        HvUnmapStatsPage = 0x006D,
        HvCallMapSparseGpaPages = 0x006E,
        HvCallSetSystemProperty = 0x006F,
        HvCallSetPortProperty = 0x0070,
        // 0x0071..0x0075 are reserved
        HvCallAddLogicalProcessor = 0x0076,
        HvCallRemoveLogicalProcessor = 0x0077,
        HvCallQueryNumaDistance = 0x0078,
        HvCallSetLogicalProcessorProperty = 0x0079,
        HvCallGetLogicalProcessorProperty = 0x007A,
        HvCallGetSystemProperty = 0x007B,
        HvCallMapDeviceInterrupt = 0x007C,
        HvCallUnmapDeviceInterrupt = 0x007D,
        HvCallRetargetDeviceInterrupt = 0x007E,
        // 0x007F is reserved
        HvCallMapDevicePages = 0x0080,
        HvCallUnmapDevicePages = 0x0081,
        HvCallAttachDevice = 0x0082,
        HvCallDetachDevice = 0x0083,
        HvCallNotifyStandbyTransition = 0x0084,
        HvCallPrepareForSleep = 0x0085,
        HvCallPrepareForHibernate = 0x0086,
        HvCallNotifyPartitionEvent = 0x0087,
        HvCallGetLogicalProcessorRegisters = 0x0088,
        HvCallSetLogicalProcessorRegisters = 0x0089,
        HvCallQueryAssotiatedLpsforMca = 0x008A,
        HvCallNotifyRingEmpty = 0x008B,
        HvCallInjectSyntheticMachineCheck = 0x008C,
        HvCallScrubPartition = 0x008D,
        HvCallCollectLivedump = 0x008E,
        HvCallDisableHypervisor = 0x008F,
        HvCallModifySparseGpaPages = 0x0090,
        HvCallRegisterInterceptResult = 0x0091,
        HvCallUnregisterInterceptResult = 0x0092,
        HvCallAssertVirtualInterrupt = 0x0094,
        HvCallCreatePort = 0x0095,
        HvCallConnectPort = 0x0096,
        HvCallGetSpaPageList = 0x0097,
        // 0x0098 is reserved
        HvCallStartVirtualProcessor = 0x009A,
        HvCallGetVpIndexFromApicId = 0x009A,
        // 0x009A..0x00AE are reserved
        HvCallFlushGuestPhysicalAddressSpace = 0x00AF,
        HvCallFlushGuestPhysicalAddressList = 0x00B0
    };

    enum class HV_STATUS
    {
        HV_STATUS_SUCCESS = 0x0000,
        // 0x0001 is reserved
        HV_STATUS_INVALID_HYPERCALL_CODE = 0x0002,
        HV_STATUS_INVALID_HYPERCALL_INPUT = 0x0003,
        HV_STATUS_INVALID_ALIGNMENT = 0x0004,
        HV_STATUS_INVALID_PARAMETER = 0x0005,
        HV_STATUS_ACCESS_DENIED = 0x0006,
        HV_STATUS_INVALID_PARTITION_STATE = 0x0007,
        HV_STATUS_OPERATION_DENIED = 0x0008,
        HV_STATUS_UNKNOWN_PROPERTY = 0x0009,
        HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE = 0x000A,
        HV_STATUS_INSUFFICIENT_MEMORY = 0x000B,
        HV_STATUS_PARTITION_TOO_DEEP = 0x000C,
        HV_STATUS_INVALID_PARTITION_ID = 0x000D,
        HV_STATUS_INVALID_VP_INDEX = 0x000E,
        // 0x000F..0x0010 are reserved
        HV_STATUS_INVALID_PORT_ID = 0x0011,
        HV_STATUS_INVALID_CONNECTION_ID = 0x0012,
        HV_STATUS_INSUFFICIENT_BUFFERS = 0x0013,
        HV_STATUS_NOT_ACKNOWLEDGED = 0x0014,
        HV_STATUS_INVALID_VP_STATE = 0x0015,
        HV_STATUS_ACKNOWLEDGED = 0x0016,
        HV_STATUS_INVALID_SAVE_REStORE_STATE = 0x0017,
        HV_STATUS_INVALID_SYNIC_STATE = 0x0018,
        HV_STATUS_OBJECT_IN_USE = 0x0019,
        HV_STATUS_INVALID_PROXIMITY_DOMAIN_INFO = 0x001A,
        HV_STATUS_NO_DATA = 0x001B,
        HV_STATUS_INACTIVE = 0x001C,
        HV_STATUS_NO_RESOURCES = 0x001D,
        HV_STATUS_FEATURE_UNAVAILABLE = 0x001E,
        HV_STATUS_PARTIAL_PACKET = 0x001F,
        HV_STATUS_PROCESSOR_FEATURE_NOT_SUPPORTED = 0x0020,
        HV_STATUS_PROCESSOR_CACHE_LINE_FLUSH_SIZE_INCOMPATIBLE = 0x0030,
        HV_STATUS_INSUFFICIENT_BUFFER = 0x0033,
        HV_STATUS_INCOMPATIBLE_PROCESSOR = 0x0037,
        HV_STATUS_INSUFFICIENT_DEVICE_DOMAINS = 0x0038,
        HV_STATUS_CPUID_FEATURE_VALIDATION_ERROR = 0x003C,
        HV_STATUS_CPUID_XSAVE_FEATURE_VALIDATION_ERROR = 0x003D,
        HV_STATUS_PROCESSOR_STARTUP_TIMEOUT = 0x003E,
        HV_STATUS_SMX_ENABLED = 0x003F,
        HV_STATUS_INVALID_LP_INDEX = 0x0041,
        HV_STATUS_INVALID_REGISTER_VALUE = 0x0050,
        HV_STATUS_NX_NOT_DETECTED = 0x0055,
        HV_STATUS_INVALID_DEVICE_ID = 0x0057,
        HV_STATUS_INVALID_DEVICE_STATE = 0x0058,
        HV_STATUS_PENDING_PAGE_REQUESTS = 0x0059,
        HV_STATUS_PAGE_REQUEST_INVALID = 0x0060,
        HV_STATUS_OPERATION_FAILED = 0x0071,
        HV_STATUS_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE = 0x0072,
    };

    enum class CPUID
    {
        MAX_LEAF_NUMBER_AND_VENDOR_ID = 0x40000000,
        INTERFACE_SIGNATURE = 0x40000001,
        SYSTEM_IDENTITY = 0x40000002,
        FEATURE_IDENTIFICATION = 0x40000003,
        IMPLEMENTATION_RECOMMENDATIONS = 0x40000004,
        IMPLEMENTATION_LIMITS = 0x40000005,
        IMPLEMENTATION_HARDWARE_FEATURES = 0x40000006,
        CPU_MANAGEMENT_FEATURES = 0x40000007,
        SVM_FEATURES = 0x40000008,
        NESTED_HYPERVISOR_FEATURE_IDENTIFICATION = 0x40000009,
        NESTED_VIRTUALIZATION_FEATURES = 0x4000000A,
    };

    enum class HYPERVISOR_SYNTHETIC_MSRS
    {
        HV_X64_MSR_GUEST_OS_ID = 0x40000000,
        HV_X64_MSR_HYPERCALL   = 0x40000001,
        HV_X64_MSR_VP_INDEX    = 0x40000002,
        HV_X64_MSR_RESET = 0x40000003,
        HV_X64_MSR_VP_RUNTIME = 0x40000010,
        HV_X64_MSR_TIME_REF_COUNT = 0x40000020,
        HV_X64_MSR_REFERENCE_TSC = 0x40000021,
        HV_X64_MSR_TSC_FREQUENCY = 0x40000022,
        HV_X64_MSR_APIC_FREQUENCY = 0x40000023,
        HV_X64_MSR_NPIEP_CONFIG = 0x40000040,
        HV_X64_MSR_EOI = 0x40000070,
        HV_X64_MSR_ICR = 0x40000071,
        HV_X64_MSR_TPR = 0x40000072,
        HV_X64_MSR_VP_ASSIST_PAGE = 0x40000073,
        HV_X64_MSR_SCONTROL = 0x40000080,
        HV_X64_MSR_SVERSION = 0x40000081,
        HV_X64_MSR_SIEFP = 0x40000082,
        HV_X64_MSR_SIMP = 0x40000083,
        HV_X64_MSR_EOM = 0x40000084,
        HV_X64_MSR_SINT0 = 0x40000090,
        HV_X64_MSR_SINT1 = 0x40000091,
        HV_X64_MSR_SINT2 = 0x40000092,
        HV_X64_MSR_SINT3 = 0x40000093,
        HV_X64_MSR_SINT4 = 0x40000094,
        HV_X64_MSR_SINT5 = 0x40000095,
        HV_X64_MSR_SINT6 = 0x40000096,
        HV_X64_MSR_SINT7 = 0x40000097,
        HV_X64_MSR_SINT8 = 0x40000098,
        HV_X64_MSR_SINT9 = 0x40000099,
        HV_X64_MSR_SINT10 = 0x4000009A,
        HV_X64_MSR_SINT11 = 0x4000009B,
        HV_X64_MSR_SINT12 = 0x4000009C,
        HV_X64_MSR_SINT13 = 0x4000009D,
        HV_X64_MSR_SINT14 = 0x4000009E,
        HV_X64_MSR_SINT15 = 0x4000009F,
        HV_X64_MSR_STIMER0_CONFIG = 0x400000B0,
        HV_X64_MSR_STIMER0_COUNT = 0x400000B1,
        HV_X64_MSR_STIMER1_CONFIG = 0x400000B2,
        HV_X64_MSR_STIMER1_COUNT = 0x400000B3,
        HV_X64_MSR_STIMER2_CONFIG = 0x400000B4,
        HV_X64_MSR_STIMER2_COUNT = 0x400000B5,
        HV_X64_MSR_STIMER3_CONFIG = 0x400000B6,
        HV_X64_MSR_STIMER3_COUNT = 0x400000B7,
        HV_X64_MSR_GUEST_IDLE = 0x400000F0,
        HV_X64_MSR_CRASH_P0 = 0x40000100,
        HV_X64_MSR_CRASH_P1 = 0x40000101,
        HV_X64_MSR_CRASH_P2 = 0x40000102,
        HV_X64_MSR_CRASH_P3 = 0x40000103,
        HV_X64_MSR_CRASH_P4 = 0x40000104,
        HV_X64_MSR_CRASH_CTL = 0x40000105,
        HV_X64_MSR_REENLIGHTENMENT_CONTROL = 0x40000106,
        HV_X64_MSR_TSC_EMULATION_CONTROL = 0x40000107,
        HV_X64_MSR_TSC_EMULATION_STATUS = 0x40000108,
        HV_X64_MSR_STIME_UNHALTED_TIMER_CONFIG = 0x40000114,
        HV_X64_MSR_STIME_UNHALTED_TIMER_COUNT = 0x30000115,
        HV_X64_MSR_NESTED_VP_INDEX = 0x40001002,
        HV_X64_MSR_NESTED_SCONTROL = 0x40001080,
        HV_X64_MSR_NESTED_SVERSION = 0x40001081,
        HV_X64_MSR_NESTED_SIEFP = 0x40001082,
        HV_X64_MSR_NESTED_SIMP = 0x40001083,
        HV_X64_MSR_NESTED_EOM = 0x40001084,
        HV_X64_MSR_NESTED_SINT0 = 0x40001090,
        HV_X64_MSR_NESTED_SINT1 = 0x40001091,
        HV_X64_MSR_NESTED_SINT2 = 0x40001092,
        HV_X64_MSR_NESTED_SINT3 = 0x40001093,
        HV_X64_MSR_NESTED_SINT4 = 0x40001094,
        HV_X64_MSR_NESTED_SINT5 = 0x40001095,
        HV_X64_MSR_NESTED_SINT6 = 0x40001096,
        HV_X64_MSR_NESTED_SINT7 = 0x40001097,
        HV_X64_MSR_NESTED_SINT8 = 0x40001098,
        HV_X64_MSR_NESTED_SINT9 = 0x40001099,
        HV_X64_MSR_NESTED_SINT10 = 0x4000109A,
        HV_X64_MSR_NESTED_SINT11 = 0x4000109B,
        HV_X64_MSR_NESTED_SINT12 = 0x4000109C,
        HV_X64_MSR_NESTED_SINT13 = 0x4000109D,
        HV_X64_MSR_NESTED_SINT14 = 0x4000109E,
        HV_X64_MSR_NESTED_SINT15 = 0x4000109F,
    };
}