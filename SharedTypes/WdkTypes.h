#pragma once

#define DECLARE_STRUCT(Name, Fields) \
    using Name = struct Fields;      \
    using P##Name = Name*

// Direct WDK types port for use in usermode:
namespace WdkTypes {
    enum KPROCESSOR_MODE {
        KernelMode,
        UserMode,
        MaximumMode
    };

    enum LOCK_OPERATION {
        IoReadAccess,
        IoWriteAccess,
        IoModifyAccess
    };

    enum MEMORY_CACHING_TYPE_ORIG {
        MmFrameBufferCached = 2        
    };

    enum MEMORY_CACHING_TYPE {
        MmNonCached = FALSE,
        MmCached = TRUE,
        MmWriteCombined = MmFrameBufferCached,
        MmHardwareCoherentCached,
        MmNonCachedUnordered, // IA64
        MmUSWCCached,
        MmMaximumCacheType,
        MmNotMapped = -1
    };

    enum SECTION_INHERIT {
        ViewShare = 1,
        ViewUnmap = 2
    };

    // Using universal x64 types for compatibility with x32 and x64:
    using NTSTATUS  = unsigned int;
    using HANDLE    = unsigned long long;
    using PVOID     = unsigned long long;
    using PVOID64   = unsigned long long;
    using PEPROCESS = PVOID;
    using PETHREAD  = PVOID;
    using PMDL      = PVOID;
    using HMODULE   = PVOID;
    using LPCWSTR   = PVOID;
    using LPWSTR    = PVOID;
    using LPCSTR    = PVOID;
    using LPSTR     = PVOID;
    using PBYTE     = PVOID;
    using PSHORT    = PVOID;
    using PULONG    = PVOID;
    using PDWORD    = PVOID;
    using PUINT64   = PVOID;

    using CLIENT_ID = struct {
        UINT64 ProcessId;
        UINT64 ThreadId;
    };
}

namespace ObjFlags {
    enum ObjFlags {
        _OBJ_INHERIT                        = 0x00000002L,
        _OBJ_PERMANENT                      = 0x00000010L,
        _OBJ_EXCLUSIVE                      = 0x00000020L,
        _OBJ_CASE_INSENSITIVE               = 0x00000040L,
        _OBJ_OPENIF                         = 0x00000080L,
        _OBJ_OPENLINK                       = 0x00000100L,
        _OBJ_KERNEL_HANDLE                  = 0x00000200L,
        _OBJ_FORCE_ACCESS_CHECK             = 0x00000400L,
        _OBJ_IGNORE_IMPERSONATED_DEVICEMAP  = 0x00000800L,
        _OBJ_DONT_REPARSE                   = 0x00001000L,
        _OBJ_VALID_ATTRIBUTES               = 0x00001FF2L,
    };
}

namespace NtTypes {
    enum PROCESSINFOCLASS {
        ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: HANDLE
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // 10, qs: PROCESS_LDT_INFORMATION
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only)
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information,
        ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
        ProcessAffinityMask, // s: KAFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // 30, q: HANDLE
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: ULONG
        ProcessExecuteFlags, // qs: ULONG
        ProcessResourceManagement,
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // q: ULONG
        ProcessInstrumentationCallback, // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // q: ULONG_PTR
        ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // since WINBLUE
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation, // 60, q: UNICODE_STRING
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation,
        ProcessAllowedCpuSetsInformation,
        ProcessReserved1Information,
        ProcessReserved2Information,
        ProcessSubsystemProcess, // 70
        ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
        MaxProcessInfoClass
    };

    enum THREADINFOCLASS {
        ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
        ThreadTimes, // q: KERNEL_USER_TIMES
        ThreadPriority, // s: KPRIORITY
        ThreadBasePriority, // s: LONG
        ThreadAffinityMask, // s: KAFFINITY
        ThreadImpersonationToken, // s: HANDLE
        ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
        ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
        ThreadEventPair,
        ThreadQuerySetWin32StartAddress, // q: PVOID
        ThreadZeroTlsCell, // 10
        ThreadPerformanceCount, // q: LARGE_INTEGER
        ThreadAmILastThread, // q: ULONG
        ThreadIdealProcessor, // s: ULONG
        ThreadPriorityBoost, // qs: ULONG
        ThreadSetTlsArrayAddress,
        ThreadIsIoPending, // q: ULONG
        ThreadHideFromDebugger, // s: void
        ThreadBreakOnTermination, // qs: ULONG
        ThreadSwitchLegacyState,
        ThreadIsTerminated, // 20, q: ULONG
        ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
        ThreadIoPriority, // qs: ULONG
        ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
        ThreadPagePriority, // q: ULONG
        ThreadActualBasePriority,
        ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
        ThreadCSwitchMon,
        ThreadCSwitchPmu,
        ThreadWow64Context, // q: WOW64_CONTEXT
        ThreadGroupInformation, // 30, q: GROUP_AFFINITY
        ThreadUmsInformation,
        ThreadCounterProfiling,
        ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
        ThreadCpuAccountingInformation, // since WIN8
        ThreadSuspendCount, // since WINBLUE
        ThreadHeterogeneousCpuPolicy, // KHETERO_CPU_POLICY // since THRESHOLD
        ThreadContainerId,
        ThreadNameInformation,
        ThreadProperty,
        ThreadSelectedCpuSets,
        ThreadSystemThreadInformation,
        MaxThreadInfoClass
    };
}