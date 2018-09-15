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

    // Using universal x64 types for compatibility with x32 and x64:
    using HANDLE    = unsigned long long;
    using PVOID     = unsigned long long;
    using PVOID64   = unsigned long long;
    using PEPROCESS = PVOID;
    using PETHREAD  = PVOID;
    using PMDL      = PVOID;
    using LPCWSTR   = PVOID;
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