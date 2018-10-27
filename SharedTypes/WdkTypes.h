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
    using NTSTATUS  = unsigned int;
    using HANDLE    = unsigned long long;
    using PVOID     = unsigned long long;
    using PVOID64   = unsigned long long;
    using PEPROCESS = PVOID;
    using PETHREAD  = PVOID;
    using PMDL      = PVOID;
    using HMODULE   = PVOID;
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