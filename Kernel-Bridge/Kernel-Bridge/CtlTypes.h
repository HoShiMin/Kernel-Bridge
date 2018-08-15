#pragma once

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
    using PEPROCESS = PVOID;
    using PETHREAD  = PVOID;
    using PMDL      = PVOID;
    using LPCWSTR   = PVOID;

    using CLIENT_ID = struct {
        UINT64 ProcessId;
        UINT64 ThreadId;
    };
}

#define DECLARE_STRUCT(Name, Fields) \
    typedef struct _##Name           \
        Fields                       \
    Name, *P##Name

DECLARE_STRUCT(KB_SET_BEEPER_DIVIDER_IN, { 
    USHORT Divider; 
});

DECLARE_STRUCT(KB_SET_BEEPER_FREQUENCY_IN, { 
    USHORT Frequency;
});

DECLARE_STRUCT(KB_READ_PORT_IN, {
    USHORT PortNumber;
});

DECLARE_STRUCT(KB_READ_PORT_OUT, {
    union {
        UCHAR Byte;
        USHORT Word;
        ULONG Dword;
    };
});

DECLARE_STRUCT(KB_READ_PORT_STRING_IN, {
    USHORT PortNumber;
    USHORT Granularity; // sizeof(UCHAR/USHORT/ULONG)
    ULONG Count; // Will be read 'Count' times of 'Granularity' bytes
});

DECLARE_STRUCT(KB_READ_PORT_STRING_OUT, {
    union { // Arrays of UCHAR/USHORT/ULONG:
        UCHAR ByteString[1];
        USHORT WordString[1];
        ULONG DwordString[1];
    };
});

DECLARE_STRUCT(KB_WRITE_PORT_IN, {
    USHORT PortNumber;
    USHORT Granularity; // sizeof(UCHAR/USHORT/ULONG)
    union {
        UCHAR Byte;
        USHORT Word;
        ULONG Dword;
    };
});

DECLARE_STRUCT(KB_WRITE_PORT_STRING_IN, {
    struct {
        USHORT PortNumber;
        USHORT Granularity; // sizeof(UCHAR/USHORT/ULONG)
        ULONG Count; // Will be write 'Count' times of 'Granularity' bytes
    } Header;
    union {
        UCHAR ByteString[1];
        USHORT WordString[1];
        ULONG DwordString[1];
    } Payload;
});

DECLARE_STRUCT(KB_READ_MSR_IN, {
    ULONG Index;
});

DECLARE_STRUCT(KB_READ_MSR_OUT, {
    UINT64 Value;
});

DECLARE_STRUCT(KB_WRITE_MSR_IN, {
    UINT64 Value;
    ULONG Index;
});

DECLARE_STRUCT(KB_CPUID_IN, {
    ULONG FunctionIdEax;
});

DECLARE_STRUCT(KB_CPUIDEX_IN, {
    ULONG FunctionIdEax;
    ULONG SubfunctionIdEcx;
});

DECLARE_STRUCT(KB_CPUID_OUT, {
    ULONG Eax;
    ULONG Ebx;
    ULONG Ecx;
    ULONG Edx;
});

DECLARE_STRUCT(KB_READ_PMC_IN, {
    ULONG Counter;
});

DECLARE_STRUCT(KB_READ_PMC_OUT, {
    UINT64 Value;
});

DECLARE_STRUCT(KB_READ_TSC_OUT, {
    UINT64 Value;
});

DECLARE_STRUCT(KB_READ_TSCP_OUT, {
    UINT64 Value;
    UINT32 TscAux;
});

DECLARE_STRUCT(KB_ALLOC_KERNEL_MEMORY_IN, {
    ULONG Size;
    BOOLEAN Executable;
});

DECLARE_STRUCT(KB_ALLOC_KERNEL_MEMORY_OUT, {
    WdkTypes::PVOID KernelAddress;
});

DECLARE_STRUCT(KB_FREE_KERNEL_MEMORY_IN, {
    WdkTypes::PVOID KernelAddress;
});

DECLARE_STRUCT(KB_COPY_MOVE_MEMORY_IN, {
    WdkTypes::PVOID Src;
    WdkTypes::PVOID Dest;
    ULONG Size;
    BOOLEAN Intersects; // Whether Src and Dest intersects (use memmove if true)
});

DECLARE_STRUCT(KB_FILL_MEMORY_IN, {
    WdkTypes::PVOID Address;
    ULONG Size;
    UCHAR Filler;
});

DECLARE_STRUCT(KB_EQUAL_MEMORY_IN, {
    WdkTypes::PVOID Src;
    WdkTypes::PVOID Dest;
    ULONG Size;
});

DECLARE_STRUCT(KB_EQUAL_MEMORY_OUT, {
    BOOLEAN Equals;
});

DECLARE_STRUCT(KB_MAP_MEMORY_IN, {
    OPTIONAL UINT64 SrcProcessId;
    OPTIONAL UINT64 DestProcessId;
    WdkTypes::PVOID VirtualAddress;
    ULONG Size;
    WdkTypes::KPROCESSOR_MODE AccessMode;
    WdkTypes::LOCK_OPERATION LockOperation;
    WdkTypes::MEMORY_CACHING_TYPE CacheType;
    OPTIONAL WdkTypes::PVOID UserRequestedAddress;
});

DECLARE_STRUCT(KB_MAP_MEMORY_OUT, {
    WdkTypes::PMDL Mdl; // Necessary for unmapping, don't change!
    WdkTypes::PVOID BaseAddress;
});

DECLARE_STRUCT(KB_UNMAP_MEMORY_IN, {
    WdkTypes::PMDL Mdl;
    WdkTypes::PVOID BaseAddress;
});

DECLARE_STRUCT(KB_MAP_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID PhysicalAddress;
    ULONG Size;
});

DECLARE_STRUCT(KB_MAP_PHYSICAL_MEMORY_OUT, {
    WdkTypes::PVOID VirtualAddress; 
});

DECLARE_STRUCT(KB_UNMAP_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID VirtualAddress;
    ULONG Size;
});

DECLARE_STRUCT(KB_GET_PHYSICAL_ADDRESS_IN, {
    WdkTypes::PEPROCESS Process;
    WdkTypes::PVOID VirtualAddress;
});

DECLARE_STRUCT(KB_GET_PHYSICAL_ADDRESS_OUT, {
    WdkTypes::PVOID PhysicalAddress;
});

DECLARE_STRUCT(KB_READ_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID PhysicalAddress;
    ULONG Size;
});

DECLARE_STRUCT(KB_READ_PHYSICAL_MEMORY_OUT, {
    UCHAR Buffer[1];
});

DECLARE_STRUCT(KB_WRITE_PHYSICAL_MEMORY_IN, {
    struct {
        WdkTypes::PVOID PhysicalAddress;
        ULONG Size;
    } Header;
    UCHAR Buffer[1];
});

constexpr int DmiSize = 65536;

DECLARE_STRUCT(KB_READ_DMI_MEMORY_OUT, {
    UCHAR DmiBuffer[DmiSize];
});

DECLARE_STRUCT(KB_GET_EPROCESS_IN, {
    UINT64 ProcessId;
});

DECLARE_STRUCT(KB_GET_EPROCESS_OUT, {
    WdkTypes::PEPROCESS Process;
});

DECLARE_STRUCT(KB_GET_ETHREAD_IN, {
    UINT64 ThreadId;    
});

DECLARE_STRUCT(KB_GET_ETHREAD_OUT, {
    WdkTypes::PETHREAD Thread;
});

DECLARE_STRUCT(KB_OPEN_PROCESS_IN, {
    UINT64 ProcessId;
});

DECLARE_STRUCT(KB_OPEN_PROCESS_OUT, {
    WdkTypes::HANDLE hProcess;
});

DECLARE_STRUCT(KB_DEREFERENCE_OBJECT_IN, {
    WdkTypes::PVOID Object;
});

DECLARE_STRUCT(KB_CLOSE_HANDLE_IN, {
    WdkTypes::HANDLE Handle;
});

DECLARE_STRUCT(KB_ALLOC_USER_MEMORY_IN, {
    UINT64 ProcessId;
    ULONG Size;
    ULONG Protect;
});

DECLARE_STRUCT(KB_ALLOC_USER_MEMORY_OUT, {
    WdkTypes::PVOID BaseAddress;
});

DECLARE_STRUCT(KB_FREE_USER_MEMORY_IN, {
    UINT64 ProcessId;
    WdkTypes::PVOID BaseAddress;
});

DECLARE_STRUCT(KB_READ_WRITE_PROCESS_MEMORY_IN, {
    UINT64 ProcessId;
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PVOID Buffer;
    ULONG Size;
});

DECLARE_STRUCT(KB_SUSPEND_RESUME_PROCESS_IN, {
    UINT64 ProcessId;
});

DECLARE_STRUCT(KB_CREATE_USER_THREAD_IN, {
    UINT64 ProcessId;
    WdkTypes::PVOID ThreadRoutine;
    WdkTypes::PVOID Argument;
    BOOLEAN CreateSuspended;
});

DECLARE_STRUCT(KB_CREATE_SYSTEM_THREAD_IN, {
    OPTIONAL UINT64 AssociatedProcessId;
    WdkTypes::PVOID ThreadRoutine;
    WdkTypes::PVOID Argument;
});

DECLARE_STRUCT(KB_CREATE_USER_SYSTEM_THREAD_OUT, {
    WdkTypes::HANDLE hThread;
    WdkTypes::CLIENT_ID ClientId;
});

DECLARE_STRUCT(KB_GET_KERNEL_PROC_ADDRESS_IN, {
    WdkTypes::LPCWSTR RoutineName;
    ULONG SizeOfBufferInBytes;
});

DECLARE_STRUCT(KB_GET_KERNEL_PROC_ADDRESS_OUT, {
    WdkTypes::PVOID Address;
});

DECLARE_STRUCT(KB_STALL_EXECUTION_PROCESSOR_IN, {
    ULONG Microseconds;
});

DECLARE_STRUCT(KB_BUG_CHECK_IN, {
    ULONG Status;
});