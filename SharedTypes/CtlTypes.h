#pragma once

constexpr int KB_API_VERSION = 8;

namespace Ctls
{
    enum KbCtlIndices {
        // Driver management:
        /* 00 */ KbGetDriverApiVersion,
        /* 01 */ KbGetHandlesCount,

        // Beeper:
        /* 02 */ KbSetBeeperRegime,
        /* 03 */ KbStartBeeper,
        /* 04 */ KbStopBeeper,
        /* 05 */ KbSetBeeperIn,
        /* 06 */ KbSetBeeperOut,
        /* 07 */ KbSetBeeperDivider,
        /* 08 */ KbSetBeeperFrequency,

        // IO-Ports:
        /* 09 */ KbReadPort,
        /* 10 */ KbReadPortString,
        /* 11 */ KbWritePort,
        /* 12 */ KbWritePortString,

        // Interrupts:
        /* 13 */ KbCli,
        /* 14 */ KbSti,
        /* 15 */ KbHlt,

        // MSR:
        /* 16 */ KbReadMsr,
        /* 17 */ KbWriteMsr,

        // CPUID:
        /* 18 */ KbCpuid,
        /* 19 */ KbCpuidEx,

        // TSC & PMC:
        /* 20 */ KbReadPmc,
        /* 21 */ KbReadTsc,
        /* 22 */ KbReadTscp,

        // Memory management:
        /* 23 */ KbAllocKernelMemory,
        /* 24 */ KbFreeKernelMemory,
        /* 25 */ KbAllocNonCachedMemory,
        /* 26 */ KbFreeNonCachedMemory,
        /* 27 */ KbCopyMoveMemory,
        /* 28 */ KbFillMemory,
        /* 29 */ KbEqualMemory,

        // Memory mappings:
        /* 30 */ KbAllocateMdl,
        /* 31 */ KbProbeAndLockPages,
        /* 32 */ KbMapMdl,
        /* 33 */ KbProtectMappedMemory,
        /* 34 */ KbUnmapMdl,
        /* 35 */ KbUnlockPages,
        /* 36 */ KbFreeMdl,
        /* 37 */ KbMapMemory,
        /* 38 */ KbUnmapMemory,

        // Physical memory:
        /* 39 */ KbAllocPhysicalMemory,
        /* 40 */ KbFreePhysicalMemory,
        /* 41 */ KbMapPhysicalMemory,
        /* 42 */ KbUnmapPhysicalMemory,
        /* 43 */ KbGetPhysicalAddress,
        /* 44 */ KbGetVirtualForPhysical,
        /* 45 */ KbReadPhysicalMemory,
        /* 46 */ KbWritePhysicalMemory,
        /* 47 */ KbReadDmiMemory,

        // Processes & Threads:
        /* 48 */ KbGetEprocess,
        /* 49 */ KbGetEthread,
        /* 50 */ KbOpenProcess,
        /* 51 */ KbOpenProcessByPointer,
        /* 52 */ KbOpenThread,
        /* 53 */ KbOpenThreadByPointer,
        /* 54 */ KbDereferenceObject,
        /* 55 */ KbCloseHandle,
        /* 56 */ KbQueryInformationProcess,
        /* 57 */ KbSetInformationProcess,
        /* 58 */ KbQueryInformationThread,
        /* 59 */ KbSetInformationThread,
        /* 60 */ KbAllocUserMemory,
        /* 61 */ KbFreeUserMemory,
        /* 62 */ KbSecureVirtualMemory,
        /* 63 */ KbUnsecureVirtualMemory,
        /* 64 */ KbReadProcessMemory,
        /* 65 */ KbWriteProcessMemory,
        /* 66 */ KbTriggerCopyOnWrite,
        /* 67 */ KbSuspendProcess,
        /* 68 */ KbResumeProcess,
        /* 69 */ KbGetThreadContext,
        /* 70 */ KbSetThreadContext,
        /* 71 */ KbCreateUserThread,
        /* 72 */ KbCreateSystemThread,
        /* 73 */ KbQueueUserApc,
        /* 74 */ KbRaiseIopl,
        /* 75 */ KbResetIopl,
        /* 76 */ KbGetProcessCr3Cr4,

        // Sections:
        /* 77 */ KbCreateSection,
        /* 78 */ KbOpenSection,
        /* 79 */ KbMapViewOfSection,
        /* 80 */ KbUnmapViewOfSection,

        // Loadable modules:
        /* 81 */ KbCreateDriver,
        /* 82 */ KbLoadModule,
        /* 83 */ KbGetModuleHandle,
        /* 84 */ KbCallModule,
        /* 85 */ KbUnloadModule,

        // Hypervisor:
        /* 86 */ KbVmmEnable,
        /* 87 */ KbVmmDisable,
        /* 88 */ KbVmmInterceptPage,
        /* 89 */ KbVmmDeinterceptPage,

        // Stuff u kn0w:
        /* 90 */ KbExecuteShellCode,
        /* 91 */ KbGetKernelProcAddress,
        /* 92 */ KbStallExecutionProcessor,
        /* 93 */ KbBugCheck,
        /* 94 */ KbFindSignature
    };
}

DECLARE_STRUCT(KB_GET_DRIVER_API_VERSION_OUT, {
    ULONG Version;
});

DECLARE_STRUCT(KB_GET_HANDLES_COUNT_OUT, {
    ULONG HandlesCount;
});

DECLARE_STRUCT(KB_SET_BEEPER_DIVIDER_IN, { 
    USHORT Divider; 
});

DECLARE_STRUCT(KB_SET_BEEPER_FREQUENCY_IN, { 
    USHORT Frequency;
});

DECLARE_STRUCT(KB_READ_PORT_IN, {
    USHORT PortNumber;
});

DECLARE_STRUCT(KB_READ_PORT_BYTE_OUT, {
    UCHAR Value;
});

DECLARE_STRUCT(KB_READ_PORT_WORD_OUT, {
    USHORT Value;
});

DECLARE_STRUCT(KB_READ_PORT_DWORD_OUT, {
    ULONG Value;
});

DECLARE_STRUCT(KB_READ_PORT_STRING_IN, {
    USHORT PortNumber;
    USHORT Granularity; // sizeof(UCHAR/USHORT/ULONG)
    ULONG Count; // Will be write 'Count' times of 'Granularity' bytes
});

DECLARE_STRUCT(KB_READ_PORT_STRING_OUT, {
    union {
        UCHAR ByteString[1];
        USHORT WordString[1];
        ULONG DwordString[1];
    };    
});

DECLARE_STRUCT(KB_WRITE_PORT_IN, {
    USHORT PortNumber;
    USHORT Granularity;
    union {
        UCHAR Byte;
        USHORT Word;
        ULONG Dword;
    };   
});

DECLARE_STRUCT(KB_WRITE_PORT_STRING_IN, {
    USHORT PortNumber;
    USHORT Granularity; // sizeof(UCHAR/USHORT/ULONG)
    ULONG Count; // Will be write 'Count' times of 'Granularity' bytes
    ULONG BufferSize;
    WdkTypes::PVOID Buffer;
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

DECLARE_STRUCT(KB_ALLOC_NON_CACHED_MEMORY_IN, {
    ULONG Size;
});

DECLARE_STRUCT(KB_ALLOC_NON_CACHED_MEMORY_OUT, {
    WdkTypes::PVOID KernelAddress;
});

DECLARE_STRUCT(KB_FREE_NON_CACHED_MEMORY_IN, {
    WdkTypes::PVOID KernelAddress;
    ULONG Size;
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

DECLARE_STRUCT(KB_ALLOCATE_MDL_IN, {
    WdkTypes::PVOID VirtualAddress;
    ULONG Size;
});

DECLARE_STRUCT(KB_ALLOCATE_MDL_OUT, {
    WdkTypes::PMDL Mdl;    
});

DECLARE_STRUCT(KB_PROBE_AND_LOCK_PAGES_IN, {
    OPTIONAL UINT64 ProcessId;
    WdkTypes::PMDL Mdl;
    WdkTypes::KPROCESSOR_MODE ProcessorMode;
    WdkTypes::LOCK_OPERATION LockOperation;
});

DECLARE_STRUCT(KB_MAP_MDL_IN, {
    OPTIONAL UINT64 SrcProcessId;
    OPTIONAL UINT64 DestProcessId;
    WdkTypes::PMDL Mdl;
    BOOLEAN NeedProbeAndLock;
    WdkTypes::KPROCESSOR_MODE MapToAddressSpace;
    ULONG Protect;
    WdkTypes::MEMORY_CACHING_TYPE CacheType;
    OPTIONAL WdkTypes::PVOID UserRequestedAddress;
});

DECLARE_STRUCT(KB_MAP_MDL_OUT, {
    WdkTypes::PVOID BaseAddress;
});

DECLARE_STRUCT(KB_MAP_MEMORY_IN, {
    OPTIONAL UINT64 SrcProcessId;
    OPTIONAL UINT64 DestProcessId;
    WdkTypes::PVOID VirtualAddress;
    ULONG Size;
    WdkTypes::KPROCESSOR_MODE MapToAddressSpace;
    ULONG Protect;
    WdkTypes::MEMORY_CACHING_TYPE CacheType;
    OPTIONAL WdkTypes::PVOID UserRequestedAddress;
});

DECLARE_STRUCT(KB_MAP_MEMORY_OUT, {
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PMDL Mdl; // Necessary for unmapping, don't change!
});

DECLARE_STRUCT(KB_PROTECT_MAPPED_MEMORY_IN, {
    WdkTypes::PMDL Mdl;
    ULONG Protect;
});

DECLARE_STRUCT(KB_UNMAP_MDL_IN, {
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PMDL Mdl;
    BOOLEAN NeedUnlock;
});

DECLARE_STRUCT(KB_UNLOCK_PAGES_IN, {
    WdkTypes::PMDL Mdl;    
});

DECLARE_STRUCT(KB_FREE_MDL_IN, {
    WdkTypes::PMDL Mdl;    
});

DECLARE_STRUCT(KB_UNMAP_MEMORY_IN, {
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PMDL Mdl;
});

DECLARE_STRUCT(KB_ALLOC_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID LowestAcceptableAddress;
    WdkTypes::PVOID HighestAcceptableAddress;
    WdkTypes::PVOID BoundaryAddressMultiple;
    ULONG Size;
    WdkTypes::MEMORY_CACHING_TYPE CachingType;
});

DECLARE_STRUCT(KB_ALLOC_PHYSICAL_MEMORY_OUT, {
    WdkTypes::PVOID Address;
});

DECLARE_STRUCT(KB_FREE_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID Address;    
});

DECLARE_STRUCT(KB_MAP_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID PhysicalAddress;
    ULONG Size;
    WdkTypes::MEMORY_CACHING_TYPE CachingType;
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

DECLARE_STRUCT(KB_GET_VIRTUAL_FOR_PHYSICAL_IN, {
    WdkTypes::PVOID PhysicalAddress; 
});

DECLARE_STRUCT(KB_GET_VIRTUAL_FOR_PHYSICAL_OUT, {
    WdkTypes::PVOID VirtualAddress;
});

DECLARE_STRUCT(KB_READ_WRITE_PHYSICAL_MEMORY_IN, {
    WdkTypes::PVOID PhysicalAddress;
    WdkTypes::PVOID Buffer;
    ULONG Size;
    WdkTypes::MEMORY_CACHING_TYPE CachingType;
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
    ACCESS_MASK Access;
    ULONG Attributes;
});

DECLARE_STRUCT(KB_OPEN_PROCESS_BY_POINTER_IN, {
    WdkTypes::PEPROCESS Process;
    ACCESS_MASK Access;
    ULONG Attributes;
    WdkTypes::KPROCESSOR_MODE ProcessorMode;
});

DECLARE_STRUCT(KB_OPEN_PROCESS_OUT, {
    WdkTypes::HANDLE hProcess;
});

DECLARE_STRUCT(KB_OPEN_THREAD_IN, {
    UINT64 ThreadId;
    ACCESS_MASK Access;
    ULONG Attributes;
});

DECLARE_STRUCT(KB_OPEN_THREAD_BY_POINTER_IN, {
    WdkTypes::PETHREAD Thread;
    ACCESS_MASK Access;
    ULONG Attributes;
    WdkTypes::KPROCESSOR_MODE ProcessorMode;
});

DECLARE_STRUCT(KB_OPEN_THREAD_OUT, {
    WdkTypes::HANDLE hThread;
});

DECLARE_STRUCT(KB_DEREFERENCE_OBJECT_IN, {
    WdkTypes::PVOID Object;
});

DECLARE_STRUCT(KB_CLOSE_HANDLE_IN, {
    WdkTypes::HANDLE Handle;
});

DECLARE_STRUCT(KB_QUERY_INFORMATION_PROCESS_THREAD_IN, {
    WdkTypes::HANDLE Handle;
    WdkTypes::PVOID Buffer;
    WdkTypes::PULONG ReturnLength;
    ULONG InfoClass;
    ULONG Size;
});

DECLARE_STRUCT(KB_SET_INFORMATION_PROCESS_THREAD_IN, {
    WdkTypes::HANDLE Handle;
    WdkTypes::PVOID Buffer;
    ULONG InfoClass;
    ULONG Size;
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

DECLARE_STRUCT(KB_SECURE_VIRTUAL_MEMORY_IN, {
    ULONG ProcessId;
    ULONG ProtectRights;
    WdkTypes::PVOID BaseAddress;
    ULONG Size;
});

DECLARE_STRUCT(KB_SECURE_VIRTUAL_MEMORY_OUT, {
    WdkTypes::HANDLE SecureHandle;    
});

DECLARE_STRUCT(KB_UNSECURE_VIRTUAL_MEMORY_IN, {
    WdkTypes::HANDLE SecureHandle; 
    ULONG ProcessId;
});

DECLARE_STRUCT(KB_READ_PROCESS_MEMORY_IN, {
    OPTIONAL UINT64 ProcessId;
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PVOID Buffer;
    ULONG Size;
});

DECLARE_STRUCT(KB_WRITE_PROCESS_MEMORY_IN, {
    OPTIONAL UINT64 ProcessId;
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PVOID Buffer;
    ULONG Size;
    BOOLEAN PerformCopyOnWrite;
});

DECLARE_STRUCT(KB_TRIGGER_COPY_ON_WRITE_IN, {
    OPTIONAL UINT64 ProcessId;
    WdkTypes::PVOID PageVirtualAddress;
});

DECLARE_STRUCT(KB_SUSPEND_RESUME_PROCESS_IN, {
    UINT64 ProcessId;
});

DECLARE_STRUCT(KB_GET_SET_THREAD_CONTEXT_IN, {
    UINT64 ThreadId;
    ULONG ContextSize; // Must be size of native CONTEXT struct
    WdkTypes::KPROCESSOR_MODE ProcessorMode;
    WdkTypes::PVOID Context; // Pointer to native CONTEXT struct
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

DECLARE_STRUCT(KB_QUEUE_USER_APC_IN, {
    UINT64 ThreadId;
    WdkTypes::PVOID ApcProc;
    WdkTypes::PVOID Argument;
});

DECLARE_STRUCT(KB_GET_PROCESS_CR3_CR4_IN, {
    UINT64 ProcessId;
});

DECLARE_STRUCT(KB_GET_PROCESS_CR3_CR4_OUT, {
    UINT64 Cr3;
    UINT64 Cr4;
});

DECLARE_STRUCT(KB_CREATE_SECTION_IN, {
    OPTIONAL WdkTypes::LPCWSTR Name;
    UINT64 MaximumSize;
    ACCESS_MASK DesiredAccess;
    ULONG SecObjFlags; // OBJ_***
    ULONG SecPageProtection;
    ULONG AllocationAttributes;
    OPTIONAL WdkTypes::HANDLE hFile;
});

DECLARE_STRUCT(KB_OPEN_SECTION_IN, {
    WdkTypes::LPCWSTR Name;
    ACCESS_MASK DesiredAccess;
    ULONG SecObjFlags; // OBJ_***
});

DECLARE_STRUCT(KB_CREATE_OPEN_SECTION_OUT, {
    WdkTypes::HANDLE hSection;
});

DECLARE_STRUCT(KB_MAP_VIEW_OF_SECTION_IN, {
    WdkTypes::HANDLE hSection;
    WdkTypes::HANDLE hProcess;
    IN WdkTypes::PVOID BaseAddress;
    ULONG CommitSize;
    UINT64 SectionOffset;
    UINT64 ViewSize;
    WdkTypes::SECTION_INHERIT SectionInherit;
    ULONG AllocationType;
    ULONG Win32Protect;
});

DECLARE_STRUCT(KB_MAP_VIEW_OF_SECTION_OUT, {
    WdkTypes::PVOID BaseAddress;
    UINT64 SectionOffset;
    UINT64 ViewSize;
});

DECLARE_STRUCT(KB_UNMAP_VIEW_OF_SECTION_IN, {
    WdkTypes::HANDLE hProcess;
    WdkTypes::PVOID BaseAddress;
});

DECLARE_STRUCT(KB_VMM_INTERCEPT_PAGE_IN, {
    IN WdkTypes::PVOID64 PhysicalAddress;
    IN OPTIONAL WdkTypes::PVOID64 OnReadPhysicalAddress;
    IN OPTIONAL WdkTypes::PVOID64 OnWritePhysicalAddress;
    IN OPTIONAL WdkTypes::PVOID64 OnExecutePhysicalAddress;
    IN OPTIONAL WdkTypes::PVOID64 OnExecuteReadPhysicalAddress;
    IN OPTIONAL WdkTypes::PVOID64 OnExecuteWritePhysicalAddress;
});

DECLARE_STRUCT(KB_VMM_DEINTERCEPT_PAGE_IN, {
    IN WdkTypes::PVOID64 PhysicalAddress;
});

DECLARE_STRUCT(KB_EXECUTE_SHELL_CODE_IN, {
    WdkTypes::PVOID Address;
    WdkTypes::PVOID Argument;
});

DECLARE_STRUCT(KB_EXECUTE_SHELL_CODE_OUT, {
    ULONG Result;    
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

DECLARE_STRUCT(KB_CREATE_DRIVER_IN, {
    WdkTypes::PVOID DriverEntry;
    WdkTypes::LPCWSTR DriverName;
    ULONG DriverNameSizeInBytes;
});

DECLARE_STRUCT(KB_LOAD_MODULE_IN, {
    WdkTypes::HMODULE hModule;
    WdkTypes::LPCWSTR ModuleName;
    WdkTypes::PVOID OnLoad;
    WdkTypes::PVOID OnUnload;
    WdkTypes::PVOID OnDeviceControl;
});

DECLARE_STRUCT(KB_GET_MODULE_HANDLE_IN, {
    WdkTypes::LPCWSTR ModuleName;    
});

DECLARE_STRUCT(KB_GET_MODULE_HANDLE_OUT, {
    WdkTypes::HMODULE hModule;    
});

DECLARE_STRUCT(KB_CALL_MODULE_IN, {
    WdkTypes::HMODULE hModule;
    WdkTypes::PVOID Argument;
    ULONG CtlCode;
});

DECLARE_STRUCT(KB_UNLOAD_MODULE_IN, {
    WdkTypes::HMODULE hModule;    
});

DECLARE_STRUCT(KB_FIND_SIGNATURE_IN, {
    OPTIONAL UINT64 ProcessId;
    WdkTypes::PVOID Memory;
    ULONG Size;
    WdkTypes::LPCSTR Signature;
    WdkTypes::LPCSTR Mask;
});

DECLARE_STRUCT(KB_FIND_SIGNATURE_OUT, {
    WdkTypes::PVOID Address;    
});