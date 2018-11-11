#pragma once

namespace Ctls {
    enum KbCtlIndices {
        // Beeper:
        /* 00 */ KbSetBeeperRegime,
        /* 01 */ KbStartBeeper,
        /* 02 */ KbStopBeeper,
        /* 03 */ KbSetBeeperIn,
        /* 04 */ KbSetBeeperOut,
        /* 05 */ KbSetBeeperDivider,
        /* 06 */ KbSetBeeperFrequency,

        // IO-Ports:
        /* 07 */ KbReadPort,
        /* 08 */ KbReadPortString,
        /* 09 */ KbWritePort,
        /* 10 */ KbWritePortString,

        // Interrupts:
        /* 11 */ KbCli,
        /* 12 */ KbSti,
        /* 13 */ KbHlt,

        // MSR:
        /* 14 */ KbReadMsr,
        /* 15 */ KbWriteMsr,

        // CPUID:
        /* 16 */ KbCpuid,
        /* 17 */ KbCpuidEx,

        // TSC & PMC:
        /* 18 */ KbReadPmc,
        /* 19 */ KbReadTsc,
        /* 20 */ KbReadTscp,

        // Memory management:
        /* 21 */ KbAllocKernelMemory,
        /* 22 */ KbFreeKernelMemory,
        /* 23 */ KbCopyMoveMemory,
        /* 24 */ KbFillMemory,
        /* 25 */ KbEqualMemory,

        // Memory mappings:
        /* 26 */ KbMapMdl,
        /* 27 */ KbMapMemory,
        /* 28 */ KbProtectMappedMemory,
        /* 29 */ KbUnmapMdl,
        /* 30 */ KbUnmapMemory,

        // Physical memory:
        /* 31 */ KbAllocPhysicalMemory,
        /* 32 */ KbFreePhysicalMemory,
        /* 33 */ KbMapPhysicalMemory,
        /* 34 */ KbUnmapPhysicalMemory,
        /* 35 */ KbGetPhysicalAddress,
        /* 36 */ KbReadPhysicalMemory,
        /* 37 */ KbWritePhysicalMemory,
        /* 38 */ KbReadDmiMemory,

        // Processes & Threads:
        /* 39 */ KbGetEprocess,
        /* 40 */ KbGetEthread,
        /* 41 */ KbOpenProcess,
        /* 42 */ KbOpenProcessByPointer,
        /* 43 */ KbOpenThread,
        /* 44 */ KbOpenThreadByPointer,
        /* 45 */ KbDereferenceObject,
        /* 46 */ KbCloseHandle,
        /* 47 */ KbAllocUserMemory,
        /* 48 */ KbFreeUserMemory,
        /* 49 */ KbSecureVirtualMemory,
        /* 50 */ KbUnsecureVirtualMemory,
        /* 51 */ KbReadProcessMemory,
        /* 52 */ KbWriteProcessMemory,
        /* 53 */ KbSuspendProcess,
        /* 54 */ KbResumeProcess,
        /* 55 */ KbGetThreadContext,
        /* 56 */ KbSetThreadContext,
        /* 57 */ KbCreateUserThread,
        /* 58 */ KbCreateSystemThread,
        /* 59 */ KbQueueUserApc,
        /* 60 */ KbRaiseIopl,
        /* 61 */ KbResetIopl,

        // Loadable modules:
        /* 62 */ KbCreateDriver,
        /* 63 */ KbLoadModule,
        /* 64 */ KbGetModuleHandle,
        /* 65 */ KbCallModule,
        /* 66 */ KbUnloadModule,

        // Stuff u kn0w:
        /* 67 */ KbExecuteShellCode,
        /* 68 */ KbGetKernelProcAddress,
        /* 69 */ KbStallExecutionProcessor,
        /* 70 */ KbBugCheck,
        /* 71 */ KbFindSignature
    };
}


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

DECLARE_STRUCT(KB_MAP_MDL_IN, {
    OPTIONAL UINT64 SrcProcessId;
    OPTIONAL UINT64 DestProcessId;
    WdkTypes::PMDL Mdl;
    BOOLEAN NeedLock;
    WdkTypes::KPROCESSOR_MODE AccessMode;
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
    WdkTypes::KPROCESSOR_MODE AccessMode;
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

DECLARE_STRUCT(KB_READ_WRITE_PROCESS_MEMORY_IN, {
    UINT64 ProcessId;
    WdkTypes::PVOID BaseAddress;
    WdkTypes::PVOID Buffer;
    ULONG Size;
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