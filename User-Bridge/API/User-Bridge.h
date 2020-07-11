#pragma once

namespace KbLoader
{
    BOOL WINAPI KbLoadAsDriver(LPCWSTR DriverPath);
    BOOL WINAPI KbLoadAsFilter(LPCWSTR DriverPath, LPCWSTR Altitude);
    BOOL WINAPI KbUnload();
    ULONG WINAPI KbGetDriverApiVersion();
    ULONG WINAPI KbGetUserApiVersion();
    BOOL WINAPI KbGetHandlesCount(OUT PULONG Count);
}

namespace AddressRange
{
    inline BOOLEAN IsUserAddress(PVOID Address)
    {
        return reinterpret_cast<SIZE_T>(Address) < (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
    }

    inline BOOLEAN IsKernelAddress(PVOID Address)
    {
        return reinterpret_cast<SIZE_T>(Address) >= (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
    }

    inline BOOLEAN IsUserAddressIa32(UINT64 Address)
    {
        return Address < 0x80000000;
    }

    inline BOOLEAN IsUserAddressAmd64(UINT64 Address)
    {
        return Address < 0x8000000000000000;
    }

    inline BOOLEAN IsKernelAddressIa32(UINT64 Address)
    {
        return Address > 0x7FFFFFFF;
    }

    inline BOOLEAN IsKernelAddressAmd64(UINT64 Address)
    {
        return Address > 0x7FFFFFFFFFFFFFFF;
    }
}

namespace IO
{
    namespace Beeper
    {
        BOOL WINAPI KbSetBeeperRegime();
        BOOL WINAPI KbStartBeeper();
        BOOL WINAPI KbStopBeeper();
        BOOL WINAPI KbSetBeeperIn();
        BOOL WINAPI KbSetBeeperOut();
        BOOL WINAPI KbSetBeeperDivider(USHORT Divider);
        BOOL WINAPI KbSetBeeperFrequency(USHORT Frequency);
    }

    namespace RW
    {
        BOOL WINAPI KbReadPortByte(USHORT PortNumber, OUT PUCHAR Value);
        BOOL WINAPI KbReadPortWord(USHORT PortNumber, OUT PUSHORT Value);
        BOOL WINAPI KbReadPortDword(USHORT PortNumber, OUT PULONG Value);
        
        BOOL WINAPI KbReadPortByteString(USHORT PortNumber, ULONG Count, OUT PUCHAR ByteString, ULONG ByteStringSizeInBytes);
        BOOL WINAPI KbReadPortWordString(USHORT PortNumber, ULONG Count, OUT PUSHORT WordString, ULONG WordStringSizeInBytes);
        BOOL WINAPI KbReadPortDwordString(USHORT PortNumber, ULONG Count, OUT PULONG DwordString, ULONG DwordStringSizeInBytes);
        
        BOOL WINAPI KbWritePortByte(USHORT PortNumber, UCHAR Value);
        BOOL WINAPI KbWritePortWord(USHORT PortNumber, USHORT Value);
        BOOL WINAPI KbWritePortDword(USHORT PortNumber, ULONG Value);
        
        BOOL WINAPI KbWritePortByteString(USHORT PortNumber, ULONG Count, IN PUCHAR ByteString, ULONG ByteStringSizeInBytes);
        BOOL WINAPI KbWritePortWordString(USHORT PortNumber, ULONG Count, IN PUSHORT WordString, ULONG WordStringSizeInBytes);
        BOOL WINAPI KbWritePortDwordString(USHORT PortNumber, ULONG Count, IN PULONG DwordString, ULONG DwordStringSizeInBytes);
    }

    namespace Iopl
    {
        // Allows to use 'in/out/cli/sti' in usermode:
        BOOL WINAPI KbRaiseIopl();
        BOOL WINAPI KbResetIopl();
    }
}

namespace CPU
{
    BOOL WINAPI KbCli();
    BOOL WINAPI KbSti();
    BOOL WINAPI KbHlt();

    BOOL WINAPI KbReadMsr(ULONG Index, OUT PUINT64 MsrValue);
    BOOL WINAPI KbWriteMsr(ULONG Index, IN UINT64 MsrValue);

    using CPUID_INFO = struct
    {
        ULONG Eax;
        ULONG Ebx;
        ULONG Ecx;
        ULONG Edx;
    };
    using PCPUID_INFO = CPUID_INFO*;

    BOOL WINAPI KbCpuid(ULONG FunctionIdEax, OUT PCPUID_INFO CpuidInfo);
    BOOL WINAPI KbCpuidEx(ULONG FunctionIdEax, ULONG SubfunctionIdEcx, OUT PCPUID_INFO CpuidInfo);

    BOOL WINAPI KbReadPmc(ULONG Counter, OUT PUINT64 PmcValue);
    BOOL WINAPI KbReadTsc(OUT PUINT64 TscValue);
    BOOL WINAPI KbReadTscp(OUT PUINT64 TscValue, OUT OPTIONAL PULONG TscAux);
}

namespace VirtualMemory
{
    // Supports both user- and kernel-memory in context of current process:
    BOOL WINAPI KbAllocKernelMemory(ULONG Size, BOOLEAN Executable, OUT WdkTypes::PVOID* KernelAddress);
    BOOL WINAPI KbFreeKernelMemory(IN WdkTypes::PVOID KernelAddress);
    BOOL WINAPI KbAllocNonCachedMemory(ULONG Size, OUT WdkTypes::PVOID* KernelAddress);
    BOOL WINAPI KbFreeNonCachedMemory(WdkTypes::PVOID KernelAddress, ULONG Size);
    BOOL WINAPI KbCopyMoveMemory(OUT WdkTypes::PVOID Dest, IN WdkTypes::PVOID Src, ULONG Size, BOOLEAN Intersects);
    BOOL WINAPI KbFillMemory(IN WdkTypes::PVOID Address, UCHAR Filler, ULONG Size);
    BOOL WINAPI KbEqualMemory(IN WdkTypes::PVOID Src, IN WdkTypes::PVOID Dest, ULONG Size, OUT PBOOLEAN Equals);
}

namespace Mdl
{
    BOOL WINAPI KbAllocateMdl(
        WdkTypes::PVOID VirtualAddress,
        ULONG Size,
        OUT WdkTypes::PMDL* Mdl
    );

    BOOL WINAPI KbProbeAndLockPages(
        OPTIONAL ULONG ProcessId,
        WdkTypes::PMDL Mdl,
        WdkTypes::KPROCESSOR_MODE ProcessorMode,
        WdkTypes::LOCK_OPERATION LockOperation
    );

    BOOL WINAPI KbMapMdl(
        OUT WdkTypes::PVOID* MappedMemory,
        OPTIONAL UINT64 SrcProcessId,
        OPTIONAL UINT64 DestProcessId,
        WdkTypes::PMDL Mdl,
        BOOLEAN NeedProbeAndLock,
        WdkTypes::KPROCESSOR_MODE MapToAddressSpace = WdkTypes::UserMode,
        ULONG Protect = PAGE_READWRITE,
        WdkTypes::MEMORY_CACHING_TYPE CacheType = WdkTypes::MmNonCached,
        OPTIONAL WdkTypes::PVOID UserRequestedAddress = NULL
    );

    BOOL WINAPI KbProtectMappedMemory(IN WdkTypes::PMDL Mdl, ULONG Protect);
    BOOL WINAPI KbUnmapMdl(IN WdkTypes::PMDL Mdl, IN WdkTypes::PVOID MappedMemory, BOOLEAN NeedUnlock);
    BOOL WINAPI KbUnlockPages(WdkTypes::PMDL Mdl);
    BOOL WINAPI KbFreeMdl(WdkTypes::PMDL Mdl);

    using MAPPING_INFO = struct
    {
        WdkTypes::PVOID MappedAddress;
        WdkTypes::PVOID Mdl;
    };
    using PMAPPING_INFO = MAPPING_INFO*;

    BOOL WINAPI KbMapMemory(
        OUT PMAPPING_INFO MappingInfo,
        OPTIONAL UINT64 SrcProcessId,
        OPTIONAL UINT64 DestProcessId,
        WdkTypes::PVOID VirtualAddress,
        ULONG Size,
        WdkTypes::KPROCESSOR_MODE MapToAddressSpace = WdkTypes::UserMode,
        ULONG Protect = PAGE_READWRITE,
        WdkTypes::MEMORY_CACHING_TYPE CacheType = WdkTypes::MmNonCached,
        OPTIONAL WdkTypes::PVOID UserRequestedAddress = NULL
    );
    BOOL WINAPI KbUnmapMemory(IN PMAPPING_INFO MappingInfo);
}

namespace PhysicalMemory
{
    // Allocates contiguous physical memory in the specified range:
    BOOL WINAPI KbAllocPhysicalMemory(
        WdkTypes::PVOID LowestAcceptableAddress,
        WdkTypes::PVOID HighestAcceptableAddress,
        WdkTypes::PVOID BoundaryAddressMultiple,
        ULONG Size,
        WdkTypes::MEMORY_CACHING_TYPE CachingType,
        OUT WdkTypes::PVOID* Address
    );

    BOOL WINAPI KbFreePhysicalMemory(WdkTypes::PVOID Address);

    // Maps physical memory to a KERNEL address-space, so if you
    // wants to work with it in usermode, you should map it to usermode
    // by Mdl::MapMemory:
    BOOL WINAPI KbMapPhysicalMemory(
        IN WdkTypes::PVOID PhysicalAddress,
        ULONG Size,
        WdkTypes::MEMORY_CACHING_TYPE CachingType,
        OUT WdkTypes::PVOID* VirtualAddress
    );
    BOOL WINAPI KbUnmapPhysicalMemory(IN WdkTypes::PVOID VirtualAddress, ULONG Size);
    
    // Obtains physical address for specified virtual address 
    // in context of target process:
    BOOL WINAPI KbGetPhysicalAddress(
        IN OPTIONAL WdkTypes::PEPROCESS Process, 
        IN WdkTypes::PVOID VirtualAddress,
        OUT WdkTypes::PVOID* PhysicalAddress
    );

    BOOL WINAPI KbGetVirtualForPhysical(
        IN WdkTypes::PVOID PhysicalAddress, 
        OUT WdkTypes::PVOID* VirtualAddress    
    );

    // Reads and writes raw physical memory to buffer in context of current process:
    BOOL WINAPI KbReadPhysicalMemory(
        WdkTypes::PVOID64 PhysicalAddress,
        OUT PVOID Buffer,
        ULONG Size,
        WdkTypes::MEMORY_CACHING_TYPE CachingType = WdkTypes::MmNonCached
    );
    BOOL WINAPI KbWritePhysicalMemory(
        WdkTypes::PVOID64 PhysicalAddress,
        IN PVOID Buffer,
        ULONG Size,
        WdkTypes::MEMORY_CACHING_TYPE CachingType = WdkTypes::MmNonCached
    );
    
    BOOL WINAPI KbReadDmiMemory(OUT UCHAR DmiMemory[DmiSize], ULONG BufferSize);
}

namespace Processes
{
    namespace Descriptors
    {
        // EPROCESS/ETHREAD must be dereferenced by KbDereferenceObject,
        // HANDLE must be closed by KbCloseHandle:
        BOOL WINAPI KbGetEprocess(ULONG ProcessId, OUT WdkTypes::PEPROCESS* Process);
        BOOL WINAPI KbGetEthread(ULONG ThreadId, OUT WdkTypes::PETHREAD* Thread);
        BOOL WINAPI KbOpenProcess(
            ULONG ProcessId, 
            OUT WdkTypes::HANDLE* hProcess, 
            OPTIONAL ACCESS_MASK Access = PROCESS_ALL_ACCESS, 
            OPTIONAL ULONG Attributes = ObjFlags::_OBJ_CASE_INSENSITIVE | ObjFlags::_OBJ_KERNEL_HANDLE
        );
        BOOL WINAPI KbOpenProcessByPointer(
            WdkTypes::PEPROCESS Process, 
            OUT WdkTypes::HANDLE* hProcess, 
            OPTIONAL ACCESS_MASK Access = PROCESS_ALL_ACCESS, 
            OPTIONAL ULONG Attributes = ObjFlags::_OBJ_CASE_INSENSITIVE | ObjFlags::_OBJ_KERNEL_HANDLE,
            OPTIONAL WdkTypes::KPROCESSOR_MODE ProcessorMode = WdkTypes::KernelMode
        );
        BOOL WINAPI KbOpenThread(
            ULONG ThreadId, 
            OUT WdkTypes::HANDLE* hThread, 
            OPTIONAL ACCESS_MASK Access = PROCESS_ALL_ACCESS, 
            OPTIONAL ULONG Attributes = ObjFlags::_OBJ_CASE_INSENSITIVE | ObjFlags::_OBJ_KERNEL_HANDLE
        );
        BOOL WINAPI KbOpenThreadByPointer(
            WdkTypes::PETHREAD Thread, 
            OUT WdkTypes::HANDLE* hThread, 
            OPTIONAL ACCESS_MASK Access = PROCESS_ALL_ACCESS, 
            OPTIONAL ULONG Attributes = ObjFlags::_OBJ_CASE_INSENSITIVE | ObjFlags::_OBJ_KERNEL_HANDLE,
            OPTIONAL WdkTypes::KPROCESSOR_MODE ProcessorMode = WdkTypes::KernelMode
        );
        BOOL WINAPI KbDereferenceObject(WdkTypes::PVOID Object);
        BOOL WINAPI KbCloseHandle(WdkTypes::HANDLE Handle);

    }

    namespace Information
    {
        BOOL WINAPI KbQueryInformationProcess(
            WdkTypes::HANDLE hProcess,
            NtTypes::PROCESSINFOCLASS ProcessInfoClass,
            OUT PVOID Buffer,
            ULONG Size,
            OPTIONAL OUT PULONG ReturnLength = NULL
        );
        BOOL WINAPI KbSetInformationProcess(
            WdkTypes::HANDLE hProcess,
            NtTypes::PROCESSINFOCLASS ProcessInfoClass,
            IN PVOID Buffer,
            ULONG Size
        );
        BOOL WINAPI KbQueryInformationThread(
            WdkTypes::HANDLE hThread,
            NtTypes::THREADINFOCLASS ThreadInfoClass,
            OUT PVOID Buffer,
            ULONG Size,
            OPTIONAL OUT PULONG ReturnLength = NULL
        );
        BOOL WINAPI KbSetInformationThread(
            WdkTypes::HANDLE hThread,
            NtTypes::THREADINFOCLASS ThreadInfoClass,
            IN PVOID Buffer,
            ULONG Size
        );
    }

    namespace Threads
    {
        using NTSTATUS = ULONG;
        using _ThreadRoutine = NTSTATUS (NTAPI*)(PVOID Argument);

        BOOL WINAPI KbCreateUserThread(
            ULONG ProcessId, 
            WdkTypes::PVOID ThreadRoutine, 
            WdkTypes::PVOID Argument, 
            BOOL CreateSuspended,
            OUT OPTIONAL WdkTypes::CLIENT_ID* ClientId,
            OUT OPTIONAL WdkTypes::HANDLE* hThread
        );

        BOOL WINAPI KbCreateSystemThread(
            ULONG ProcessId, 
            WdkTypes::PVOID ThreadRoutine, 
            WdkTypes::PVOID Argument,
            OUT OPTIONAL WdkTypes::CLIENT_ID* ClientId,
            OUT OPTIONAL WdkTypes::HANDLE* hThread
        );

        BOOL WINAPI KbSuspendProcess(ULONG ProcessId);
        BOOL WINAPI KbResumeProcess(ULONG ProcessId);

        BOOL WINAPI KbGetThreadContext(ULONG ThreadId, OUT PCONTEXT Context, ULONG ContextSize, OPTIONAL WdkTypes::KPROCESSOR_MODE ProcessorMode = WdkTypes::UserMode);
        BOOL WINAPI KbSetThreadContext(ULONG ThreadId, IN PCONTEXT Context, ULONG ContextSize, OPTIONAL WdkTypes::KPROCESSOR_MODE ProcessorMode = WdkTypes::UserMode);
    }

    namespace MemoryManagement
    {
        BOOL WINAPI KbAllocUserMemory(ULONG ProcessId, ULONG Protect, ULONG Size, OUT WdkTypes::PVOID* BaseAddress);
        BOOL WINAPI KbFreeUserMemory(ULONG ProcessId, WdkTypes::PVOID BaseAddress);
        
        BOOL WINAPI KbSecureVirtualMemory(
            ULONG ProcessId,
            WdkTypes::PVOID BaseAddress,
            ULONG Size,
            ULONG ProtectRights,
            OUT WdkTypes::HANDLE* SecureHandle
        );

        BOOL WINAPI KbUnsecureVirtualMemory(
            ULONG ProcessId,
            WdkTypes::HANDLE SecureHandle
        );

        BOOL WINAPI KbReadProcessMemory(
            ULONG ProcessId,
            IN WdkTypes::PVOID BaseAddress,
            OUT PVOID Buffer,
            ULONG Size
        );

        BOOL WINAPI KbWriteProcessMemory(
            ULONG ProcessId,
            OUT WdkTypes::PVOID BaseAddress,
            IN PVOID Buffer,
            ULONG Size,
            BOOLEAN PerformCopyOnWrite = TRUE
        );

        BOOL WINAPI KbTriggerCopyOnWrite(ULONG ProcessId, IN WdkTypes::PVOID PageVirtualAddress);

        BOOL WINAPI KbGetProcessCr3Cr4(ULONG ProcessId, OUT OPTIONAL PUINT64 Cr3, OUT OPTIONAL PUINT64 Cr4);
    }

    namespace Apc
    {
        using _ApcProc = VOID(WINAPI*)(PVOID Argument);
        BOOL WINAPI KbQueueUserApc(ULONG ThreadId, WdkTypes::PVOID ApcProc, WdkTypes::PVOID Argument);
    }
}

namespace Sections
{
    BOOL WINAPI KbCreateSection(
        OUT WdkTypes::HANDLE* hSection,
        OPTIONAL LPCWSTR Name,
        UINT64 MaximumSize,
        ACCESS_MASK DesiredAccess,
        ULONG SecObjFlags, // OBJ_***
        ULONG SecPageProtection, // SEC_***
        ULONG AllocationAttributes,
        OPTIONAL WdkTypes::HANDLE hFile
    );

    BOOL WINAPI KbOpenSection(
        OUT WdkTypes::HANDLE* hSection,
        LPCWSTR Name,
        ACCESS_MASK DesiredAccess,
        ULONG SecObjFlags // OBJ_***
    );

    BOOL WINAPI KbMapViewOfSection(
        WdkTypes::HANDLE hSection,
        WdkTypes::HANDLE hProcess,
        IN OUT WdkTypes::PVOID* BaseAddress,
        ULONG CommitSize,
        IN OUT OPTIONAL UINT64* SectionOffset = NULL,
        IN OUT OPTIONAL UINT64* ViewSize = NULL,
        WdkTypes::SECTION_INHERIT SectionInherit = WdkTypes::ViewUnmap,
        ULONG AllocationType = MEM_RESERVE,
        ULONG Win32Protect = PAGE_READWRITE
    );

    BOOL WINAPI KbUnmapViewOfSection(
        WdkTypes::HANDLE hProcess,
        WdkTypes::PVOID BaseAddress
    );
}

namespace KernelShells
{
    using _GetKernelProcAddress = PVOID(WINAPI*)(LPCWSTR RoutineName);
    using _ShellCode = ULONG(WINAPI*)(
        _GetKernelProcAddress GetKernelProcAddress, // You can obtain any function address from ntoskrnl.exe/hal.dll
        OPTIONAL IN OUT PVOID Argument
    );
    // Execute specified function in Ring0 
    // into SEH-section with FPU-safe context 
    // in context of current process:
    BOOL WINAPI KbExecuteShellCode(_ShellCode ShellCode, PVOID Argument = NULL, OUT OPTIONAL PULONG Result = NULL);
}

namespace LoadableModules
{
    BOOL WINAPI KbCreateDriver(LPCWSTR DriverName, WdkTypes::PVOID DriverEntry);
    BOOL WINAPI KbLoadModule(
        WdkTypes::HMODULE hModule,
        LPCWSTR ModuleName,
        OPTIONAL WdkTypes::PVOID OnLoad = NULL,
        OPTIONAL WdkTypes::PVOID OnUnload = NULL,
        OPTIONAL WdkTypes::PVOID OnDeviceControl = NULL
    );
    BOOL WINAPI KbUnloadModule(WdkTypes::HMODULE hModule);
    BOOL WINAPI KbGetModuleHandle(LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);
    BOOL WINAPI KbCallModule(WdkTypes::HMODULE hModule, ULONG CtlCode, OPTIONAL WdkTypes::PVOID Argument = NULL);
}

namespace Hypervisor
{
    BOOL WINAPI KbVmmEnable();
    BOOL WINAPI KbVmmDisable();
    BOOL WINAPI KbVmmInterceptPage(
        IN OPTIONAL WdkTypes::PVOID64 PhysicalAddress,
        IN OPTIONAL WdkTypes::PVOID64 OnReadPhysicalAddress,
        IN OPTIONAL WdkTypes::PVOID64 OnWritePhysicalAddress,
        IN OPTIONAL WdkTypes::PVOID64 OnExecutePhysicalAddress,
        IN OPTIONAL WdkTypes::PVOID64 OnExecuteReadPhysicalAddress,
        IN OPTIONAL WdkTypes::PVOID64 OnExecuteWritePhysicalAddress
    );
    BOOL WINAPI KbVmmDeinterceptPage(IN OPTIONAL WdkTypes::PVOID64 PhysicalAddress);
}

namespace Stuff
{
    BOOL WINAPI KbGetKernelProcAddress(LPCWSTR RoutineName, WdkTypes::PVOID* KernelAddress);
    BOOL WINAPI KbStallExecutionProcessor(ULONG Microseconds);
    BOOL WINAPI KbBugCheck(ULONG Status);
    BOOL WINAPI KbFindSignature(
        OPTIONAL ULONG ProcessId,
        WdkTypes::PVOID Memory, // Both user and kernel
        ULONG Size,
        LPCSTR Signature, // "\x11\x22\x33\x00\x44"
        LPCSTR Mask, // "...?."
        OUT WdkTypes::PVOID* FoundAddress
    );
}