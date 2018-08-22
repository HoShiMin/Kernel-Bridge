#pragma once

namespace KbLoader {
    BOOL WINAPI KbLoad(LPCWSTR DriverPath);
    BOOL WINAPI KbUnload();
}

namespace AddressRange {
    inline BOOLEAN IsUserAddress(PVOID Address) {
        return reinterpret_cast<SIZE_T>(Address) < (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
    }

    inline BOOLEAN IsKernelAddress(PVOID Address) {
        return reinterpret_cast<SIZE_T>(Address) >= (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
    }

    inline BOOLEAN IsUserAddressIa32(UINT64 Address) {
        return Address < 0x80000000;
    }

    inline BOOLEAN IsUserAddressAmd64(UINT64 Address) {
        return Address < 0x8000000000000000;
    }

    inline BOOLEAN IsKernelAddressIa32(UINT64 Address) {
        return Address > 0x7FFFFFFF;
    }

    inline BOOLEAN IsKernelAddressAmd64(UINT64 Address) {
        return Address > 0x7FFFFFFFFFFFFFFF;
    }
}

namespace IO {
    namespace Beeper {
        BOOL WINAPI KbSetBeeperRegime();
        BOOL WINAPI KbStartBeeper();
        BOOL WINAPI KbStopBeeper();
        BOOL WINAPI KbSetBeeperIn();
        BOOL WINAPI KbSetBeeperOut();
        BOOL WINAPI KbSetBeeperDivider(USHORT Divider);
        BOOL WINAPI KbSetBeeperFrequency(USHORT Frequency);
    }

    namespace RW {
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

    namespace Iopl {
        // Allows to use 'in/out/cli/sti' in usermode:
        BOOL WINAPI KbRaiseIopl();
        BOOL WINAPI KbResetIopl();
    }
}

namespace CPU {
    BOOL WINAPI KbCli();
    BOOL WINAPI KbSti();
    BOOL WINAPI KbHlt();

    BOOL WINAPI KbReadMsr(ULONG Index, OUT PUINT64 MsrValue);
    BOOL WINAPI KbWriteMsr(ULONG Index, IN UINT64 MsrValue);

    using CPUID_INFO = struct {
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

namespace VirtualMemory {
    // Supports both user- and kernel-memory in context of current process:
    BOOL WINAPI KbAllocKernelMemory(ULONG Size, BOOLEAN Executable, OUT WdkTypes::PVOID* KernelAddress);
    BOOL WINAPI KbFreeKernelMemory(IN WdkTypes::PVOID KernelAddress);
    BOOL WINAPI KbCopyMoveMemory(OUT WdkTypes::PVOID Dest, IN WdkTypes::PVOID Src, ULONG Size, BOOLEAN Intersects);
    BOOL WINAPI KbFillMemory(IN WdkTypes::PVOID Address, UCHAR Filler, ULONG Size);
    BOOL WINAPI KbEqualMemory(IN WdkTypes::PVOID Src, IN WdkTypes::PVOID Dest, ULONG Size, OUT PBOOLEAN Equals);
}

namespace Mdl {
    using MAPPING_INFO = struct {
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
        WdkTypes::KPROCESSOR_MODE AccessMode = WdkTypes::UserMode,
        WdkTypes::LOCK_OPERATION LockOperation = WdkTypes::IoWriteAccess,
        WdkTypes::MEMORY_CACHING_TYPE CacheType = WdkTypes::MmNonCached,
        OPTIONAL WdkTypes::PVOID UserRequestedAddress = NULL
    );

    BOOL WINAPI KbUnmapMemory(IN PMAPPING_INFO MappingInfo);
}

namespace PhysicalMemory {
    // Maps physical memory to a KERNEL address-space, so if you
    // wants to work with it in usermode, you should map it to usermode
    // by Mdl::MapMemory:
    BOOL WINAPI KbMapPhysicalMemory(IN WdkTypes::PVOID PhysicalAddress, ULONG Size, OUT WdkTypes::PVOID* VirtualAddress);
    BOOL WINAPI KbUnmapPhysicalMemory(IN WdkTypes::PVOID VirtualAddress, ULONG Size);
    
    // Obtains physical address for specified virtual address 
    // in context of target process:
    BOOL WINAPI KbGetPhysicalAddress(
        IN OPTIONAL WdkTypes::PEPROCESS Process, 
        IN WdkTypes::PVOID VirtualAddress,
        OUT WdkTypes::PVOID* PhysicalAddress
    );
    
    // Reads and writes raw physical memory to buffer in context of current process:
    BOOL WINAPI KbReadPhysicalMemory(WdkTypes::PVOID64 PhysicalAddress, OUT PVOID Buffer, ULONG Size);
    BOOL WINAPI KbWritePhysicalMemory(WdkTypes::PVOID64 PhysicalAddress, IN PVOID Buffer, ULONG Size);
    
    BOOL WINAPI KbReadDmiMemory(OUT UCHAR DmiMemory[DmiSize], ULONG BufferSize);
}

namespace Processes {
    namespace Descriptors {
        // EPROCESS/ETHREAD must be dereferenced by KbDereferenceObject,
        // HANDLE must be closed by KbCloseHandle:
        BOOL WINAPI KbGetEprocess(ULONG ProcessId, OUT WdkTypes::PEPROCESS* Process);
        BOOL WINAPI KbGetEthread(ULONG ThreadId, OUT WdkTypes::PETHREAD* Thread);
        BOOL WINAPI KbOpenProcess(ULONG ProcessId, OUT WdkTypes::HANDLE* hProcess);
        BOOL WINAPI KbDereferenceObject(WdkTypes::PVOID Object);
        BOOL WINAPI KbCloseHandle(WdkTypes::HANDLE Handle);
    }

    namespace Threads {
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
    }

    namespace MemoryManagement {
        BOOL WINAPI KbAllocUserMemory(ULONG ProcessId, ULONG Protect, ULONG Size, OUT WdkTypes::PVOID* BaseAddress);
        BOOL WINAPI KbFreeUserMemory(ULONG ProcessId, WdkTypes::PVOID BaseAddress);
        
        BOOL WINAPI KbReadProcessMemory(ULONG ProcessId, IN WdkTypes::PVOID BaseAddress, OUT PVOID Buffer, ULONG Size);
        BOOL WINAPI KbWriteProcessMemory(ULONG ProcessId, OUT WdkTypes::PVOID BaseAddress, IN PVOID Buffer, ULONG Size);
        
        BOOL WINAPI KbSuspendProcess(ULONG ProcessId);
        BOOL WINAPI KbResumeProcess(ULONG ProcessId);
    }
}

namespace Stuff {
    BOOL WINAPI KbGetKernelProcAddress(LPCWSTR RoutineName, WdkTypes::PVOID* KernelAddress);
    BOOL WINAPI KbStallExecutionProcessor(ULONG Microseconds);
    BOOL WINAPI KbBugCheck(ULONG Status);
    BOOL WINAPI KbCreateDriver(LPCWSTR DriverName, WdkTypes::PVOID DriverEntry);
}