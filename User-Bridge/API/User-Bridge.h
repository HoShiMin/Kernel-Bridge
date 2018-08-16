#pragma once

namespace KbLoader {
    BOOL WINAPI KbLoad(LPCWSTR DriverPath);
    BOOL WINAPI KbUnload();
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
    
    }

    namespace Iopl {
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
        WdkTypes::KPROCESSOR_MODE AccessMode,
        WdkTypes::LOCK_OPERATION LockOperation,
        WdkTypes::MEMORY_CACHING_TYPE CacheType,
        OPTIONAL WdkTypes::PVOID UserRequestedAddress
    );

    BOOL WINAPI KbUnmapMemory(IN PMAPPING_INFO MappingInfo);
}

namespace PhysicalMemory {
    BOOL WINAPI KbMapPhysicalMemory(IN WdkTypes::PVOID PhysicalAddress, ULONG Size, OUT WdkTypes::PVOID* VirtualAddress);
    BOOL WINAPI KbUnmapPhysicalMemory(IN WdkTypes::PVOID VirtualAddress, ULONG Size);
    BOOL WINAPI KbGetPhysicalAddress(
        IN OPTIONAL WdkTypes::PEPROCESS Process, 
        IN WdkTypes::PVOID VirtualAddress,
        OUT WdkTypes::PVOID* PhysicalAddress
    );
}