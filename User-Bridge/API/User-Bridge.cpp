#include <Windows.h>

#include "CtlTypes.h"
#include "User-Bridge.h"

#include "DriversUtils.h"


namespace KbLoader {

    constexpr LPCWSTR KbDriverName = L"Kernel-Bridge";
    constexpr LPCWSTR KbDeviceName = L"\\\\.\\Kernel-Bridge";

    static HANDLE hDriver = INVALID_HANDLE_VALUE;

    BOOL WINAPI KbLoad(LPCWSTR DriverPath)
    {
        // Check whether the Kernel-Bridge is already loaded:
        if (hDriver != INVALID_HANDLE_VALUE) return TRUE;
        hDriver = OpenDevice(KbDeviceName);
        if (hDriver != INVALID_HANDLE_VALUE) return TRUE;

        // Installing driver:
        BOOL Status = InstallDriver(DriverPath, KbDriverName);
        if (!Status) return FALSE;

        // Obtaining it's handle:
        hDriver = OpenDevice(KbDeviceName);
        if (hDriver == INVALID_HANDLE_VALUE) {
            DeleteDriver(KbDriverName);
            return FALSE;
        }

        return TRUE;
    }

    BOOL WINAPI KbUnload()
    {
        if (hDriver == INVALID_HANDLE_VALUE) return TRUE;
        CloseHandle(hDriver);
        return DeleteDriver(KbDriverName);
    }
}

static inline BOOL WINAPI KbSendRequest(
    Ctls::KbCtlIndices Index, 
    IN PVOID Input = NULL, 
    ULONG InputSize = 0, 
    OUT PVOID Output = NULL, 
    ULONG OutputSize = 0
) {
    return SendRawIOCTL(KbLoader::hDriver, CTL_BASE + Index, Input, InputSize, Output, OutputSize);
}

namespace IO {
    namespace Beeper {
        BOOL WINAPI KbSetBeeperRegime() {
            return KbSendRequest(Ctls::KbSetBeeperRegime);
        }

        BOOL WINAPI KbStartBeeper() {
            return KbSendRequest(Ctls::KbStartBeeper);
        }

        BOOL WINAPI KbStopBeeper() {
            return KbSendRequest(Ctls::KbStopBeeper);
        }

        BOOL WINAPI KbSetBeeperIn() {
            return KbSendRequest(Ctls::KbSetBeeperIn);
        }

        BOOL WINAPI KbSetBeeperOut() {
            return KbSendRequest(Ctls::KbSetBeeperOut);
        }

        BOOL WINAPI KbSetBeeperDivider(USHORT Divider) {
            KB_SET_BEEPER_DIVIDER_IN Input = {};
            Input.Divider = Divider;
            return KbSendRequest(Ctls::KbSetBeeperDivider, &Input, sizeof(Input));
        }

        BOOL WINAPI KbSetBeeperFrequency(USHORT Frequency) {
            KB_SET_BEEPER_FREQUENCY_IN Input = {};
            Input.Frequency = Frequency;
            return KbSendRequest(Ctls::KbSetBeeperFrequency, &Input, sizeof(Input));
        }
    }

    namespace RW {
    
    }

    namespace Iopl {
        BOOL WINAPI KbRaiseIopl() {
            return KbSendRequest(Ctls::KbRaiseIopl);
        }

        BOOL WINAPI KbResetIopl() {
            return KbSendRequest(Ctls::KbResetIopl);
        }    
    }
}

namespace CPU {
    BOOL WINAPI KbCli() {
        return KbSendRequest(Ctls::KbCli);
    }

    BOOL WINAPI KbSti() {
        return KbSendRequest(Ctls::KbSti);
    }    

    BOOL WINAPI KbHlt() {
        return KbSendRequest(Ctls::KbHlt);
    }    

    BOOL WINAPI KbReadMsr(ULONG Index, OUT PUINT64 MsrValue) {
        if (!MsrValue) return FALSE;
        KB_READ_MSR_IN Input = {};
        KB_READ_MSR_OUT Output = {};
        Input.Index = Index;
        BOOL Status = KbSendRequest(Ctls::KbReadMsr, &Input, sizeof(Input), &Output, sizeof(Output));
        *MsrValue = Output.Value;
        return Status;
    }

    BOOL WINAPI KbWriteMsr(ULONG Index, IN UINT64 MsrValue) {
        KB_WRITE_MSR_IN Input = {};
        Input.Index = Index;
        Input.Value = MsrValue;
        return KbSendRequest(Ctls::KbWriteMsr, &Input, sizeof(Input));
    }

    BOOL WINAPI KbCpuid(ULONG FunctionIdEax, OUT PCPUID_INFO CpuidInfo) {
        if (!CpuidInfo) return FALSE;
        KB_CPUID_IN Input = {};
        KB_CPUID_OUT Output = {};
        Input.FunctionIdEax = FunctionIdEax;
        BOOL Status = KbSendRequest(Ctls::KbCpuid, &Input, sizeof(Input), &Output, sizeof(Output));
        CpuidInfo->Eax = Output.Eax;
        CpuidInfo->Ebx = Output.Ebx;
        CpuidInfo->Ecx = Output.Ecx;
        CpuidInfo->Edx = Output.Edx;
        return Status;
    }

    BOOL WINAPI KbCpuidEx(ULONG FunctionIdEax, ULONG SubfunctionIdEcx, OUT PCPUID_INFO CpuidInfo) {
        if (!CpuidInfo) return FALSE;
        KB_CPUIDEX_IN Input = {};
        KB_CPUID_OUT Output = {};
        Input.FunctionIdEax = FunctionIdEax;
        Input.SubfunctionIdEcx = SubfunctionIdEcx;
        BOOL Status = KbSendRequest(Ctls::KbCpuidEx, &Input, sizeof(Input), &Output, sizeof(Output));
        CpuidInfo->Eax = Output.Eax;
        CpuidInfo->Ebx = Output.Ebx;
        CpuidInfo->Ecx = Output.Ecx;
        CpuidInfo->Edx = Output.Edx;
        return Status;
    }

    BOOL WINAPI KbReadPmc(ULONG Counter, OUT PUINT64 PmcValue) {
        if (!PmcValue) return FALSE;
        KB_READ_PMC_IN Input = {};
        KB_READ_PMC_OUT Output = {};
        Input.Counter = Counter;
        BOOL Status = KbSendRequest(Ctls::KbReadPmc, &Input, sizeof(Input), &Output, sizeof(Output));
        *PmcValue = Output.Value;
        return Status;
    }

    BOOL WINAPI KbReadTsc(OUT PUINT64 TscValue) {
        if (!TscValue) return FALSE;
        KB_READ_TSC_OUT Output = {};
        BOOL Status = KbSendRequest(Ctls::KbReadPmc, NULL, 0, &Output, sizeof(Output));
        *TscValue = Output.Value;
        return Status;
    }

    BOOL WINAPI KbReadTscp(OUT PUINT64 TscValue, OUT OPTIONAL PULONG TscAux) {
        if (!TscValue) return FALSE;
        KB_READ_TSCP_OUT Output = {};
        BOOL Status = KbSendRequest(Ctls::KbReadPmc, NULL, 0, &Output, sizeof(Output));
        *TscValue = Output.Value;
        if (TscAux) *TscAux = Output.TscAux;
        return Status;
    }
}

namespace VirtualMemory {
    BOOL WINAPI KbAllocKernelMemory(ULONG Size, BOOLEAN Executable, OUT WdkTypes::PVOID* KernelAddress) {
        if (!Size || !KernelAddress) return FALSE;
        KB_ALLOC_KERNEL_MEMORY_IN Input = {};
        KB_ALLOC_KERNEL_MEMORY_OUT Output = {};
        Input.Size = Size;
        Input.Executable = Executable;
        BOOL Status = KbSendRequest(Ctls::KbAllocKernelMemory, &Input, sizeof(Input), &Output, sizeof(Output));
        *KernelAddress = Output.KernelAddress;
        return Status;
    }

    BOOL WINAPI KbFreeKernelMemory(IN WdkTypes::PVOID KernelAddress) {
        if (!KernelAddress) return FALSE;
        KB_FREE_KERNEL_MEMORY_IN Input = {};
        Input.KernelAddress = KernelAddress;
        return KbSendRequest(Ctls::KbAllocKernelMemory, &Input, sizeof(Input));
    }

    BOOL WINAPI KbCopyMoveMemory(OUT WdkTypes::PVOID Dest, IN WdkTypes::PVOID Src, ULONG Size, BOOLEAN Intersects) {
        if (!Dest || !Src || !Size) return FALSE;
        KB_COPY_MOVE_MEMORY_IN Input = {};
        Input.Src = Src;
        Input.Dest = Dest;
        Input.Size = Size;
        Input.Intersects = Intersects;
        return KbSendRequest(Ctls::KbCopyMoveMemory, &Input, sizeof(Input));
    }

    BOOL WINAPI KbFillMemory(IN WdkTypes::PVOID Address, UCHAR Filler, ULONG Size) {
        if (!Address || !Size) return FALSE;
        KB_FILL_MEMORY_IN Input = {};
        Input.Address = Address;
        Input.Size = Size;
        Input.Filler = Filler;
        return KbSendRequest(Ctls::KbFillMemory, &Input, sizeof(Input));
    }

    BOOL WINAPI KbEqualMemory(IN WdkTypes::PVOID Src, IN WdkTypes::PVOID Dest, ULONG Size, OUT PBOOLEAN Equals) {
        if (!Src || !Dest || !Size || !Equals) return FALSE;
        KB_EQUAL_MEMORY_IN Input = {};
        KB_EQUAL_MEMORY_OUT Output = {};
        Input.Src = Src;
        Input.Dest = Dest;
        Input.Size = Size;
        BOOL Status = KbSendRequest(Ctls::KbEqualMemory, &Input, sizeof(Input), &Output, sizeof(Output));
        *Equals = Output.Equals;
        return Status;
    }
}

namespace Mdl {
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
    ) {
        if (!MappingInfo || !Size) return FALSE;
        KB_MAP_MEMORY_IN Input = {};
        KB_MAP_MEMORY_OUT Output = {};
        Input.SrcProcessId = SrcProcessId;
        Input.DestProcessId = DestProcessId;
        Input.VirtualAddress = VirtualAddress;
        Input.Size = Size;
        Input.AccessMode = AccessMode;
        Input.LockOperation = LockOperation;
        Input.CacheType = CacheType;
        Input.UserRequestedAddress;
        BOOL Status = KbSendRequest(Ctls::KbMapMemory, &Input, sizeof(Input), &Output, sizeof(Output));
        MappingInfo->MappedAddress = Output.BaseAddress;
        MappingInfo->Mdl = Output.Mdl;
        return Status;
    }

    BOOL WINAPI KbUnmapMemory(IN PMAPPING_INFO MappingInfo) {
        if (!MappingInfo || !MappingInfo->Mdl) return FALSE;
        KB_UNMAP_MEMORY_IN Input = {};
        Input.Mdl = MappingInfo->Mdl;
        Input.BaseAddress = MappingInfo->MappedAddress;
        return KbSendRequest(Ctls::KbUnmapMemory, &Input, sizeof(Input));
    }
}

namespace PhysicalMemory {
    BOOL WINAPI KbMapPhysicalMemory(IN WdkTypes::PVOID PhysicalAddress, ULONG Size, OUT WdkTypes::PVOID* VirtualAddress) {
        if (!Size || !VirtualAddress) return FALSE;
        KB_MAP_PHYSICAL_MEMORY_IN Input = {};
        KB_MAP_PHYSICAL_MEMORY_OUT Output = {};
        Input.PhysicalAddress = PhysicalAddress;
        Input.Size = Size;
        BOOL Status = KbSendRequest(Ctls::KbMapPhysicalMemory, &Input, sizeof(Input), &Output, sizeof(Output));
        *VirtualAddress = Output.VirtualAddress;
        return Status;
    }

    BOOL WINAPI KbUnmapPhysicalMemory(IN WdkTypes::PVOID VirtualAddress, ULONG Size) {
        if (!VirtualAddress || !Size) return FALSE;
        KB_UNMAP_PHYSICAL_MEMORY_IN Input = {};
        Input.VirtualAddress = VirtualAddress;
        Input.Size = Size;
        return KbSendRequest(Ctls::KbUnmapPhysicalMemory, &Input, sizeof(Input));
    }

    BOOL WINAPI KbGetPhysicalAddress(
        IN OPTIONAL WdkTypes::PEPROCESS Process, 
        IN WdkTypes::PVOID VirtualAddress,
        OUT WdkTypes::PVOID* PhysicalAddress
    ) {
        if (!PhysicalAddress) return FALSE;
        KB_GET_PHYSICAL_ADDRESS_IN Input = {};
        KB_GET_PHYSICAL_ADDRESS_OUT Output = {};
        Input.Process = Process;
        Input.VirtualAddress = VirtualAddress;
        BOOL Status = KbSendRequest(Ctls::KbMapPhysicalMemory, &Input, sizeof(Input), &Output, sizeof(Output));
        *PhysicalAddress = Output.PhysicalAddress;
        return Status;
    }
}