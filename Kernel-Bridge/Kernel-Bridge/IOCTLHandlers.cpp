#include <fltKernel.h>
#include <ntstrsafe.h>
#include <stdarg.h>

#include "WdkTypes.h"
#include "CtlTypes.h"
#include "IOCTLHandlers.h"
#include "LoadableModules.h"

#include "PTE.h"

#include "../API/MemoryUtils.h"
#include "../API/PteUtils.h"
#include "../API/ProcessesUtils.h"
#include "../API/SectionsUtils.h"
#include "../API/IO.h"
#include "../API/CPU.h"
#include "../API/Importer.h"
#include "../API/KernelShells.h"
#include "../API/StringsAPI.h"
#include "../API/Signatures.h"
#include "../API/Hypervisor.h"

#include "IOCTLs.h"

#ifdef _AMD64_
extern "C" size_t __cdecl __readcr3();
extern "C" size_t __cdecl __readcr4();
#else
extern "C" unsigned long __cdecl __readcr4();
#endif

extern volatile LONG KbHandlesCount;

namespace
{
    NTSTATUS FASTCALL KbGetDriverApiVersion(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (RequestInfo->OutputBufferSize != sizeof(KB_GET_DRIVER_API_VERSION_OUT)) 
            return STATUS_INFO_LENGTH_MISMATCH;
        auto Output = reinterpret_cast<PKB_GET_DRIVER_API_VERSION_OUT>(RequestInfo->OutputBuffer);
        if (!Output) return STATUS_INVALID_PARAMETER;
        Output->Version = KB_API_VERSION;
        *ResponseLength = sizeof(*Output);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbGetHandlesCount(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (RequestInfo->OutputBufferSize != sizeof(KB_GET_HANDLES_COUNT_OUT)) 
            return STATUS_INFO_LENGTH_MISMATCH;
        auto Output = reinterpret_cast<PKB_GET_HANDLES_COUNT_OUT>(RequestInfo->OutputBuffer);
        if (!Output) return STATUS_INVALID_PARAMETER;
        Output->HandlesCount = KbHandlesCount;
        *ResponseLength = sizeof(*Output);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbSetBeeperRegime(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::Beeper::SetBeeperRegime();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbStartBeeper(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::Beeper::StartBeeper();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbStopBeeper(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::Beeper::StopBeeper();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbSetBeeperIn(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::Beeper::SetBeeperIn();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbSetBeeperOut(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::Beeper::SetBeeperOut();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbSetBeeperDivider(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);
        if (RequestInfo->InputBufferSize != sizeof(KB_SET_BEEPER_DIVIDER_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;
        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;
        IO::Beeper::SetBeeperDivider(static_cast<PKB_SET_BEEPER_DIVIDER_IN>(RequestInfo->InputBuffer)->Divider);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbSetBeeperFrequency(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);
        if (RequestInfo->InputBufferSize != sizeof(KB_SET_BEEPER_FREQUENCY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;
        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;
        IO::Beeper::SetBeeperFrequency(static_cast<PKB_SET_BEEPER_FREQUENCY_IN>(RequestInfo->InputBuffer)->Frequency);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbReadPort(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;
        
        if (RequestInfo->InputBufferSize != sizeof(KB_READ_PORT_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        switch (RequestInfo->OutputBufferSize) {
        case sizeof(UCHAR): {
            static_cast<PKB_READ_PORT_BYTE_OUT>(RequestInfo->OutputBuffer)->Value =
                IO::RW::ReadPortByte(static_cast<PKB_READ_PORT_IN>(RequestInfo->InputBuffer)->PortNumber);
            break;
        }
        case sizeof(USHORT): {
            static_cast<PKB_READ_PORT_WORD_OUT>(RequestInfo->OutputBuffer)->Value =
                IO::RW::ReadPortWord(static_cast<PKB_READ_PORT_IN>(RequestInfo->InputBuffer)->PortNumber);
            break;
        }
        case sizeof(ULONG): {
            static_cast<PKB_READ_PORT_DWORD_OUT>(RequestInfo->OutputBuffer)->Value =
                IO::RW::ReadPortDword(static_cast<PKB_READ_PORT_IN>(RequestInfo->InputBuffer)->PortNumber);
            break;
        }
        default:
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbReadPortString(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_READ_PORT_STRING_IN>(RequestInfo->InputBuffer);
        if (RequestInfo->InputBufferSize != sizeof(KB_READ_PORT_STRING_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        ULONG BytesToReadCount = Input->Count * Input->Granularity;
        if (RequestInfo->OutputBufferSize < BytesToReadCount) 
            return STATUS_INFO_LENGTH_MISMATCH;

        switch (Input->Granularity) {
        case sizeof(UCHAR): {
            IO::RW::ReadPortByteString(
                Input->PortNumber,
                static_cast<PKB_READ_PORT_STRING_OUT>(RequestInfo->OutputBuffer)->ByteString,
                Input->Count
            );
            break;
        }
        case sizeof(USHORT): {
            IO::RW::ReadPortWordString(
                Input->PortNumber,
                static_cast<PKB_READ_PORT_STRING_OUT>(RequestInfo->OutputBuffer)->WordString,
                Input->Count
            );
            break;            
        }
        case sizeof(ULONG): {
            IO::RW::ReadPortDwordString(
                Input->PortNumber,
                static_cast<PKB_READ_PORT_STRING_OUT>(RequestInfo->OutputBuffer)->DwordString,
                Input->Count
            );
            break;            
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }

        *ResponseLength = BytesToReadCount;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbWritePort(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_WRITE_PORT_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_WRITE_PORT_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        switch (Input->Granularity) {
        case sizeof(UCHAR): {
            IO::RW::WritePortByte(Input->PortNumber, Input->Byte);
            break;
        }
        case sizeof(USHORT): {
            IO::RW::WritePortWord(Input->PortNumber, Input->Word);
            break;
        }
        case sizeof(ULONG): {
            IO::RW::WritePortDword(Input->PortNumber, Input->Dword);
            break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbWritePortString(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize <= sizeof(KB_WRITE_PORT_STRING_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_WRITE_PORT_STRING_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        if (Input->BufferSize < Input->Count * Input->Granularity)
            return STATUS_INFO_LENGTH_MISMATCH;

        switch (Input->Granularity) {
        case sizeof(UCHAR): {
            IO::RW::WritePortByteString(Input->PortNumber, reinterpret_cast<unsigned char*>(Input->Buffer), Input->Count);
            break;
        }
        case sizeof(USHORT): {
            IO::RW::WritePortWordString(Input->PortNumber, reinterpret_cast<unsigned short*>(Input->Buffer), Input->Count);
            break;
        }
        case sizeof(ULONG): {
            IO::RW::WritePortDwordString(Input->PortNumber, reinterpret_cast<unsigned long*>(Input->Buffer), Input->Count);
            break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbCli(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        CPU::CLI();
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbSti(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        CPU::STI();
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbHlt(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        CPU::HLT();
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbReadMsr(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_READ_MSR_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_READ_MSR_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        static_cast<PKB_READ_MSR_OUT>(RequestInfo->OutputBuffer)->Value =
            CPU::RDMSR(static_cast<PKB_READ_MSR_IN>(RequestInfo->InputBuffer)->Index);

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbWriteMsr(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_WRITE_MSR_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        CPU::WRMSR(
            static_cast<PKB_WRITE_MSR_IN>(RequestInfo->InputBuffer)->Index,
            static_cast<PKB_WRITE_MSR_IN>(RequestInfo->InputBuffer)->Value
        );

        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbCpuid(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_CPUID_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_CPUID_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        CPU::CPUID(
            static_cast<PKB_CPUID_IN>(RequestInfo->InputBuffer)->FunctionIdEax,
            static_cast<int*>(RequestInfo->OutputBuffer)
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbCpuidEx(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_CPUIDEX_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_CPUID_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        CPU::CPUIDEX(
            static_cast<PKB_CPUIDEX_IN>(RequestInfo->InputBuffer)->FunctionIdEax,
            static_cast<PKB_CPUIDEX_IN>(RequestInfo->InputBuffer)->SubfunctionIdEcx,
            static_cast<int*>(RequestInfo->OutputBuffer)
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbReadPmc(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_READ_PMC_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_READ_PMC_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        static_cast<PKB_READ_PMC_OUT>(RequestInfo->OutputBuffer)->Value =
            CPU::RDPMC(static_cast<PKB_READ_PMC_IN>(RequestInfo->InputBuffer)->Counter);

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbReadTsc(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (RequestInfo->OutputBufferSize != sizeof(KB_READ_TSC_OUT)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        static_cast<PKB_READ_TSC_OUT>(RequestInfo->OutputBuffer)->Value = CPU::RDTSC();

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbReadTscp(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (RequestInfo->OutputBufferSize != sizeof(KB_READ_TSC_OUT)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        static_cast<PKB_READ_TSCP_OUT>(RequestInfo->OutputBuffer)->Value = 
            CPU::RDTSCP(&static_cast<PKB_READ_TSCP_OUT>(RequestInfo->OutputBuffer)->TscAux);

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;        
    }

    NTSTATUS FASTCALL KbAllocKernelMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_ALLOC_KERNEL_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_ALLOC_KERNEL_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_ALLOC_KERNEL_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_ALLOC_KERNEL_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        Output->KernelAddress = reinterpret_cast<WdkTypes::PVOID>(
            Input->Executable
                ? VirtualMemory::AllocFromPoolExecutable(Input->Size)
                : VirtualMemory::AllocFromPool(Input->Size)
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
        return Output->KernelAddress ? STATUS_SUCCESS : STATUS_MEMORY_NOT_ALLOCATED;        
    }

    NTSTATUS FASTCALL KbFreeKernelMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FREE_KERNEL_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FREE_KERNEL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->KernelAddress) return STATUS_INVALID_PARAMETER;

        VirtualMemory::FreePoolMemory(reinterpret_cast<PVOID>(Input->KernelAddress));
        
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbAllocNonCachedMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_ALLOC_NON_CACHED_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_ALLOC_NON_CACHED_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_ALLOC_NON_CACHED_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_ALLOC_NON_CACHED_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        Output->KernelAddress = reinterpret_cast<WdkTypes::PVOID>(
            VirtualMemory::AllocNonCachedNorInitialized(Input->Size)
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
        return Output->KernelAddress ? STATUS_SUCCESS : STATUS_MEMORY_NOT_ALLOCATED;        
    }

    NTSTATUS FASTCALL KbFreeNonCachedMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FREE_NON_CACHED_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FREE_NON_CACHED_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->KernelAddress) return STATUS_INVALID_PARAMETER;

        VirtualMemory::FreeNonCachedMemory(reinterpret_cast<PVOID>(Input->KernelAddress), Input->Size);
        
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbCopyMoveMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_COPY_MOVE_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_COPY_MOVE_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Src || !Input->Dest) return STATUS_INVALID_PARAMETER;

        if (!Input->Size) return STATUS_SUCCESS;

        BOOLEAN Status = FALSE; 
        __try {
            Status = VirtualMemory::CopyMemory(
                reinterpret_cast<PVOID>(Input->Dest),
                reinterpret_cast<PVOID>(Input->Src),
                Input->Size,
                Input->Intersects,
                TRUE
            );
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_UNSUCCESSFUL;
        }

        return Status ? STATUS_SUCCESS : STATUS_MEMORY_NOT_ALLOCATED;
    }

    NTSTATUS FASTCALL KbFillMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FILL_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FILL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Address) return STATUS_INVALID_PARAMETER;

        PVOID Address = reinterpret_cast<PVOID>(Input->Address);

        using namespace VirtualMemory;
        using namespace AddressRange;
        if (IsKernelAddress(Address) && !IsMemoryRangePresent(Address, Input->Size))
            return STATUS_MEMORY_NOT_ALLOCATED;

        __try {
            RtlFillMemory(reinterpret_cast<PVOID>(Input->Address), Input->Size, Input->Filler);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbEqualMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_EQUAL_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_EQUAL_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_EQUAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Src || !Input->Dest || !RequestInfo->OutputBuffer) return STATUS_INVALID_PARAMETER;

        PVOID Src = reinterpret_cast<PVOID>(Input->Src);
        PVOID Dest = reinterpret_cast<PVOID>(Input->Dest);

        using namespace VirtualMemory;
        using namespace AddressRange;

        if (IsKernelAddress(Src) && !IsMemoryRangePresent(Src, Input->Size))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (IsKernelAddress(Dest) && !IsMemoryRangePresent(Dest, Input->Size))
            return STATUS_MEMORY_NOT_ALLOCATED;

        *ResponseLength = RequestInfo->OutputBufferSize;

        __try {
            static_cast<PKB_EQUAL_MEMORY_OUT>(RequestInfo->OutputBuffer)->Equals = RtlEqualMemory(
                reinterpret_cast<PVOID>(Input->Src),
                reinterpret_cast<PVOID>(Input->Dest),
                Input->Size
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            static_cast<PKB_EQUAL_MEMORY_OUT>(RequestInfo->OutputBuffer)->Equals = FALSE;
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbAllocateMdl(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_ALLOCATE_MDL_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_ALLOCATE_MDL_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_ALLOCATE_MDL_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_ALLOCATE_MDL_OUT>(RequestInfo->OutputBuffer);
        if (!Input || !Output || !Input->VirtualAddress || !Input->Size) return STATUS_INVALID_PARAMETER;

        Output->Mdl = reinterpret_cast<WdkTypes::PMDL>(
            IoAllocateMdl(
                reinterpret_cast<PVOID>(Input->VirtualAddress),
                Input->Size,
                FALSE,
                FALSE,
                NULL
            )
        );

        *ResponseLength = sizeof(*Output);
        return Output->Mdl ? STATUS_SUCCESS : STATUS_INVALID_ADDRESS;
    }

    NTSTATUS FASTCALL KbProbeAndLockPages(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_PROBE_AND_LOCK_PAGES_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_PROBE_AND_LOCK_PAGES_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Mdl) return STATUS_INVALID_PARAMETER;

        NTSTATUS Status = STATUS_SUCCESS;

        if (Input->ProcessId && reinterpret_cast<HANDLE>(Input->ProcessId) != PsGetCurrentProcessId()) {
            PEPROCESS Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(Input->ProcessId));
            if (!Process) return STATUS_NOT_FOUND;
            __try {
                MmProbeAndLockProcessPages(
                    reinterpret_cast<PMDL>(Input->Mdl),
                    Process,
                    static_cast<KPROCESSOR_MODE>(Input->ProcessorMode),
                    static_cast<LOCK_OPERATION>(Input->LockOperation)
                );
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = STATUS_UNSUCCESSFUL;
            }
            ObDereferenceObject(Process);
        } else {
            __try {
                MmProbeAndLockPages(
                    reinterpret_cast<PMDL>(Input->Mdl),
                    static_cast<KPROCESSOR_MODE>(Input->ProcessorMode),
                    static_cast<LOCK_OPERATION>(Input->LockOperation)
                );
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = STATUS_UNSUCCESSFUL;
            }
        }

        return Status;
    }

    NTSTATUS FASTCALL KbMapMdl(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_MAP_MDL_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_MAP_MDL_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_MAP_MDL_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_MAP_MDL_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        PEPROCESS SrcProcess = NULL, DestProcess = NULL;
        HANDLE CurrentProcessId = PsGetCurrentProcessId();
        
        if (Input->SrcProcessId && reinterpret_cast<HANDLE>(Input->SrcProcessId) != CurrentProcessId) { 
            SrcProcess = Processes::Descriptors::GetEPROCESS(
                reinterpret_cast<HANDLE>(Input->SrcProcessId)
            );
            if (!SrcProcess) return STATUS_NOT_FOUND;
        }

        if (Input->DestProcessId && reinterpret_cast<HANDLE>(Input->DestProcessId) != CurrentProcessId) { 
            DestProcess = Processes::Descriptors::GetEPROCESS(
                reinterpret_cast<HANDLE>(Input->DestProcessId)
            );
            if (!DestProcess) {
                if (SrcProcess) ObDereferenceObject(SrcProcess);
                return STATUS_NOT_FOUND;
            }
        }

        PVOID Mapping = NULL;
        NTSTATUS Status = Mdl::MapMdl(
            reinterpret_cast<PMDL>(Input->Mdl),
            &Mapping,
            SrcProcess,
            DestProcess,
            Input->NeedProbeAndLock,
            static_cast<KPROCESSOR_MODE>(Input->MapToAddressSpace),
            Input->Protect,
            static_cast<MEMORY_CACHING_TYPE>(Input->CacheType),
            reinterpret_cast<PVOID>(Input->UserRequestedAddress)
        );

        Output->BaseAddress = reinterpret_cast<WdkTypes::PVOID>(Mapping);

        if (SrcProcess) ObDereferenceObject(SrcProcess);
        if (DestProcess) ObDereferenceObject(DestProcess);

        if (NT_SUCCESS(Status)) {
            *ResponseLength = RequestInfo->OutputBufferSize;
        }

        return Status;
    }

    NTSTATUS FASTCALL KbProtectMappedMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_PROTECT_MAPPED_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_PROTECT_MAPPED_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Mdl) return STATUS_INVALID_PARAMETER;

        return MmProtectMdlSystemAddress(
            reinterpret_cast<PMDL>(Input->Mdl),
            Input->Protect
        );
    }

    NTSTATUS FASTCALL KbUnmapMdl(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNMAP_MDL_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_UNMAP_MDL_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Mdl || !Input->BaseAddress) return STATUS_INVALID_PARAMETER;

        Mdl::UnmapMdl(reinterpret_cast<PMDL>(Input->Mdl), reinterpret_cast<PVOID>(Input->BaseAddress), Input->NeedUnlock);
        
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbUnlockPages(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNLOCK_PAGES_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_UNLOCK_PAGES_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Mdl) return STATUS_INVALID_PARAMETER;

        MmUnlockPages(reinterpret_cast<PMDL>(Input->Mdl));

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbFreeMdl(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FREE_MDL_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FREE_MDL_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Mdl) return STATUS_INVALID_PARAMETER;

        IoFreeMdl(reinterpret_cast<PMDL>(Input->Mdl));

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbMapMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_MAP_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_MAP_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_MAP_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_MAP_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        PEPROCESS SrcProcess = NULL, DestProcess = NULL;
        HANDLE CurrentProcessId = PsGetCurrentProcessId();
        
        if (Input->SrcProcessId && reinterpret_cast<HANDLE>(Input->SrcProcessId) != CurrentProcessId) { 
            SrcProcess = Processes::Descriptors::GetEPROCESS(
                reinterpret_cast<HANDLE>(Input->SrcProcessId)
            );
            if (!SrcProcess) return STATUS_NOT_FOUND;
        }

        if (Input->DestProcessId && reinterpret_cast<HANDLE>(Input->DestProcessId) != CurrentProcessId) { 
            DestProcess = Processes::Descriptors::GetEPROCESS(
                reinterpret_cast<HANDLE>(Input->DestProcessId)
            );
            if (!DestProcess) {
                if (SrcProcess) ObDereferenceObject(SrcProcess);
                return STATUS_NOT_FOUND;
            }
        }

        Mdl::MAPPING_INFO MappingInfo = {};
        NTSTATUS Status = Mdl::MapMemory(
            &MappingInfo,
            SrcProcess,
            DestProcess,
            reinterpret_cast<PVOID>(Input->VirtualAddress),
            Input->Size,
            static_cast<KPROCESSOR_MODE>(Input->MapToAddressSpace),
            Input->Protect,
            static_cast<MEMORY_CACHING_TYPE>(Input->CacheType),
            reinterpret_cast<PVOID>(Input->UserRequestedAddress)
        );

        if (SrcProcess) ObDereferenceObject(SrcProcess);
        if (DestProcess) ObDereferenceObject(DestProcess);

        if (NT_SUCCESS(Status)) {
            Output->Mdl = reinterpret_cast<WdkTypes::PMDL>(MappingInfo.Mdl);
            Output->BaseAddress = reinterpret_cast<WdkTypes::PVOID>(MappingInfo.BaseAddress);
            *ResponseLength = RequestInfo->OutputBufferSize;
        }

        return Status;
    }

    NTSTATUS FASTCALL KbUnmapMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNMAP_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_UNMAP_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Mdl || !Input->BaseAddress) return STATUS_INVALID_PARAMETER;

        Mdl::MAPPING_INFO MappingInfo = {};
        MappingInfo.Mdl = reinterpret_cast<PMDL>(Input->Mdl);
        MappingInfo.BaseAddress = reinterpret_cast<PVOID>(Input->BaseAddress);
        Mdl::UnmapMemory(&MappingInfo);
        
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbAllocPhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_ALLOC_PHYSICAL_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_ALLOC_PHYSICAL_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_ALLOC_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_ALLOC_PHYSICAL_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Input->Size || !Output) return STATUS_INVALID_PARAMETER;

        Output->Address = reinterpret_cast<WdkTypes::PVOID>(PhysicalMemory::AllocPhysicalMemorySpecifyCache(
            reinterpret_cast<PVOID64>(Input->LowestAcceptableAddress),
            reinterpret_cast<PVOID64>(Input->LowestAcceptableAddress),
            reinterpret_cast<PVOID64>(Input->LowestAcceptableAddress),
            Input->Size,
            static_cast<MEMORY_CACHING_TYPE>(Input->CachingType)
        ));

        *ResponseLength = sizeof(*Output);
        return Output->Address ? STATUS_SUCCESS : STATUS_MEMORY_NOT_ALLOCATED;
    }

    NTSTATUS FASTCALL KbFreePhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FREE_PHYSICAL_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FREE_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Address) return STATUS_INVALID_PARAMETER;

        PhysicalMemory::FreePhysicalMemory(reinterpret_cast<PVOID>(Input->Address));
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbMapPhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_MAP_PHYSICAL_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_MAP_PHYSICAL_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_MAP_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_MAP_PHYSICAL_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Input->Size || !Output) return STATUS_INVALID_PARAMETER;

        Output->VirtualAddress = reinterpret_cast<WdkTypes::PVOID>(
            PhysicalMemory::MapPhysicalMemory(
                reinterpret_cast<PVOID64>(Input->PhysicalAddress),
                Input->Size,
                static_cast<MEMORY_CACHING_TYPE>(Input->CachingType)
            )
        );

        *ResponseLength = RequestInfo->OutputBufferSize;

        return Output->VirtualAddress
            ? STATUS_SUCCESS
            : STATUS_GENERIC_NOT_MAPPED;
    }

    NTSTATUS FASTCALL KbUnmapPhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNMAP_PHYSICAL_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_MAP_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->PhysicalAddress || !Input->Size) return STATUS_INVALID_PARAMETER;

        PhysicalMemory::UnmapPhysicalMemory(
            reinterpret_cast<PVOID64>(Input->PhysicalAddress),
            Input->Size
        );

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbGetPhysicalAddress(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_PHYSICAL_ADDRESS_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_PHYSICAL_ADDRESS_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_PHYSICAL_ADDRESS_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_PHYSICAL_ADDRESS_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        Output->PhysicalAddress = reinterpret_cast<WdkTypes::PVOID>(
            PhysicalMemory::GetPhysicalAddress(
                reinterpret_cast<PVOID>(Input->VirtualAddress),
                reinterpret_cast<PEPROCESS>(Input->Process)
            )
        );

        *ResponseLength = RequestInfo->OutputBufferSize;

        return Output->PhysicalAddress
            ? STATUS_SUCCESS
            : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbGetVirtualForPhysical(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_VIRTUAL_FOR_PHYSICAL_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_VIRTUAL_FOR_PHYSICAL_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_VIRTUAL_FOR_PHYSICAL_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_VIRTUAL_FOR_PHYSICAL_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        Output->VirtualAddress = reinterpret_cast<WdkTypes::PVOID>(
            PhysicalMemory::GetVirtualForPhysical(reinterpret_cast<PVOID64>(Input->PhysicalAddress))
        );

        *ResponseLength = sizeof(*Output);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbReadPhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        auto Input = static_cast<PKB_READ_WRITE_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        
        if (RequestInfo->InputBufferSize != sizeof(KB_READ_WRITE_PHYSICAL_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!Input || !Input->Buffer || !Input->Size) return STATUS_INVALID_PARAMETER;

        return PhysicalMemory::ReadPhysicalMemory(
            reinterpret_cast<PVOID64>(Input->PhysicalAddress),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size,
            static_cast<MEMORY_CACHING_TYPE>(Input->CachingType)
        ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbWritePhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize < sizeof(KB_READ_WRITE_PHYSICAL_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_READ_WRITE_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Buffer || !Input->Size) return STATUS_INVALID_PARAMETER;

        return PhysicalMemory::WritePhysicalMemory(
            reinterpret_cast<PVOID64>(Input->PhysicalAddress),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size,
            static_cast<MEMORY_CACHING_TYPE>(Input->CachingType)
        ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbReadDmiMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (RequestInfo->OutputBufferSize != sizeof(KB_READ_DMI_MEMORY_OUT))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Output = static_cast<PKB_READ_DMI_MEMORY_OUT>(RequestInfo->OutputBuffer);
        if (!Output) return STATUS_INVALID_PARAMETER;

        BOOLEAN Status = PhysicalMemory::ReadDmiMemory(
            reinterpret_cast<PVOID>(Output->DmiBuffer),
            DmiSize
        );

        if (!Status) return STATUS_UNSUCCESSFUL;

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbGetEprocess(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_EPROCESS_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_EPROCESS_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer)
            return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_GET_EPROCESS_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_EPROCESS_OUT>(RequestInfo->OutputBuffer);

        Output->Process = reinterpret_cast<WdkTypes::PEPROCESS>(
            Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(Input->ProcessId))    
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
        return Output->Process ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    NTSTATUS FASTCALL KbGetEthread(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_ETHREAD_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_ETHREAD_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer)
            return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_GET_ETHREAD_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_ETHREAD_OUT>(RequestInfo->OutputBuffer);

        Output->Thread = reinterpret_cast<WdkTypes::PEPROCESS>(
            Processes::Descriptors::GetETHREAD(reinterpret_cast<HANDLE>(Input->ThreadId))    
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
        return Output->Thread ? STATUS_SUCCESS : STATUS_NOT_FOUND;        
    }

    NTSTATUS FASTCALL KbOpenProcess(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_OPEN_PROCESS_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_OPEN_PROCESS_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer)
            return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_OPEN_PROCESS_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_OPEN_PROCESS_OUT>(RequestInfo->OutputBuffer);

        HANDLE hProcess = NULL;
        NTSTATUS Status = Processes::Descriptors::OpenProcess(
            reinterpret_cast<HANDLE>(Input->ProcessId),
            &hProcess,
            Input->Access,
            Input->Attributes
        );

        if (!NT_SUCCESS(Status)) return Status;

        Output->hProcess = reinterpret_cast<WdkTypes::HANDLE>(hProcess);
        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbOpenProcessByPointer(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_OPEN_PROCESS_BY_POINTER_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_OPEN_PROCESS_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer)
            return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_OPEN_PROCESS_BY_POINTER_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_OPEN_PROCESS_OUT>(RequestInfo->OutputBuffer);

        HANDLE hProcess = NULL;
        NTSTATUS Status = Processes::Descriptors::OpenProcessByPointer(
            reinterpret_cast<PEPROCESS>(Input->Process),
            &hProcess,
            Input->Access,
            Input->Attributes,
            static_cast<KPROCESSOR_MODE>(Input->ProcessorMode)
        );

        if (!NT_SUCCESS(Status)) return Status;

        Output->hProcess = reinterpret_cast<WdkTypes::HANDLE>(hProcess);
        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbOpenThread(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_OPEN_THREAD_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_OPEN_THREAD_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer)
            return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_OPEN_THREAD_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_OPEN_THREAD_OUT>(RequestInfo->OutputBuffer);

        HANDLE hThread = NULL;
        NTSTATUS Status = Processes::Descriptors::OpenThread(
            reinterpret_cast<HANDLE>(Input->ThreadId),
            &hThread,
            Input->Access,
            Input->Attributes
        );

        if (!NT_SUCCESS(Status)) return Status;

        Output->hThread = reinterpret_cast<WdkTypes::HANDLE>(hThread);
        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbOpenThreadByPointer(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_OPEN_THREAD_BY_POINTER_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_OPEN_THREAD_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer || !RequestInfo->OutputBuffer)
            return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_OPEN_THREAD_BY_POINTER_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_OPEN_THREAD_OUT>(RequestInfo->OutputBuffer);

        HANDLE hThread = NULL;
        NTSTATUS Status = Processes::Descriptors::OpenThreadByPointer(
            reinterpret_cast<PETHREAD>(Input->Thread),
            &hThread,
            Input->Access,
            Input->Attributes,
            static_cast<KPROCESSOR_MODE>(Input->ProcessorMode)
        );

        if (!NT_SUCCESS(Status)) return Status;

        Output->hThread = reinterpret_cast<WdkTypes::HANDLE>(hThread);
        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbDereferenceObject(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_DEREFERENCE_OBJECT_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_DEREFERENCE_OBJECT_IN>(RequestInfo->InputBuffer);

        ObDereferenceObject(reinterpret_cast<PVOID>(Input->Object));
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbCloseHandle(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_CLOSE_HANDLE_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_CLOSE_HANDLE_IN>(RequestInfo->InputBuffer);

        return ZwClose(reinterpret_cast<HANDLE>(Input->Handle));        
    }

    NTSTATUS FASTCALL KbQueryInformationProcess(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_QUERY_INFORMATION_PROCESS_THREAD_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_QUERY_INFORMATION_PROCESS_THREAD_IN>(RequestInfo->InputBuffer);

        return Processes::Information::QueryInformationProcess(
            reinterpret_cast<HANDLE>(Input->Handle),
            static_cast<PROCESSINFOCLASS>(Input->InfoClass),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size,
            reinterpret_cast<PULONG>(Input->ReturnLength)
        );
    }

    NTSTATUS FASTCALL KbSetInformationProcess(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_SET_INFORMATION_PROCESS_THREAD_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_SET_INFORMATION_PROCESS_THREAD_IN>(RequestInfo->InputBuffer);

        return Processes::Information::SetInformationProcess(
            reinterpret_cast<HANDLE>(Input->Handle),
            static_cast<PROCESSINFOCLASS>(Input->InfoClass),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size
        );
    }

    NTSTATUS FASTCALL KbQueryInformationThread(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_QUERY_INFORMATION_PROCESS_THREAD_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_QUERY_INFORMATION_PROCESS_THREAD_IN>(RequestInfo->InputBuffer);

        return Processes::Threads::QueryInformationThread(
            reinterpret_cast<HANDLE>(Input->Handle),
            static_cast<THREADINFOCLASS>(Input->InfoClass),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size,
            reinterpret_cast<PULONG>(Input->ReturnLength)
        );
    }

    NTSTATUS FASTCALL KbSetInformationThread(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_SET_INFORMATION_PROCESS_THREAD_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        if (!RequestInfo->InputBuffer) return STATUS_INVALID_PARAMETER;

        auto Input = static_cast<PKB_SET_INFORMATION_PROCESS_THREAD_IN>(RequestInfo->InputBuffer);

        return Processes::Threads::SetInformationThread(
            reinterpret_cast<HANDLE>(Input->Handle),
            static_cast<THREADINFOCLASS>(Input->InfoClass),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size
        );
    }

    NTSTATUS FASTCALL KbAllocUserMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_ALLOC_USER_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_ALLOC_USER_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_ALLOC_USER_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_ALLOC_USER_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        HANDLE hProcess = ZwCurrentProcess();
        NTSTATUS Status = Input->ProcessId ? Processes::Descriptors::OpenProcess(
            reinterpret_cast<HANDLE>(Input->ProcessId),
            &hProcess
        ) : STATUS_SUCCESS;

        if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

        PVOID BaseAddress = NULL;
        Status = Processes::MemoryManagement::AllocateVirtualMemory(
            hProcess,
            Input->Size,
            Input->Protect,
            &BaseAddress
        );

        if (hProcess && hProcess != ZwCurrentProcess()) ZwClose(hProcess);

        if (NT_SUCCESS(Status)) {
            Output->BaseAddress = reinterpret_cast<WdkTypes::PVOID>(BaseAddress);
            *ResponseLength = RequestInfo->OutputBufferSize;
        }

        return Status;
    }

    NTSTATUS FASTCALL KbFreeUserMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FREE_USER_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FREE_USER_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        HANDLE hProcess = ZwCurrentProcess();
        NTSTATUS Status = Input->ProcessId ? Processes::Descriptors::OpenProcess(
            reinterpret_cast<HANDLE>(Input->ProcessId),
            &hProcess
        ) : STATUS_SUCCESS;

        if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

        Status = Processes::MemoryManagement::FreeVirtualMemory(
            hProcess,
            reinterpret_cast<PVOID>(Input->BaseAddress)
        );

        if (hProcess && hProcess != ZwCurrentProcess()) ZwClose(hProcess);

        return Status;
    }

    NTSTATUS FASTCALL KbSecureVirtualMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_SECURE_VIRTUAL_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_SECURE_VIRTUAL_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_SECURE_VIRTUAL_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_SECURE_VIRTUAL_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        if (!Input->ProcessId || !Input->BaseAddress || !Input->Size)
            return STATUS_INVALID_PARAMETER;

        if (AddressRange::IsKernelAddress(reinterpret_cast<PVOID>(Input->BaseAddress)))
            return STATUS_INVALID_ADDRESS;

        HANDLE SecureHandle = NULL;
        BOOLEAN Status = FALSE;
        if (reinterpret_cast<HANDLE>(Input->ProcessId) == PsGetCurrentProcessId()) {
            Status = VirtualMemory::SecureMemory(
                reinterpret_cast<PVOID>(Input->BaseAddress),
                Input->Size,
                Input->ProtectRights,
                &SecureHandle
            );
        } else {
            PEPROCESS Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(Input->ProcessId));
            if (!Process) return STATUS_NOT_FOUND;
            Status = VirtualMemory::SecureProcessMemory(
                Process,
                reinterpret_cast<PVOID>(Input->BaseAddress),
                Input->Size,
                Input->ProtectRights,
                &SecureHandle
            );
            ObDereferenceObject(Process);
        }

        if (!Status || !SecureHandle) return STATUS_UNSUCCESSFUL;

        *ResponseLength = RequestInfo->OutputBufferSize;
        Output->SecureHandle = reinterpret_cast<WdkTypes::HANDLE>(SecureHandle);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbUnsecureVirtualMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNSECURE_VIRTUAL_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_UNSECURE_VIRTUAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->ProcessId || !Input->SecureHandle) return STATUS_INVALID_PARAMETER;

        if (reinterpret_cast<HANDLE>(Input->ProcessId) == PsGetCurrentProcessId()) {
            VirtualMemory::UnsecureMemory(reinterpret_cast<HANDLE>(Input->SecureHandle));
        } else {
            PEPROCESS Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(Input->ProcessId));
            if (!Process) return STATUS_NOT_FOUND;
            VirtualMemory::UnsecureProcessMemory(
                Process,
                reinterpret_cast<HANDLE>(Input->SecureHandle)
            );
            ObDereferenceObject(Process);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbReadProcessMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_READ_PROCESS_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_READ_PROCESS_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        HANDLE ProcessId = Input->ProcessId ? reinterpret_cast<HANDLE>(Input->ProcessId) : PsGetCurrentProcessId();
        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(ProcessId);
        if (!Process) return STATUS_UNSUCCESSFUL;

        NTSTATUS Status = Processes::MemoryManagement::ReadProcessMemory(
            Process,
            reinterpret_cast<PVOID>(Input->BaseAddress),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size
        );

        ObDereferenceObject(Process);

        return Status;
    }

    NTSTATUS FASTCALL KbWriteProcessMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_WRITE_PROCESS_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_WRITE_PROCESS_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        HANDLE ProcessId = Input->ProcessId ? reinterpret_cast<HANDLE>(Input->ProcessId) : PsGetCurrentProcessId();
        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(ProcessId);
        if (!Process) return STATUS_UNSUCCESSFUL;

        PVOID Address = reinterpret_cast<PVOID>(Input->BaseAddress);
        SIZE_T Size = Input->Size;
        if (Input->PerformCopyOnWrite) {
            using namespace Pte;
            PVOID PageCounter = Address;
            do {   
                ULONG PageSize = 0;
                BOOLEAN Status = TriggerCopyOnWrite(Process, PageCounter, &PageSize);
                if (!Status || !PageSize) {
                    ObDereferenceObject(Process);
                    return STATUS_PARTIAL_COPY;
                }
                PageCounter = reinterpret_cast<PVOID>(
                    reinterpret_cast<SIZE_T>(ALIGN_DOWN_POINTER_BY(PageCounter, PageSize)) + PageSize
                );
            } while (PageCounter < reinterpret_cast<PVOID>(reinterpret_cast<SIZE_T>(Address) + Size));
        }

        NTSTATUS Status = Processes::MemoryManagement::WriteProcessMemory(
            Process,
            Address,
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size
        );

        ObDereferenceObject(Process);

        return Status; 
    }

    NTSTATUS FASTCALL KbTriggerCopyOnWrite(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_TRIGGER_COPY_ON_WRITE_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_TRIGGER_COPY_ON_WRITE_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        HANDLE ProcessId = Input->ProcessId ? reinterpret_cast<HANDLE>(Input->ProcessId) : PsGetCurrentProcessId();
        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(ProcessId);
        if (!Process) return STATUS_UNSUCCESSFUL;

        BOOLEAN Status = Pte::TriggerCopyOnWrite(Process, reinterpret_cast<PVOID>(Input->PageVirtualAddress));

        ObDereferenceObject(Process);

        return Status ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbSuspendProcess(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {    
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_SUSPEND_RESUME_PROCESS_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_SUSPEND_RESUME_PROCESS_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(
            reinterpret_cast<HANDLE>(Input->ProcessId)
        );

        if (!Process) return STATUS_UNSUCCESSFUL;
        NTSTATUS Status = Processes::Threads::SuspendProcess(Process);
        ObDereferenceObject(Process);

        return Status;
    }

    NTSTATUS FASTCALL KbResumeProcess(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {    
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_SUSPEND_RESUME_PROCESS_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_SUSPEND_RESUME_PROCESS_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(
            reinterpret_cast<HANDLE>(Input->ProcessId)
        );

        if (!Process) return STATUS_UNSUCCESSFUL;
        NTSTATUS Status = Processes::Threads::ResumeProcess(Process);
        ObDereferenceObject(Process);

        return Status;
    }

    NTSTATUS FASTCALL KbGetThreadContext(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_GET_SET_THREAD_CONTEXT_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_SET_THREAD_CONTEXT_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Context) return STATUS_INVALID_PARAMETER;

        if (Input->ContextSize != sizeof(CONTEXT)) return STATUS_INFO_LENGTH_MISMATCH;

        PETHREAD Thread = Processes::Descriptors::GetETHREAD(reinterpret_cast<HANDLE>(Input->ThreadId));
        if (!Thread) return STATUS_NOT_FOUND;

        PCONTEXT UserContext = reinterpret_cast<PCONTEXT>(Input->Context);
        HANDLE SecureHandle = NULL;
        if (!VirtualMemory::SecureMemory(UserContext, sizeof(CONTEXT), PAGE_READWRITE, &SecureHandle)) {
            ObDereferenceObject(Thread);
            return STATUS_NOT_LOCKED;
        }

        NTSTATUS Status = STATUS_SUCCESS;
        switch (Input->ProcessorMode) {
        case KernelMode: {
            PCONTEXT Context = static_cast<PCONTEXT>(VirtualMemory::AllocFromPool(sizeof(CONTEXT)));
            if (Context) {
                Context->ContextFlags = UserContext->ContextFlags;
                Status = Processes::Threads::GetContextThread(Thread, Context, KernelMode);
                if (NT_SUCCESS(Status)) {
                    __try {
                        RtlCopyMemory(UserContext, Context, sizeof(CONTEXT));
                        Status = STATUS_SUCCESS;
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        Status = STATUS_UNSUCCESSFUL;
                    }
                }
                VirtualMemory::FreePoolMemory(Context);
            } else {
                Status = STATUS_MEMORY_NOT_ALLOCATED;
            }
            break;
        }
        case UserMode: {
            Status = Processes::Threads::GetContextThread(Thread, UserContext, UserMode);
            break;
        }
        }

        VirtualMemory::UnsecureMemory(SecureHandle);
        ObDereferenceObject(Thread);

        return Status;
    }

    NTSTATUS FASTCALL KbSetThreadContext(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_GET_SET_THREAD_CONTEXT_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_SET_THREAD_CONTEXT_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Context) return STATUS_INVALID_PARAMETER;

        if (Input->ContextSize != sizeof(CONTEXT)) return STATUS_INFO_LENGTH_MISMATCH;

        PETHREAD Thread = Processes::Descriptors::GetETHREAD(reinterpret_cast<HANDLE>(Input->ThreadId));
        if (!Thread) return STATUS_NOT_FOUND;

        PCONTEXT UserContext = reinterpret_cast<PCONTEXT>(Input->Context);
        HANDLE SecureHandle = NULL;
        if (!VirtualMemory::SecureMemory(UserContext, sizeof(CONTEXT), PAGE_READWRITE, &SecureHandle)) {
            ObDereferenceObject(Thread);
            return STATUS_NOT_LOCKED;
        }

        NTSTATUS Status = STATUS_SUCCESS;
        switch (Input->ProcessorMode) {
        case KernelMode: {
            PCONTEXT Context = static_cast<PCONTEXT>(VirtualMemory::AllocFromPool(sizeof(CONTEXT)));
            if (Context) {
                __try {
                    RtlCopyMemory(Context, UserContext, sizeof(CONTEXT));
                    Status = Processes::Threads::SetContextThread(Thread, Context, KernelMode);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    Status = STATUS_UNSUCCESSFUL;
                }
                VirtualMemory::FreePoolMemory(Context);
            } else {
                Status = STATUS_MEMORY_NOT_ALLOCATED;
            }
            break;
        }
        case UserMode: {
            Status = Processes::Threads::SetContextThread(Thread, UserContext, UserMode);
            break;
        }
        }

        VirtualMemory::UnsecureMemory(SecureHandle);
        ObDereferenceObject(Thread);

        return Status;
    }

    NTSTATUS FASTCALL KbCreateUserThread(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_CREATE_USER_THREAD_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_CREATE_USER_SYSTEM_THREAD_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_CREATE_USER_THREAD_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_CREATE_USER_SYSTEM_THREAD_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        HANDLE hProcess;
        NTSTATUS Status = Processes::Descriptors::OpenProcess(
            reinterpret_cast<HANDLE>(Input->ProcessId),
            &hProcess
        );

        if (!NT_SUCCESS(Status)) return STATUS_NOT_FOUND;

        HANDLE hThread = NULL;
        CLIENT_ID ClientId = {};
        Status = Processes::Threads::CreateUserThread(
            hProcess,
            reinterpret_cast<Processes::Threads::_UserThreadRoutine>(Input->ThreadRoutine),
            reinterpret_cast<PVOID>(Input->Argument),
            Input->CreateSuspended,
            &hThread,
            &ClientId
        );

        if (NT_SUCCESS(Status)) {
            Output->hThread = reinterpret_cast<WdkTypes::HANDLE>(hThread);
            Output->ClientId.ProcessId = reinterpret_cast<UINT64>(ClientId.UniqueProcess);
            Output->ClientId.ThreadId  = reinterpret_cast<UINT64>(ClientId.UniqueThread);
            *ResponseLength = RequestInfo->OutputBufferSize;
        }

        ZwClose(hProcess);

        return Status;
    }

    NTSTATUS FASTCALL KbCreateSystemThread(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_CREATE_SYSTEM_THREAD_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_CREATE_USER_SYSTEM_THREAD_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_CREATE_SYSTEM_THREAD_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_CREATE_USER_SYSTEM_THREAD_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        NTSTATUS Status = STATUS_SUCCESS;
        HANDLE hProcess = NULL;
        if (Input->AssociatedProcessId && Input->AssociatedProcessId != 4) {
            // Open process if process was specified and PID != System PID:
            Status = Processes::Descriptors::OpenProcess(
                reinterpret_cast<HANDLE>(Input->AssociatedProcessId),
                &hProcess
            );
            if (!NT_SUCCESS(Status)) return STATUS_NOT_FOUND;
        }

        using ThreadParams = struct {
            PVOID ThreadRoutine;
            PVOID Argument;
            KEVENT Event;
        };
        ThreadParams Params = {};
        Params.ThreadRoutine = reinterpret_cast<PVOID>(Input->ThreadRoutine);
        Params.Argument = reinterpret_cast<PVOID>(Input->Argument);
        KeInitializeEvent(&Params.Event, NotificationEvent, FALSE);

        HANDLE hThread = NULL;
        CLIENT_ID ClientId = {};
        Status = Processes::Threads::CreateSystemThread(
            hProcess,
            [](PVOID Argument) -> VOID {
                auto Params = static_cast<ThreadParams*>(Argument);
                
                auto ThreadRoutine = static_cast<PKSTART_ROUTINE>(Params->ThreadRoutine);
                PVOID ThreadArgument = Params->Argument;
                KeSetEvent(&Params->Event, LOW_REALTIME_PRIORITY, FALSE);

                NTSTATUS Status = STATUS_SUCCESS;
                __try {
                    ThreadRoutine(ThreadArgument);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    Status = STATUS_UNSUCCESSFUL;
                }

                PsTerminateSystemThread(Status);
            },
            reinterpret_cast<PVOID>(&Params),
            &hThread,
            &ClientId
        );

        KeWaitForSingleObject(&Params.Event, UserRequest, KernelMode, FALSE, NULL);

        if (NT_SUCCESS(Status)) {
            Output->hThread = reinterpret_cast<WdkTypes::HANDLE>(hThread);
            Output->ClientId.ProcessId = reinterpret_cast<UINT64>(ClientId.UniqueProcess);
            Output->ClientId.ThreadId  = reinterpret_cast<UINT64>(ClientId.UniqueThread);
            *ResponseLength = RequestInfo->OutputBufferSize;
        }

        if (hProcess) ZwClose(hProcess);

        return Status;
    }

    NTSTATUS FASTCALL KbQueueUserApc(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_QUEUE_USER_APC_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_QUEUE_USER_APC_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        PETHREAD Thread = Processes::Descriptors::GetETHREAD(reinterpret_cast<HANDLE>(Input->ThreadId));
        if (!Thread) return STATUS_NOT_FOUND;

        NTSTATUS Status = Processes::Apc::QueueUserApc(
            Thread,
            reinterpret_cast<Processes::Apc::PKNORMAL_ROUTINE>(Input->ApcProc),
            reinterpret_cast<PVOID>(Input->Argument)
        );

        ObDereferenceObject(Thread);

        return Status;
    }

    NTSTATUS FASTCALL KbRaiseIopl(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::IOPL::RaiseIopl();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbResetIopl(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        IO::IOPL::ResetIopl();
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbGetProcessCr3Cr4(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_PROCESS_CR3_CR4_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_PROCESS_CR3_CR4_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_PROCESS_CR3_CR4_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_PROCESS_CR3_CR4_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output || !Input->ProcessId) return STATUS_INVALID_PARAMETER;

        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(Input->ProcessId));
        if (!Process) return STATUS_NOT_FOUND;

        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        SIZE_T Cr3 = __readcr3();
        SIZE_T Cr4 = __readcr4();
        KeUnstackDetachProcess(&ApcState);

        ObDereferenceObject(Process);

        Output->Cr3 = Cr3;
        Output->Cr4 = Cr4;

        *ResponseLength = RequestInfo->OutputBufferSize;
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbCreateSection(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_CREATE_SECTION_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_CREATE_OPEN_SECTION_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_CREATE_SECTION_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_CREATE_OPEN_SECTION_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        HANDLE hSection = NULL;
        NTSTATUS Status = Sections::CreateSection(
            &hSection,
            reinterpret_cast<LPCWSTR>(Input->Name),
            Input->MaximumSize,
            Input->DesiredAccess,
            Input->SecObjFlags,
            Input->SecPageProtection,
            Input->AllocationAttributes,
            reinterpret_cast<HANDLE>(Input->hFile)
        );

        Output->hSection = reinterpret_cast<WdkTypes::HANDLE>(hSection);
        *ResponseLength = sizeof(*Output);
        return Status;
    }

    NTSTATUS FASTCALL KbOpenSection(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_OPEN_SECTION_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_CREATE_OPEN_SECTION_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_OPEN_SECTION_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_CREATE_OPEN_SECTION_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output || !Input->Name) return STATUS_INVALID_PARAMETER;

        HANDLE hSection = NULL;
        NTSTATUS Status = Sections::OpenSection(
            &hSection,
            reinterpret_cast<LPCWSTR>(Input->Name),
            Input->DesiredAccess,
            Input->SecObjFlags
        );

        Output->hSection = reinterpret_cast<WdkTypes::HANDLE>(hSection);
        *ResponseLength = sizeof(*Output);
        return Status;
    }

    NTSTATUS FASTCALL KbMapViewOfSection(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_MAP_VIEW_OF_SECTION_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_MAP_VIEW_OF_SECTION_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_MAP_VIEW_OF_SECTION_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_MAP_VIEW_OF_SECTION_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output || !Input->hSection) return STATUS_INVALID_PARAMETER;

        PVOID BaseAddress = reinterpret_cast<PVOID>(Input->BaseAddress);
        UINT64 SectionOffset = static_cast<UINT64>(Input->SectionOffset);
        SIZE_T ViewSize = static_cast<SIZE_T>(Input->ViewSize);
        NTSTATUS Status = Sections::MapViewOfSection(
            reinterpret_cast<HANDLE>(Input->hSection),
            reinterpret_cast<HANDLE>(Input->hProcess),
            &BaseAddress,
            static_cast<SIZE_T>(Input->CommitSize),
            &SectionOffset,
            &ViewSize,
            static_cast<SECTION_INHERIT>(Input->SectionInherit),
            Input->AllocationType,
            Input->Win32Protect
        );

        Output->BaseAddress = reinterpret_cast<WdkTypes::PVOID>(BaseAddress);
        Output->SectionOffset = SectionOffset;
        Output->ViewSize = ViewSize;
        *ResponseLength = sizeof(*Output);
        return Status;
    }

    NTSTATUS FASTCALL KbUnmapViewOfSection(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNMAP_VIEW_OF_SECTION_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_UNMAP_VIEW_OF_SECTION_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        return Sections::UnmapViewOfSection(
            reinterpret_cast<HANDLE>(Input->hProcess),
            reinterpret_cast<PVOID>(Input->BaseAddress)
        );
    }

    NTSTATUS FASTCALL KbVmmEnable(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        return Hypervisor::Virtualize() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbVmmDisable(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(RequestInfo);
        UNREFERENCED_PARAMETER(ResponseLength);
        return Hypervisor::Devirtualize() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbVmmInterceptPage(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_VMM_INTERCEPT_PAGE_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_VMM_INTERCEPT_PAGE_IN>(RequestInfo->InputBuffer);
        bool Status = Hypervisor::InterceptPage(
            Input->PhysicalAddress,
            Input->OnReadPhysicalAddress,
            Input->OnWritePhysicalAddress,
            Input->OnExecutePhysicalAddress,
            Input->OnExecuteReadPhysicalAddress,
            Input->OnExecuteWritePhysicalAddress
        );

        return Status ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    }

    NTSTATUS FASTCALL KbVmmDeinterceptPage(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_VMM_DEINTERCEPT_PAGE_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_VMM_DEINTERCEPT_PAGE_IN>(RequestInfo->InputBuffer);
        bool Status = Hypervisor::DeinterceptPage(Input->PhysicalAddress);

        return Status ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    }

    NTSTATUS FASTCALL KbExecuteShellCode(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_EXECUTE_SHELL_CODE_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_EXECUTE_SHELL_CODE_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_EXECUTE_SHELL_CODE_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_EXECUTE_SHELL_CODE_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        Output->Result = KernelShells::ExecuteShellCode(
            reinterpret_cast<KernelShells::_ShellCode>(Input->Address),
            reinterpret_cast<PVOID>(Input->Argument)
        );

        *ResponseLength = sizeof(KB_EXECUTE_SHELL_CODE_OUT);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbGetKernelProcAddress(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_KERNEL_PROC_ADDRESS_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_KERNEL_PROC_ADDRESS_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_KERNEL_PROC_ADDRESS_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_KERNEL_PROC_ADDRESS_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output || !Input->RoutineName || !Input->SizeOfBufferInBytes)
            return STATUS_INVALID_PARAMETER;

        HANDLE hSecure = NULL;
        BOOLEAN SecureStatus = VirtualMemory::SecureMemory(
            reinterpret_cast<PVOID>(Input->RoutineName),
            Input->SizeOfBufferInBytes,
            PAGE_READONLY,
            &hSecure
        );

        if (!SecureStatus) return STATUS_UNSUCCESSFUL;

        LPWSTR RoutineNameKernelBuffer = 
            VirtualMemory::AllocWideString(Input->SizeOfBufferInBytes / sizeof(WCHAR));

        if (!RoutineNameKernelBuffer) {
            VirtualMemory::UnsecureMemory(hSecure);
            return STATUS_MEMORY_NOT_ALLOCATED;
        }

        NTSTATUS Status = STATUS_SUCCESS;
        PVOID KernelAddress = NULL;
        __try {
            RtlCopyMemory(RoutineNameKernelBuffer, reinterpret_cast<PVOID>(Input->RoutineName), Input->SizeOfBufferInBytes);
            KernelAddress = Importer::GetKernelProcAddress(RoutineNameKernelBuffer);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = STATUS_UNSUCCESSFUL;
        }

        VirtualMemory::FreePoolMemory(RoutineNameKernelBuffer);
        VirtualMemory::UnsecureMemory(hSecure);

        if (NT_SUCCESS(Status)) {
            Output->Address = reinterpret_cast<WdkTypes::PVOID>(KernelAddress);
            *ResponseLength = RequestInfo->OutputBufferSize;
        }

        return Status;
    }

    NTSTATUS FASTCALL KbStallExecutionProcessor(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_STALL_EXECUTION_PROCESSOR_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_STALL_EXECUTION_PROCESSOR_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        KeStallExecutionProcessor(Input->Microseconds);

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbBugCheck(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_BUG_CHECK_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_BUG_CHECK_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        KeBugCheck(Input->Status);
    }

    NTSTATUS FASTCALL KbCreateDriver(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_CREATE_DRIVER_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_CREATE_DRIVER_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        using _DriverEntry = NTSTATUS(NTAPI*)(
            _In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath
        );

        HANDLE hSecure = NULL;
        BOOLEAN SecureStatus = VirtualMemory::SecureMemory(
            reinterpret_cast<PVOID>(Input->DriverName),
            Input->DriverNameSizeInBytes,
            PAGE_READONLY,
            &hSecure
        );

        if (!SecureStatus) return STATUS_UNSUCCESSFUL;

        LPWSTR DriverNameKernelBuffer = 
            VirtualMemory::AllocWideString(Input->DriverNameSizeInBytes / sizeof(WCHAR));

        if (!DriverNameKernelBuffer) {
            VirtualMemory::UnsecureMemory(hSecure);
            return STATUS_MEMORY_NOT_ALLOCATED;
        }

        NTSTATUS Status = STATUS_SUCCESS;
        __try {
            RtlCopyMemory(DriverNameKernelBuffer, reinterpret_cast<PVOID>(Input->DriverName), Input->DriverNameSizeInBytes);
            
            using _IoCreateDriver = NTSTATUS(NTAPI*)(PUNICODE_STRING DriverName, _DriverEntry EntryPoint);
            
            using SystemThreadParams = struct {
                LPCWSTR Name;
                _DriverEntry DriverEntry;
                _IoCreateDriver IoCreateDriver;
                NTSTATUS Status;
                KEVENT Event;
            };

            SystemThreadParams Args;
            Args.Name = DriverNameKernelBuffer;
            Args.DriverEntry = reinterpret_cast<_DriverEntry>(Input->DriverEntry);
            Args.IoCreateDriver = static_cast<_IoCreateDriver>(Importer::GetKernelProcAddress(L"IoCreateDriver"));
            if (!Args.IoCreateDriver) {
                VirtualMemory::FreePoolMemory(DriverNameKernelBuffer);
                VirtualMemory::UnsecureMemory(hSecure);
                return STATUS_NOT_IMPLEMENTED;
            }

            KeInitializeEvent(&Args.Event, NotificationEvent, FALSE);

            HANDLE hThread = NULL;
            Processes::Threads::CreateSystemThread([](PVOID Argument) -> VOID {
                    auto Args = reinterpret_cast<SystemThreadParams*>(Argument);
                    UNICODE_STRING DriverName;
                    RtlInitUnicodeString(&DriverName, Args->Name);
                    __try {
                        Args->Status = Args->IoCreateDriver(&DriverName, Args->DriverEntry);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        Args->Status = STATUS_UNSUCCESSFUL;
                    }
                    KeSetEvent(&Args->Event, LOW_REALTIME_PRIORITY, FALSE);
                    PsTerminateSystemThread(Args->Status);
                }, 
                &Args,
                &hThread
            );

            // Waiting for system thread completes:
            KeWaitForSingleObject(&Args.Event, UserRequest, KernelMode, FALSE, NULL);
            ZwClose(hThread);

            Status = Args.Status;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = STATUS_UNSUCCESSFUL;
        }

        VirtualMemory::FreePoolMemory(DriverNameKernelBuffer);
        VirtualMemory::UnsecureMemory(hSecure);        

        return Status;
    }

    NTSTATUS FASTCALL KbLoadModule(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_LOAD_MODULE_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_LOAD_MODULE_IN>(RequestInfo->InputBuffer);
        
        if (!Input || !Input->hModule || !Input->ModuleName)
            return STATUS_INVALID_PARAMETER;

        LPCWSTR UserModuleName = reinterpret_cast<LPCWSTR>(Input->ModuleName);

        SIZE_T NameLength = WideString::Length(UserModuleName);
        if (!NameLength) return STATUS_INVALID_PARAMETER;

        HANDLE hSecure = NULL;
        BOOLEAN SecureStatus = VirtualMemory::SecureMemory(const_cast<LPWSTR>(UserModuleName), (NameLength + 1) * sizeof(WCHAR), PAGE_READONLY, &hSecure);
        if (!SecureStatus)
            return STATUS_UNSUCCESSFUL;

        NTSTATUS Status = LoadableModules::LoadModule(
            reinterpret_cast<PVOID>(Input->hModule),
            UserModuleName,
            reinterpret_cast<LoadableModules::_OnLoad>(Input->OnLoad),
            reinterpret_cast<LoadableModules::_OnUnload>(Input->OnUnload),
            reinterpret_cast<LoadableModules::_OnDeviceControl>(Input->OnDeviceControl)
        );

        VirtualMemory::UnsecureMemory(hSecure);

        return Status;
    }

    NTSTATUS FASTCALL KbGetModuleHandle(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_GET_MODULE_HANDLE_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_GET_MODULE_HANDLE_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_GET_MODULE_HANDLE_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_GET_MODULE_HANDLE_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output || !Input->ModuleName)
            return STATUS_INVALID_PARAMETER;

        LPCWSTR UserModuleName = reinterpret_cast<LPCWSTR>(Input->ModuleName);

        SIZE_T NameLength = WideString::Length(UserModuleName);
        if (!NameLength) return STATUS_INVALID_PARAMETER;

        HANDLE hSecure = NULL;
        BOOLEAN SecureStatus = VirtualMemory::SecureMemory(const_cast<LPWSTR>(UserModuleName), (NameLength + 1) * sizeof(WCHAR), PAGE_READONLY, &hSecure);
        if (!SecureStatus)
            return STATUS_UNSUCCESSFUL;

        Output->hModule = reinterpret_cast<WdkTypes::PVOID>(LoadableModules::GetModuleHandle(UserModuleName));

        VirtualMemory::UnsecureMemory(hSecure);

        *ResponseLength = sizeof(*Output);
        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbCallModule(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_CALL_MODULE_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_CALL_MODULE_IN>(RequestInfo->InputBuffer);
        
        if (!Input || !Input->hModule)
            return STATUS_INVALID_PARAMETER;

        return LoadableModules::CallModule(
            reinterpret_cast<PVOID>(Input->hModule),
            Input->CtlCode,
            reinterpret_cast<PVOID>(Input->Argument)
        );
    }

    NTSTATUS FASTCALL KbUnloadModule(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_UNLOAD_MODULE_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_UNLOAD_MODULE_IN>(RequestInfo->InputBuffer);
        
        if (!Input || !Input->hModule)
            return STATUS_INVALID_PARAMETER;

        return LoadableModules::UnloadModule(reinterpret_cast<PVOID>(Input->hModule));
    }

    NTSTATUS FASTCALL KbFindSignature(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_FIND_SIGNATURE_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_FIND_SIGNATURE_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FIND_SIGNATURE_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_FIND_SIGNATURE_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output || !Input->Memory || !Input->Signature || !Input->Mask)
            return STATUS_INVALID_PARAMETER;

        SIZE_T SigLength = strlen(reinterpret_cast<char*>(Input->Mask));
        LPSTR MaskBuffer = VirtualMemory::AllocAnsiString(SigLength);
        LPSTR SigBuffer = VirtualMemory::AllocAnsiString(SigLength);
        if (!MaskBuffer || !SigBuffer) {
            if (MaskBuffer) VirtualMemory::FreePoolMemory(MaskBuffer);
            if (SigBuffer) VirtualMemory::FreePoolMemory(SigBuffer);
            return STATUS_MEMORY_NOT_ALLOCATED;
        }

        __try {
            RtlCopyMemory(MaskBuffer, reinterpret_cast<char*>(Input->Mask), SigLength);
            RtlCopyMemory(SigBuffer, reinterpret_cast<char*>(Input->Signature), SigLength);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (MaskBuffer) VirtualMemory::FreePoolMemory(MaskBuffer);
            if (SigBuffer) VirtualMemory::FreePoolMemory(SigBuffer);
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS Status = STATUS_SUCCESS;
        PVOID FoundAddress = NULL;
        PVOID Memory = reinterpret_cast<PVOID>(Input->Memory);
        SIZE_T Size = Input->Size;
        switch (AddressRange::IsUserAddress(Memory)) {
        case TRUE: {
            PEPROCESS CurrentProcess = PsGetCurrentProcess();
            PEPROCESS Process = NULL;
            if (Input->ProcessId != 0 && Input->ProcessId != reinterpret_cast<UINT64>(PsGetCurrentProcessId())) {
                Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(Input->ProcessId));
                if (!Process) {
                    Status = STATUS_NOT_FOUND;
                    break;
                }
            }

            HANDLE hSecure = NULL;
            if (!VirtualMemory::SecureProcessMemory(Process ? Process : CurrentProcess, Memory, Size, PAGE_READONLY, &hSecure)) {
                if (Process) ObDereferenceObject(Process);
                Status = STATUS_NOT_LOCKED;
                break;
            }

            KAPC_STATE ApcState;
            __try {
                if (Process) KeStackAttachProcess(Process, &ApcState);
                FoundAddress = find_signature(Memory, Size, SigBuffer, MaskBuffer);
                Status = STATUS_SUCCESS;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = STATUS_UNSUCCESSFUL;
            }

            if (Process) KeUnstackDetachProcess(&ApcState);

            VirtualMemory::UnsecureProcessMemory(Process ? Process : CurrentProcess, hSecure);
            if (Process) ObDereferenceObject(Process);
            break;
        }
        case FALSE: {
            __try {
                FoundAddress = find_signature(Memory, Size, SigBuffer, MaskBuffer);
                Status = STATUS_SUCCESS;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        }

        if (MaskBuffer) VirtualMemory::FreePoolMemory(MaskBuffer);
        if (SigBuffer) VirtualMemory::FreePoolMemory(SigBuffer);

        Output->Address = reinterpret_cast<WdkTypes::PVOID>(FoundAddress);
        *ResponseLength = sizeof(KB_FIND_SIGNATURE_OUT);
        return Status;
    }
}

NTSTATUS FASTCALL DispatchIOCTL(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
{
    using _CtlHandler = NTSTATUS(FASTCALL*)(IN PIOCTL_INFO, OUT PSIZE_T);
    static const _CtlHandler Handlers[] = {
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

    USHORT Index = EXTRACT_CTL_CODE(RequestInfo->ControlCode) - CTL_BASE;
    return Index < sizeof(Handlers) / sizeof(Handlers[0])
        ? Handlers[Index](RequestInfo, ResponseLength)
        : STATUS_NOT_IMPLEMENTED;
}