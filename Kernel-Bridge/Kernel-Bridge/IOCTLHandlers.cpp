#include <fltKernel.h>

#include "CtlTypes.h"
#include "IOCTLHandlers.h"

#include "../API/MemoryUtils.h"
#include "../API/ProcessesUtils.h"
#include "../API/IO.h"
#include "../API/CPU.h"
#include "../API/GetProcAddress.h"

#include "IOCTLs.h"

namespace
{
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
            static_cast<CPU::PCPUID_INFO>(RequestInfo->OutputBuffer)
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
            static_cast<CPU::PCPUID_INFO>(RequestInfo->OutputBuffer)
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

    NTSTATUS FASTCALL KbCopyMoveMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_COPY_MOVE_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_COPY_MOVE_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Src || !Input->Dest) return STATUS_INVALID_PARAMETER;

        if (Input->Intersects)
            RtlMoveMemory(
                reinterpret_cast<PVOID>(Input->Dest),
                reinterpret_cast<PVOID>(Input->Src),
                Input->Size
            );
        else
            RtlCopyMemory(
                reinterpret_cast<PVOID>(Input->Dest),
                reinterpret_cast<PVOID>(Input->Src),
                Input->Size
            );

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbFillMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize != sizeof(KB_FILL_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_FILL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Address) return STATUS_INVALID_PARAMETER;

        RtlFillMemory(reinterpret_cast<PVOID>(Input->Address), Input->Size, Input->Filler);

        return STATUS_SUCCESS;
    }

    NTSTATUS FASTCALL KbEqualMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength) 
    {
        if (
            RequestInfo->InputBufferSize != sizeof(KB_EQUAL_MEMORY_IN) || 
            RequestInfo->OutputBufferSize != sizeof(KB_EQUAL_MEMORY_OUT)
        ) return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_EQUAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Src || !Input->Dest) return STATUS_INVALID_PARAMETER;

        static_cast<PKB_EQUAL_MEMORY_OUT>(RequestInfo->OutputBuffer)->Equals = RtlEqualMemory(
            reinterpret_cast<PVOID>(Input->Src), 
            reinterpret_cast<PVOID>(Input->Dest), 
            Input->Size
        );

        *ResponseLength = RequestInfo->OutputBufferSize;
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
            static_cast<KPROCESSOR_MODE>(Input->AccessMode),
            static_cast<LOCK_OPERATION>(Input->LockOperation),
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
                Input->Size
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
            Input->Process
                ? PhysicalMemory::GetPhysicalAddress(
                      reinterpret_cast<PEPROCESS>(Input->Process),
                      reinterpret_cast<PVOID>(Input->VirtualAddress)
                  )
                : PhysicalMemory::GetPhysicalAddress(
                      reinterpret_cast<PVOID>(Input->VirtualAddress)
                  )
        );

        *ResponseLength = RequestInfo->OutputBufferSize;

        return Output->PhysicalAddress
            ? STATUS_SUCCESS
            : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbReadPhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        auto Input = static_cast<PKB_READ_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        auto Output = static_cast<PKB_READ_PHYSICAL_MEMORY_OUT>(RequestInfo->OutputBuffer);

        if (!Input || !Output) return STATUS_INVALID_PARAMETER;

        if (RequestInfo->InputBufferSize != sizeof(KB_READ_PHYSICAL_MEMORY_IN)) 
            return STATUS_INFO_LENGTH_MISMATCH;

        return PhysicalMemory::ReadPhysicalMemory(
            reinterpret_cast<PVOID64>(Input->PhysicalAddress),
            reinterpret_cast<PVOID>(&Output->Buffer),
            RequestInfo->OutputBufferSize
        ) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    NTSTATUS FASTCALL KbWritePhysicalMemory(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
    {
        UNREFERENCED_PARAMETER(ResponseLength);

        if (RequestInfo->InputBufferSize < sizeof(KB_WRITE_PHYSICAL_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_WRITE_PHYSICAL_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input || !Input->Buffer || !Input->Size) return STATUS_INVALID_PARAMETER;

        return PhysicalMemory::WritePhysicalMemory(
            reinterpret_cast<PVOID64>(Input->PhysicalAddress),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size
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
            &hProcess
        );

        if (!NT_SUCCESS(Status)) return Status;

        Output->hProcess = reinterpret_cast<WdkTypes::HANDLE>(hProcess);
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

        if (RequestInfo->InputBufferSize != sizeof(KB_READ_WRITE_PROCESS_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_READ_WRITE_PROCESS_MEMORY_IN>(RequestInfo->InputBuffer);
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

        if (RequestInfo->InputBufferSize != sizeof(KB_READ_WRITE_PROCESS_MEMORY_IN))
            return STATUS_INFO_LENGTH_MISMATCH;

        auto Input = static_cast<PKB_READ_WRITE_PROCESS_MEMORY_IN>(RequestInfo->InputBuffer);
        if (!Input) return STATUS_INVALID_PARAMETER;

        HANDLE ProcessId = Input->ProcessId ? reinterpret_cast<HANDLE>(Input->ProcessId) : PsGetCurrentProcessId();
        PEPROCESS Process = Processes::Descriptors::GetEPROCESS(ProcessId);
        if (!Process) return STATUS_UNSUCCESSFUL;

        NTSTATUS Status = Processes::MemoryManagement::WriteProcessMemory(
            Process,
            reinterpret_cast<PVOID>(Input->BaseAddress),
            reinterpret_cast<PVOID>(Input->Buffer),
            Input->Size
        );

        ObDereferenceObject(Process);

        return Status; 
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

        if (!NT_SUCCESS(Status)) return STATUS_NOT_IMPLEMENTED;

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

        HANDLE hProcess;
        NTSTATUS Status = Processes::Descriptors::OpenProcess(
            reinterpret_cast<HANDLE>(Input->AssociatedProcessId),
            &hProcess
        );

        if (!NT_SUCCESS(Status)) return STATUS_NOT_IMPLEMENTED;

        HANDLE hThread = NULL;
        CLIENT_ID ClientId = {};
        Status = Processes::Threads::CreateSystemThread(
            hProcess,
            reinterpret_cast<PKSTART_ROUTINE>(Input->ThreadRoutine),
            reinterpret_cast<PVOID>(Input->Argument),
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
}

NTSTATUS FASTCALL DispatchIOCTL(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength)
{
    using _CtlHandler = NTSTATUS(FASTCALL*)(IN PIOCTL_INFO, OUT PSIZE_T);
    static const _CtlHandler Handlers[] = {
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
        /* 26 */ KbMapMemory,
        /* 27 */ KbUnmapMemory,

        // Physical memory:
        /* 28 */ KbMapPhysicalMemory,
        /* 29 */ KbUnmapPhysicalMemory,
        /* 30 */ KbGetPhysicalAddress,
        /* 31 */ KbReadPhysicalMemory,
        /* 32 */ KbWritePhysicalMemory,
        /* 33 */ KbReadDmiMemory,

        // Processes & Threads:
        /* 34 */ KbGetEprocess,
        /* 35 */ KbGetEthread,
        /* 36 */ KbOpenProcess,
        /* 37 */ KbDereferenceObject,
        /* 38 */ KbCloseHandle,
        /* 39 */ KbAllocUserMemory,
        /* 40 */ KbFreeUserMemory,
        /* 41 */ KbSecureVirtualMemory,
        /* 42 */ KbUnsecureVirtualMemory,
        /* 43 */ KbReadProcessMemory,
        /* 44 */ KbWriteProcessMemory,
        /* 45 */ KbSuspendProcess,
        /* 46 */ KbResumeProcess,
        /* 47 */ KbCreateUserThread,
        /* 48 */ KbCreateSystemThread,
        /* 49 */ KbRaiseIopl,
        /* 50 */ KbResetIopl,

        // Stuff u kn0w:
        /* 51 */ KbGetKernelProcAddress,
        /* 52 */ KbStallExecutionProcessor,
        /* 53 */ KbBugCheck,
        /* 54 */ KbCreateDriver,
    };

    USHORT Index = EXTRACT_CTL_CODE(RequestInfo->ControlCode) - CTL_BASE;
    return Index < sizeof(Handlers) / sizeof(Handlers[0]) 
        ? Handlers[Index](RequestInfo, ResponseLength) 
        : STATUS_NOT_IMPLEMENTED;
}