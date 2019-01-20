#include <fltKernel.h>

#include "PTE.h"
#include "PteUtils.h"
#include "MemoryUtils.h"

namespace VirtualMemory {
/*
    In Windows 8 NonPagedPool is deprecated, 
    so we should to use NonPagedPoolNx or NonPagedPoolExecute.
    In Windows 7 or lower we use NonPagedPool that has RWX rights.

    -> !!! NOTICE !!! <-
    To use ExDefaultNonPagedPoolType you should:
    1. Add definition POOL_NX_OPTIN=1 to global preprocessor definitions (look at project settings)
    2. Call ExInitializeDriverRuntime(DrvRtPoolNxOptIn) in your DriverEntry before all allocations
*/
    static const ULONG PoolTag = 'KBLI';

    _IRQL_requires_max_(DISPATCH_LEVEL)
    PVOID AllocFromPool(SIZE_T Bytes, BOOLEAN FillByZeroes) {
        if (!Bytes) return NULL;
        VOID* CONST Address = ExAllocatePoolWithTag(
            ExDefaultNonPagedPoolType,
            Bytes, 
            PoolTag
        );
        if (!Address) return NULL;
        *static_cast<PUCHAR>(Address) = 0x00;
        *(static_cast<PUCHAR>(Address) + Bytes - 1) = 0x00;
        if (FillByZeroes) RtlZeroMemory(Address, Bytes);
        return Address;
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    PVOID AllocFromPoolExecutable(SIZE_T Bytes) {
        if (!Bytes) return NULL;
        return ExAllocatePoolWithTag(
            NonPagedPoolExecute,
            Bytes,
            PoolTag
        );
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    LPSTR AllocAnsiString(SIZE_T Characters) {
        return static_cast<LPSTR>(AllocFromPool((Characters + 1) * sizeof(CHAR), TRUE));
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    LPWSTR AllocWideString(SIZE_T Characters) {
        return static_cast<LPWSTR>(AllocFromPool((Characters + 1) * sizeof(WCHAR), TRUE));
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    PVOID AllocArray(SIZE_T ElementSize, SIZE_T ElementsCount) {
        return AllocFromPool(ElementSize * ElementsCount, TRUE);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    VOID FreePoolMemory(__drv_freesMem(Mem) PVOID Address) {
        ExFreePoolWithTag(Address, PoolTag);
    }

    _IRQL_requires_max_(APC_LEVEL)
    PVOID AllocNonCachedNorInitialized(SIZE_T Bytes) {
        return MmAllocateNonCachedMemory(Bytes);
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID FreeNonCachedMemory(PVOID Address, SIZE_T Bytes) {
        MmFreeNonCachedMemory(Address, Bytes);
    }

    BOOLEAN CopyMemory(PVOID Dest, PVOID Src, SIZE_T Size, BOOLEAN Intersects, OPTIONAL BOOLEAN CheckBuffersPresence) {
        if (CheckBuffersPresence) {
            if (AddressRange::IsKernelAddress(Src) && !IsMemoryRangePresent(Src, Size)) return FALSE;
            if (AddressRange::IsKernelAddress(Dest) && !IsMemoryRangePresent(Dest, Size)) return FALSE;
        }

        switch (Size) {
        case sizeof(UCHAR): {
            *reinterpret_cast<PUCHAR>(Dest) = *reinterpret_cast<PUCHAR>(Src);
            break;
        }
        case sizeof(USHORT): {
            *reinterpret_cast<PUSHORT>(Dest) = *reinterpret_cast<PUSHORT>(Src);
            break;              
        }
        case sizeof(ULONG): {
            *reinterpret_cast<PULONG>(Dest) = *reinterpret_cast<PULONG>(Src);
            break;
        }
#ifdef _AMD64_
        case sizeof(ULONGLONG): {
            *reinterpret_cast<PULONGLONG>(Dest) = *reinterpret_cast<PULONGLONG>(Src);
            break;
        }
#endif
        default: {
            if (Intersects) {
                RtlMoveMemory(
                    reinterpret_cast<PVOID>(Dest),
                    reinterpret_cast<PVOID>(Src),
                    Size
                );
            } else {
                RtlCopyMemory(
                    reinterpret_cast<PVOID>(Dest),
                    reinterpret_cast<PVOID>(Src),
                    Size
                );
            }
        }
        }
        return TRUE;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN SecureMemory(
        __in_data_source(USER_MODE) PVOID UserAddress, 
        SIZE_T Size, 
        ULONG ProtectRights, 
        OUT PHANDLE SecureHandle
    ) {
        if (!SecureHandle || !Size || AddressRange::IsKernelAddress(UserAddress)) 
            return FALSE;
        *SecureHandle = MmSecureVirtualMemory(UserAddress, Size, ProtectRights);
        return *SecureHandle != NULL;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN SecureProcessMemory(
        PEPROCESS Process,
        __in_data_source(USER_MODE) PVOID UserAddress, 
        SIZE_T Size, 
        ULONG ProtectRights, 
        OUT PHANDLE SecureHandle
    ) {
        if (!Process || !SecureHandle) return FALSE;
        if (Process == PsGetCurrentProcess())
            return SecureMemory(UserAddress, Size, ProtectRights, SecureHandle);

        HANDLE hSecure = NULL;
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        BOOLEAN Result = SecureMemory(UserAddress, Size, ProtectRights, &hSecure);
        KeUnstackDetachProcess(&ApcState);

        *SecureHandle = hSecure;
        return Result;
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID UnsecureMemory(HANDLE SecureHandle) {
        if (SecureHandle) MmUnsecureVirtualMemory(SecureHandle);
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID UnsecureProcessMemory(PEPROCESS Process, HANDLE SecureHandle) {
        if (!Process) return;
        if (Process == PsGetCurrentProcess())
            return UnsecureMemory(SecureHandle);
        if (SecureHandle) {
            KAPC_STATE ApcState;
            KeStackAttachProcess(Process, &ApcState);
            MmUnsecureVirtualMemory(SecureHandle);
            KeUnstackDetachProcess(&ApcState);
        }
    }

    // Check whether access to address causes page fault:
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsAddressValid(PVOID Address) {
        return MmIsAddressValid(Address);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsPagePresent(PVOID Address) {
        return PhysicalMemory::GetPhysicalAddress(Address) || MmIsAddressValid(Address);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsMemoryRangePresent(PVOID Address, SIZE_T Size) {
        PVOID PageCounter = ALIGN_DOWN_POINTER_BY(Address, PAGE_SIZE);
        do {
            if (!IsPagePresent(PageCounter)) return FALSE;
            PageCounter = reinterpret_cast<PVOID>(reinterpret_cast<SIZE_T>(PageCounter) + PAGE_SIZE);
        } while (reinterpret_cast<SIZE_T>(PageCounter) < reinterpret_cast<SIZE_T>(Address) + Size);
        return TRUE;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN CheckUserMemoryReadable(__in_data_source(USER_MODE) PVOID UserAddress, SIZE_T Size) {
        __try {
            ProbeForRead(UserAddress, Size, 1);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN CheckProcessMemoryReadable(PEPROCESS Process, __in_data_source(USER_MODE) PVOID UserAddress, SIZE_T Size) {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        BOOLEAN Status = CheckUserMemoryReadable(UserAddress, Size);
        KeUnstackDetachProcess(&ApcState);
        return Status;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN CheckUserMemoryWriteable(__in_data_source(USER_MODE) PVOID UserAddress, SIZE_T Size) {
        __try {
            ProbeForWrite(UserAddress, Size, 1);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN CheckProcessMemoryWriteable(PEPROCESS Process, __in_data_source(USER_MODE) PVOID UserAddress, SIZE_T Size) {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        BOOLEAN Status = CheckUserMemoryWriteable(UserAddress, Size);
        KeUnstackDetachProcess(&ApcState);
        return Status;
    }
}

namespace Heap {
    // Creates a growable heap and returns a HeapHandle:
    _IRQL_requires_max_(APC_LEVEL)
    PVOID CreateHeap() {
        return RtlCreateHeap(
            HEAP_GROWABLE,
            NULL,
            PAGE_SIZE * 2,
            PAGE_SIZE,
            NULL,
            NULL
        );
    }

    // Allocates memory from heap and returns allocated buffer address:
    _IRQL_requires_max_(APC_LEVEL)
    PVOID AllocHeap(PVOID HeapHandle, SIZE_T Size, BOOLEAN ZeroMemory) {
        if (!HeapHandle || !Size) return NULL;
        PVOID Buffer = RtlAllocateHeap(HeapHandle, ZeroMemory ? HEAP_ZERO_MEMORY : 0, Size);
        if (Buffer && !ZeroMemory) {
            *static_cast<PUCHAR>(Buffer) = 0x00;
            *(static_cast<PUCHAR>(Buffer) + Size - 1) = 0x00;
        }
        return Buffer;
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID FreeHeap(PVOID HeapHandle, _Frees_ptr_opt_ PVOID Address) {
        if (!HeapHandle || !Address) return;
        RtlFreeHeap(HeapHandle, 0, Address);
    }

    // Free all of heap memory and destroy the heap object:
    _IRQL_requires_max_(APC_LEVEL)
    VOID DestroyHeap(PVOID HeapHandle) {
        if (HeapHandle) RtlDestroyHeap(HeapHandle);
    }


    _IRQL_requires_max_(APC_LEVEL)
    HeapObject::HeapObject() 
    : HeapHandle(CreateHeap()) {}

    _IRQL_requires_max_(APC_LEVEL)
    HeapObject::~HeapObject() {
        DestroyHeap(HeapHandle);
    }
    
    BOOLEAN HeapObject::IsHeapValid() const {
        return HeapHandle != NULL;
    }
    
    _IRQL_requires_max_(APC_LEVEL)
    PVOID HeapObject::Alloc(SIZE_T Size, BOOLEAN ZeroMemory) const {
        return AllocHeap(HeapHandle, Size, ZeroMemory);
    }
    
    _IRQL_requires_max_(APC_LEVEL)
    VOID HeapObject::Free(PVOID Address) const {
        FreeHeap(HeapHandle, Address);
    }
    
    _IRQL_requires_max_(APC_LEVEL)
    LPSTR HeapObject::AllocAnsiString(SIZE_T Characters) const {
        return static_cast<LPSTR>(AllocHeap(HeapHandle, (Characters + 1) * sizeof(CHAR)));
    }
    
    _IRQL_requires_max_(APC_LEVEL)
    LPWSTR HeapObject::AllocWideString(SIZE_T Characters) const {
        return static_cast<LPWSTR>(AllocHeap(HeapHandle, (Characters + 1) * sizeof(WCHAR)));
    }
    
    _IRQL_requires_max_(APC_LEVEL)
    PVOID HeapObject::AllocArray(SIZE_T ElementSize, SIZE_T ElementsCount) const {
        return AllocHeap(HeapHandle, ElementSize * ElementsCount);
    }
}

namespace PhysicalMemory {
    const int DMI_SIZE = 65536;

    // DMI size is 65536 bytes:
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN ReadDmiMemory(OUT PVOID Buffer, SIZE_T Size) {
        PHYSICAL_ADDRESS DmiAddress;
        DmiAddress.QuadPart = 0xF0000;
        PVOID DmiMemory = MmMapIoSpace(DmiAddress, Size, MmNonCached);
        BOOLEAN Status = DmiMemory != NULL;
        if (Status) {
            RtlMoveMemory(Buffer, DmiMemory, Size);
            MmUnmapIoSpace(DmiMemory, Size);
        }
        return Status;
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    PVOID AllocPhysicalMemory(PVOID64 HighestAcceptableAddress, SIZE_T Size) {
        return MmAllocateContiguousMemory(
            Size, 
            *reinterpret_cast<PHYSICAL_ADDRESS*>(&HighestAcceptableAddress)
        );
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    PVOID AllocPhysicalMemorySpecifyCache(
        PVOID64 LowestAcceptableAddress,
        PVOID64 HighestAcceptableAddress,
        PVOID64 BoundaryAddressMultiple,
        SIZE_T Size,
        MEMORY_CACHING_TYPE CachingType
    ) {
        return MmAllocateContiguousMemorySpecifyCache(
            Size, 
            *reinterpret_cast<PHYSICAL_ADDRESS*>(&LowestAcceptableAddress),
            *reinterpret_cast<PHYSICAL_ADDRESS*>(&HighestAcceptableAddress),
            *reinterpret_cast<PHYSICAL_ADDRESS*>(&BoundaryAddressMultiple),
            CachingType
        );
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    VOID FreePhysicalMemory(PVOID BaseVirtualAddress) {
        MmFreeContiguousMemory(BaseVirtualAddress);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    PVOID MapPhysicalMemory(PVOID64 PhysicalAddress, SIZE_T Size, MEMORY_CACHING_TYPE CachingType) {
        return MmMapIoSpace(*reinterpret_cast<PHYSICAL_ADDRESS*>(&PhysicalAddress), Size, CachingType);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    VOID UnmapPhysicalMemory(PVOID64 MappedPhysicalMemory, SIZE_T Size) {
        MmUnmapIoSpace(MappedPhysicalMemory, Size);
    }

    _IRQL_requires_max_(APC_LEVEL)
    PVOID64 GetPhysicalAddress(PVOID VirtualAddress, OPTIONAL PEPROCESS Process) {
        if (!Process || Process == PsGetCurrentProcess()) {
            return MmIsAddressValid(VirtualAddress)
                ? reinterpret_cast<PVOID64>(MmGetPhysicalAddress(VirtualAddress).QuadPart)
                : NULL;
        }

        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        PVOID64 PhysicalAddress = MmIsAddressValid(VirtualAddress)
            ? reinterpret_cast<PVOID64>(MmGetPhysicalAddress(VirtualAddress).QuadPart)
            : NULL;
        KeUnstackDetachProcess(&ApcState);
        return PhysicalAddress;
    }

    PVOID GetVirtualForPhysical(PVOID64 PhysicalAddress) {
        return MmGetVirtualForPhysical(*reinterpret_cast<PPHYSICAL_ADDRESS>(&PhysicalAddress));
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN ReadPhysicalMemory(IN PVOID64 PhysicalAddress, OUT PVOID Buffer, SIZE_T Length, MEMORY_CACHING_TYPE CachingType) {
        BOOLEAN Status;
        PVOID VirtualAddress = GetVirtualForPhysical(PhysicalAddress);
        if (VirtualAddress) {
            __try {
                VirtualMemory::CopyMemory(Buffer, VirtualAddress, Length);
                Status = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = FALSE;
            }
        } else {
            Status = FALSE;
        }

        if (!Status) {
            PVOID MappedMemory = MapPhysicalMemory(PhysicalAddress, Length, CachingType);
            if (!MappedMemory) return FALSE;
            __try {
                VirtualMemory::CopyMemory(Buffer, MappedMemory, Length);
                Status = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = FALSE;
            }
            UnmapPhysicalMemory(MappedMemory, Length);
        }

        return Status;
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN WritePhysicalMemory(OUT PVOID64 PhysicalAddress, IN PVOID Buffer, SIZE_T Length, MEMORY_CACHING_TYPE CachingType) {
        BOOLEAN Status;
        PVOID VirtualAddress = GetVirtualForPhysical(PhysicalAddress);
        if (VirtualAddress) {
            __try {
                VirtualMemory::CopyMemory(VirtualAddress, Buffer, Length);
                Status = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = FALSE;
            }
        } else {
            Status = FALSE;
        }

        if (!Status) {
            PVOID MappedMemory = MapPhysicalMemory(PhysicalAddress, Length, CachingType);
            if (!MappedMemory) return FALSE;
            __try {
                VirtualMemory::CopyMemory(MappedMemory, Buffer, Length);
                Status = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Status = FALSE;
            }
            UnmapPhysicalMemory(MappedMemory, Length);
        }

        return Status;
    }
}

namespace Mdl {
    _IRQL_requires_max_(APC_LEVEL)
    PMDL AllocMdlAndLockPages(
        PVOID Address, 
        ULONG Size, 
        KPROCESSOR_MODE AccessMode, 
        LOCK_OPERATION Operation, 
        OPTIONAL PEPROCESS Process
    ) {
        if (!Address || !Size) return NULL;
        PMDL Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
        if (!Mdl) return NULL;
        __try {
            if (Process && Process != PsGetCurrentProcess())
                MmProbeAndLockProcessPages(Mdl, Process, AccessMode, Operation);
            else
                MmProbeAndLockPages(Mdl, AccessMode, Operation);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(Mdl);
            return NULL;
        }
        return Mdl;
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID UnlockPagesAndFreeMdl(PMDL Mdl) {
        if (!Mdl) return;
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS MapMdl(
        IN PMDL Mdl,
        OUT PVOID* MappedMemory,
        OPTIONAL PEPROCESS SrcProcess,
        OPTIONAL PEPROCESS DestProcess,
        BOOLEAN NeedProbeAndLock,
        KPROCESSOR_MODE MapToAddressSpace, 
        ULONG Protect,
        MEMORY_CACHING_TYPE CacheType,
        OPTIONAL PVOID UserRequestedAddress     
    ) {
        if (!MappedMemory) return STATUS_INVALID_PARAMETER;
        *MappedMemory = NULL;

        if (UserRequestedAddress) {
            if (
                (MapToAddressSpace == KernelMode && AddressRange::IsUserAddress(UserRequestedAddress)) ||
                (MapToAddressSpace == UserMode && AddressRange::IsKernelAddress(UserRequestedAddress))
            ) return STATUS_INVALID_PARAMETER_6; // Access mode is incompatible with UserRequestAddress!
        }

        BOOLEAN IsLocked = FALSE;
        BOOLEAN IsAttached = FALSE;
        KAPC_STATE ApcState;
        __try {
            PEPROCESS CurrentProcess = PsGetCurrentProcess();

            // Lock and prepare pages in target process:
            if (NeedProbeAndLock) {
                if (!SrcProcess || SrcProcess == CurrentProcess)
                    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
                else
                    MmProbeAndLockProcessPages(Mdl, SrcProcess, KernelMode, IoReadAccess);
                IsLocked = TRUE;
            }

            if (DestProcess && DestProcess != CurrentProcess) {
                KeStackAttachProcess(DestProcess, &ApcState);
                IsAttached = TRUE;
            }

            // Map prepared pages to current process:
            PVOID Mapping = MmMapLockedPagesSpecifyCache(
                Mdl,
                MapToAddressSpace,
                CacheType,
                MapToAddressSpace == UserMode ? UserRequestedAddress : NULL,
                FALSE,
                NormalPagePriority
            );

            MmProtectMdlSystemAddress(Mdl, Protect);

            if (IsAttached) KeUnstackDetachProcess(&ApcState);
            *MappedMemory = Mapping;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (IsAttached) KeUnstackDetachProcess(&ApcState);
            if (IsLocked) MmUnlockPages(Mdl);
            return STATUS_UNSUCCESSFUL;                
        }

        return STATUS_SUCCESS;
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID UnmapMdl(IN PMDL Mdl, IN PVOID MappedMemory, BOOLEAN NeedUnlock) {
        MmUnmapLockedPages(MappedMemory, Mdl);
        if (NeedUnlock) MmUnlockPages(Mdl);
    }

    _IRQL_requires_max_(APC_LEVEL)
    NTSTATUS MapMemory(
        OUT PMAPPING_INFO MappingInfo,
        OPTIONAL PEPROCESS SrcProcess,
        OPTIONAL PEPROCESS DestProcess,
        IN PVOID VirtualAddress,
        ULONG Size,
        KPROCESSOR_MODE MapToAddressSpace,
        ULONG Protect,
        MEMORY_CACHING_TYPE CacheType,
        OPTIONAL PVOID UserRequestedAddress 
    ) {
        if (!Size || !MappingInfo) return STATUS_INVALID_PARAMETER;

        *MappingInfo = {};

        MappingInfo->Mdl = IoAllocateMdl(VirtualAddress, Size, FALSE, FALSE, NULL);
        if (!MappingInfo->Mdl) return STATUS_MEMORY_NOT_ALLOCATED;

        NTSTATUS Status = MapMdl(
            MappingInfo->Mdl,
            &MappingInfo->BaseAddress,
            SrcProcess,
            DestProcess,
            TRUE,
            MapToAddressSpace,
            Protect,
            CacheType,
            UserRequestedAddress
        );
        
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_INVALID_PARAMETER_6)
                Status = STATUS_INVALID_PARAMETER_7; // Do it corresponding to current prototype
            IoFreeMdl(MappingInfo->Mdl);
            *MappingInfo = {};
        }

        return Status;
    }

    _IRQL_requires_max_(APC_LEVEL)
    VOID UnmapMemory(IN PMAPPING_INFO MappingInfo) {
        MmUnmapLockedPages(MappingInfo->BaseAddress, MappingInfo->Mdl);
        MmUnlockPages(MappingInfo->Mdl);
        IoFreeMdl(MappingInfo->Mdl);
    }
}