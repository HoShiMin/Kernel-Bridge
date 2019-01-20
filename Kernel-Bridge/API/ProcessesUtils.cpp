#include <fltKernel.h>
#include "Importer.h"
#include "MemoryUtils.h"
#include "PTE.h"
#include "PteUtils.h"
#include "ProcessesUtils.h"

namespace Processes {
    namespace Descriptors {
        _IRQL_requires_max_(APC_LEVEL)
        PEPROCESS GetEPROCESS(HANDLE ProcessId) {
            PEPROCESS Process;
            return NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)) 
                ? Process 
                : NULL;
        }

        _IRQL_requires_max_(APC_LEVEL)
        PETHREAD GetETHREAD(HANDLE ThreadId) {
            PETHREAD Thread;
            return NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &Thread)) 
                ? Thread 
                : NULL;            
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS OpenProcess(
            HANDLE ProcessId, 
            OUT PHANDLE hProcess, 
            ACCESS_MASK AccessMask, 
            ULONG Attributes
        ) {
            CLIENT_ID ClientId;
            ClientId.UniqueProcess = ProcessId;
            ClientId.UniqueThread  = 0;

            OBJECT_ATTRIBUTES ObjectAttributes;
            InitializeObjectAttributes(&ObjectAttributes, NULL, Attributes, NULL, NULL);

            return ZwOpenProcess(hProcess, AccessMask, &ObjectAttributes, &ClientId);
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS OpenProcessByPointer(
            PEPROCESS Process, 
            OUT PHANDLE hProcess, 
            ACCESS_MASK AccessMask, 
            ULONG Attributes,
            KPROCESSOR_MODE ProcessorMode
        ) {
            return ObOpenObjectByPointer(
                Process,
                Attributes,
                NULL,
                AccessMask,
                *PsProcessType,
                ProcessorMode,
                hProcess
            );
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS OpenThread(
            HANDLE ThreadId, 
            OUT PHANDLE hThread, 
            ACCESS_MASK AccessMask, 
            ULONG Attributes
        ) {
            CLIENT_ID ClientId;
            ClientId.UniqueProcess = 0;
            ClientId.UniqueThread  = ThreadId;

            OBJECT_ATTRIBUTES ObjectAttributes;
            InitializeObjectAttributes(&ObjectAttributes, NULL, Attributes, NULL, NULL);

            using _ZwOpenThread = NTSTATUS(NTAPI*)(
                OUT PHANDLE hThread,
                IN ACCESS_MASK AccessMask,
                IN POBJECT_ATTRIBUTES ObjectAttributes,
                IN PCLIENT_ID ClientId
            );

            auto ZwOpenThread = static_cast<_ZwOpenThread>(Importer::GetKernelProcAddress(L"ZwOpenThread"));
            if (!ZwOpenThread) return STATUS_NOT_IMPLEMENTED;

            return ZwOpenThread(hThread, AccessMask, &ObjectAttributes, &ClientId);
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS OpenThreadByPointer(
            PETHREAD Thread, 
            OUT PHANDLE hThread, 
            ACCESS_MASK AccessMask, 
            ULONG Attributes,
            KPROCESSOR_MODE ProcessorMode
        ) {
            return ObOpenObjectByPointer(
                Thread,
                Attributes,
                NULL,
                AccessMask,
                *PsThreadType,
                ProcessorMode,
                hThread
            );
        }
    }

    namespace AddressSpace {
        _IRQL_requires_max_(APC_LEVEL)
        BOOLEAN AttachToProcessByPid(HANDLE ProcessId, OUT PKAPC_STATE ApcState) {
            if (!ApcState) return FALSE;
            PEPROCESS Process = Descriptors::GetEPROCESS(ProcessId);
            if (!Process) return FALSE;
            BOOLEAN Status = AttachToProcess(Process, ApcState);
            ObDereferenceObject(Process);
            return Status;
        }

        _IRQL_requires_max_(APC_LEVEL)
        BOOLEAN AttachToProcess(PEPROCESS Process, OUT PKAPC_STATE ApcState) {
            if (!Process || !ApcState) return FALSE;
            KeStackAttachProcess(Process, ApcState);
            return TRUE;
        }

        _IRQL_requires_max_(APC_LEVEL)
        VOID DetachFromProcess(IN PKAPC_STATE ApcState) {
            KeUnstackDetachProcess(ApcState);
        }
    }

    namespace Terminator {
        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS TerminateProcessByPid(HANDLE ProcessId, NTSTATUS ExitStatus) {
            HANDLE hProcess = NULL;
            NTSTATUS Status = Descriptors::OpenProcess(ProcessId, &hProcess);
            if (NT_SUCCESS(Status)) {
                Status = TerminateProcess(hProcess, ExitStatus);
                ZwClose(hProcess);
            }
            return Status;
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS TerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus) {
            return ZwTerminateProcess(hProcess, ExitStatus);
        }
    }

    namespace Threads {
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS GetContextThread(IN PETHREAD Thread, OUT PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode) {
            using _PsGetContextThread = NTSTATUS (NTAPI*)(
                IN PETHREAD Thread,
                OUT PCONTEXT Context,
                IN KPROCESSOR_MODE PreviousMode
            );
            static auto _GetContextThread = 
                static_cast<_PsGetContextThread>(Importer::GetKernelProcAddress(L"PsGetContextThread"));
            return _GetContextThread
                ? _GetContextThread(Thread, Context, PreviousMode)
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS SetContextThread(IN PETHREAD Thread, IN PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode) {
            using _PsSetContextThread = NTSTATUS (NTAPI*)(
                IN PETHREAD Thread,
                IN PCONTEXT Context,
                IN KPROCESSOR_MODE PreviousMode
            );
            static auto _SetContextThread = 
                static_cast<_PsSetContextThread>(Importer::GetKernelProcAddress(L"PsSetContextThread"));
            return _SetContextThread
                ? _SetContextThread(Thread, Context, PreviousMode)
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS SuspendProcess(IN PEPROCESS Process) {
            using _PsSuspendProcess = NTSTATUS (NTAPI*)(
                IN PEPROCESS Process  
            );
            static auto _SuspendProcess =
                static_cast<_PsSuspendProcess>(Importer::GetKernelProcAddress(L"PsSuspendProcess"));
            return _SuspendProcess
                ? _SuspendProcess(Process)
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS ResumeProcess(IN PEPROCESS Process) {
            using _PsResumeProcess = NTSTATUS (NTAPI*)(
                IN PEPROCESS Process  
            );
            static auto _SuspendProcess =
                static_cast<_PsResumeProcess>(Importer::GetKernelProcAddress(L"PsResumeProcess"));
            return _SuspendProcess
                ? _SuspendProcess(Process)
                : STATUS_NOT_IMPLEMENTED;            
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS CreateUserThread(
            HANDLE hProcess,
            IN _UserThreadRoutine StartAddress,
            IN PVOID Argument,
            BOOLEAN CreateSuspended,
            OUT PHANDLE hThread,
            OUT PCLIENT_ID ClientId
        ) {
            using _RtlCreateUserThread = NTSTATUS (NTAPI*)(
                IN HANDLE               ProcessHandle,
                IN PSECURITY_DESCRIPTOR SecurityDescriptor,
                IN BOOLEAN              CreateSuspended,
                IN ULONG                StackZeroBits,
                IN OUT PULONG           StackReserved,
                IN OUT PULONG           StackCommit,
                IN PVOID                StartAddress,
                IN PVOID                StartParameter,
                OUT PHANDLE             ThreadHandle,
                OUT PCLIENT_ID          ClientID
            );
            static auto _CreateUserThread =
                static_cast<_RtlCreateUserThread>(Importer::GetKernelProcAddress(L"RtlCreateUserThread"));
            return _CreateUserThread
                ? _CreateUserThread(
                    hProcess,
                    NULL,
                    CreateSuspended,
                    0,
                    NULL,
                    NULL,
                    StartAddress,
                    Argument,
                    hThread,
                    ClientId
                  )
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS CreateSystemThread(
            OPTIONAL HANDLE hProcess, 
            PKSTART_ROUTINE StartAddress, 
            PVOID Argument, 
            OUT PHANDLE hThread, 
            OUT PCLIENT_ID ClientId
        ) {
            OBJECT_ATTRIBUTES ObjectAttributes;
            InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            return PsCreateSystemThread(hThread, GENERIC_ALL, &ObjectAttributes, hProcess, ClientId, StartAddress, Argument);
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS CreateSystemThread(
            PKSTART_ROUTINE StartAddress, 
            PVOID Argument, 
            OUT PHANDLE hThread
        ) {
            OBJECT_ATTRIBUTES ObjectAttributes;
            InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            return PsCreateSystemThread(hThread, GENERIC_ALL, &ObjectAttributes, NULL, NULL, StartAddress, Argument);
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS QueryInformationThread(
            HANDLE hThread,
            THREADINFOCLASS ThreadInformationClass,
            OUT PVOID ThreadInformation,
            ULONG ThreadInformationLength,
            OUT PULONG ReturnLength
        ) {
            using _ZwQueryInformationThread = NTSTATUS (NTAPI*)(
                HANDLE hThread,
                THREADINFOCLASS ThreadInformationClass,
                OUT PVOID ThreadInformation,
                ULONG ThreadInformationLength,
                OUT PULONG ReturnLength              
            );
            static auto _QueryInformationThread =
                static_cast<_ZwQueryInformationThread>(Importer::GetKernelProcAddress(L"ZwQueryInformationThread"));
            return _QueryInformationThread
                ? _QueryInformationThread(
                    hThread, 
                    ThreadInformationClass, 
                    ThreadInformation, 
                    ThreadInformationLength, 
                    ReturnLength
                )
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS SetInformationThread(
            HANDLE hThread,
            THREADINFOCLASS ThreadInformationClass,
            IN PVOID ThreadInformation,
            ULONG ThreadInformationLength
        ) {
            return ZwSetInformationThread(
                hThread, 
                ThreadInformationClass, 
                ThreadInformation, 
                ThreadInformationLength
            );
        }
    }

    namespace Information {
        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS QueryInformationProcess(
            HANDLE hProcess,
            PROCESSINFOCLASS ProcessInformationClass,
            OUT PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            OUT PULONG ReturnLength
        ) {
            using _ZwQueryInformationProcess = NTSTATUS (NTAPI*)(
                HANDLE hProcess,
                PROCESSINFOCLASS ProcessInformationClass,
                IN PVOID ProcessInformation,
                ULONG ProcessInformationLength,
                OUT PULONG ReturnLength              
            );
            static auto _QueryInformationProcess =
                static_cast<_ZwQueryInformationProcess>(Importer::GetKernelProcAddress(L"ZwQueryInformationProcess"));
            return _QueryInformationProcess
                ? _QueryInformationProcess(
                    hProcess, 
                    ProcessInformationClass, 
                    ProcessInformation, 
                    ProcessInformationLength, 
                    ReturnLength
                  )
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS SetInformationProcess(
            HANDLE hProcess,
            PROCESSINFOCLASS ProcessInformationClass,
            IN PVOID ProcessInformation,
            ULONG ProcessInformationLength
        ) {
            using _ZwSetInformationProcess = NTSTATUS (NTAPI*)(
                HANDLE hProcess,
                PROCESSINFOCLASS ProcessInformationClass,
                IN PVOID ProcessInformation,
                ULONG ProcessInformationLength         
            );
            static auto _SetInformationProcess =
                static_cast<_ZwSetInformationProcess>(Importer::GetKernelProcAddress(L"ZwSetInformationProcess"));
            return _SetInformationProcess
                ? _SetInformationProcess(
                    hProcess, 
                    ProcessInformationClass, 
                    ProcessInformation, 
                    ProcessInformationLength
                  )
                : STATUS_NOT_IMPLEMENTED;
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        BOOLEAN Is32BitProcess(HANDLE hProcess) {
#ifdef _AMD64_
            UINT64 IsWow64Process = 0;
            ULONG ReturnLength = 0;
            NTSTATUS Status = QueryInformationProcess(hProcess, ProcessWow64Information, &IsWow64Process, sizeof(IsWow64Process), &ReturnLength);
            if (!NT_SUCCESS(Status) || !ReturnLength) return FALSE;
            return IsWow64Process != 0;
#else
            UNREFERENCED_PARAMETER(hProcess);
            return TRUE;
#endif
        }
    }

    namespace MemoryManagement {
        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS AllocateVirtualMemory(HANDLE hProcess, SIZE_T Size, ULONG Protect, IN OUT PVOID* BaseAddress) {
            return ZwAllocateVirtualMemory(hProcess, BaseAddress, 0, &Size, MEM_COMMIT, Protect);
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        PVOID AllocateVirtualMemory(HANDLE hProcess, SIZE_T Size, ULONG Protect) {
            PVOID BaseAddress = NULL;
            return NT_SUCCESS(ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0, &Size, MEM_COMMIT, Protect)) 
                ? BaseAddress 
                : NULL;
        }

        _IRQL_requires_max_(PASSIVE_LEVEL)
        NTSTATUS FreeVirtualMemory(HANDLE hProcess, PVOID BaseAddress) {
            SIZE_T RegionSize = 0;
            return ZwFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, MEM_RELEASE);
        }

        enum MEMORY_OPERATION_TYPE {
            MemRead,
            MemWrite
        };

        _IRQL_requires_max_(APC_LEVEL)
        static NTSTATUS OperateProcessMemory(
            PEPROCESS Process,
            PVOID BaseAddress,
            PVOID Buffer,
            ULONG Size,
            MEMORY_OPERATION_TYPE Operation
        ) {
            if (!Process) return STATUS_INVALID_PARAMETER_1;
            if (!BaseAddress) return STATUS_INVALID_PARAMETER_2;
            if (!Buffer) return STATUS_INVALID_PARAMETER_3;
            if (!Size) return STATUS_INVALID_PARAMETER_4;

            if (AddressRange::IsKernelAddress(BaseAddress)) {
                if (!VirtualMemory::IsMemoryRangePresent(BaseAddress, Size))
                    return STATUS_MEMORY_NOT_ALLOCATED;
            }

            if (AddressRange::IsKernelAddress(Buffer)) {
                if (!VirtualMemory::IsMemoryRangePresent(Buffer, Size))
                    return STATUS_MEMORY_NOT_ALLOCATED;
            }

            // Attempt to lock process memory from freeing:
            HANDLE hProcessSecure = NULL;
            if (AddressRange::IsUserAddress(BaseAddress)) {
                if (!VirtualMemory::SecureProcessMemory(Process, BaseAddress, Size, PAGE_READONLY, &hProcessSecure))
                    return STATUS_NOT_LOCKED;
            }

            // Attempt to lock buffer memory if it is usermode memory:
            HANDLE hBufferSecure = NULL;
            if (AddressRange::IsUserAddress(Buffer)) {
                if (!VirtualMemory::SecureMemory(Buffer, Size, PAGE_READWRITE, &hBufferSecure)) {
                    if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
                    return STATUS_NOT_LOCKED;
                }
            }

            // Attempt to map process memory:
            Mdl::MAPPING_INFO ProcessMapping = {};
            NTSTATUS Status = Mdl::MapMemory(
                &ProcessMapping,
                Process,
                NULL,
                BaseAddress,
                Size
            );

            if (!NT_SUCCESS(Status)) { 
                if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
                if (hBufferSecure) VirtualMemory::UnsecureMemory(hBufferSecure);
                return STATUS_NOT_MAPPED_VIEW;
            }

            // Attempt to map buffer memory:
            Mdl::MAPPING_INFO BufferMapping = {};
            Status = Mdl::MapMemory(
                &BufferMapping,
                NULL,
                NULL,
                Buffer,
                Size
            );

            if (!NT_SUCCESS(Status)) {
                Mdl::UnmapMemory(&ProcessMapping);
                if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
                if (hBufferSecure) VirtualMemory::UnsecureMemory(hBufferSecure);
                return STATUS_NOT_MAPPED_VIEW;
            }

            __try {
                Status = STATUS_UNSUCCESSFUL;
                switch (Operation) {
                case MemRead:
                    VirtualMemory::CopyMemory(BufferMapping.BaseAddress, ProcessMapping.BaseAddress, Size);
                    break;
                case MemWrite:
                    VirtualMemory::CopyMemory(ProcessMapping.BaseAddress, BufferMapping.BaseAddress, Size);
                    break;
                }
                Status = STATUS_SUCCESS;
            } __finally {
                Mdl::UnmapMemory(&BufferMapping);
                Mdl::UnmapMemory(&ProcessMapping);
                if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
                if (hBufferSecure) VirtualMemory::UnsecureMemory(hBufferSecure);
            }

            return Status;
        }

        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS ReadProcessMemory(
            PEPROCESS Process,
            IN PVOID BaseAddress,
            OUT PVOID Buffer,
            ULONG Size
        ) {
            return OperateProcessMemory(Process, BaseAddress, Buffer, Size, MemRead);
        }

        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS WriteProcessMemory(
            PEPROCESS Process,
            OUT PVOID BaseAddress,
            IN PVOID Buffer,
            ULONG Size
        ) {
            return OperateProcessMemory(Process, BaseAddress, Buffer, Size, MemWrite);
        }
    }

    namespace Apc {
        _IRQL_requires_max_(APC_LEVEL)
        NTSTATUS QueueUserApc(PETHREAD Thread, PKNORMAL_ROUTINE NormalRoutine, PVOID Argument) {

            auto KeInitializeApc  = static_cast<_KeInitializeApc>(Importer::GetKernelProcAddress(L"KeInitializeApc"));
            auto KeInsertQueueApc = static_cast<_KeInsertQueueApc>(Importer::GetKernelProcAddress(L"KeInsertQueueApc"));

            if (!KeInitializeApc || !KeInsertQueueApc) return STATUS_NOT_IMPLEMENTED;

            // Initializing user APC:
            auto UserApc = static_cast<PKAPC>(VirtualMemory::AllocFromPool(sizeof(KAPC)));
            KeInitializeApc(
                UserApc, 
                Thread, 
                OriginalApcEnvironment, 
                [](
                    PRKAPC Apc,
                    PKNORMAL_ROUTINE NormalRoutine,
                    PVOID NormalContext,
                    PVOID SystemArgument1,
                    PVOID SystemArgument2                    
                ) -> VOID {
                    UNREFERENCED_PARAMETER(SystemArgument1);
                    UNREFERENCED_PARAMETER(SystemArgument2);

                    if (PsIsThreadTerminating(PsGetCurrentThread())) return;
                    
#ifdef _AMD64_
                    // Fixing APC to Wow64-processes:
                    using _PsGetCurrentProcessWow64Process = PEPROCESS(NTAPI*)();
                    auto GetWow64Process = static_cast<_PsGetCurrentProcessWow64Process>(Importer::GetKernelProcAddress(L"PsGetCurrentProcessWow64Process"));
                    if (!GetWow64Process || GetWow64Process()) {
                        PsWrapApcWow64Thread(static_cast<PVOID*>(NormalContext), reinterpret_cast<PVOID*>(NormalRoutine));
                    }
#else
                    UNREFERENCED_PARAMETER(NormalRoutine);
                    UNREFERENCED_PARAMETER(NormalContext);
#endif

                    VirtualMemory::FreePoolMemory(Apc);
                },
                NULL,
                NormalRoutine,
                UserMode,
                Argument
            );

            // Enforcing delivery of user APCs:
            auto KernelApc = static_cast<PKAPC>(VirtualMemory::AllocFromPool(sizeof(KAPC)));
            KeInitializeApc(
                KernelApc,
                Thread,
                OriginalApcEnvironment,
                [](
                    PRKAPC Apc,
                    PKNORMAL_ROUTINE NormalRoutine,
                    PVOID NormalContext,
                    PVOID SystemArgument1,
                    PVOID SystemArgument2  
                ) -> VOID {
                    UNREFERENCED_PARAMETER(NormalRoutine);
                    UNREFERENCED_PARAMETER(NormalContext);
                    UNREFERENCED_PARAMETER(SystemArgument1);
                    UNREFERENCED_PARAMETER(SystemArgument2);

                    // Enforcing all user APCs delivery:
                    auto KeTestAlertThread = static_cast<_KeTestAlertThread>(Importer::GetKernelProcAddress(L"KeTestAlertThread"));
                    if (KeTestAlertThread) KeTestAlertThread(UserMode);

                    VirtualMemory::FreePoolMemory(Apc);
                },
                NULL,
                NULL,
                KernelMode,
                NULL
            );

            if (KeInsertQueueApc(UserApc, NULL, NULL, KernelMode)) {
                if (!KeInsertQueueApc(KernelApc, NULL, NULL, KernelMode)) {
                    VirtualMemory::FreePoolMemory(KernelApc);
                    return STATUS_UNSUCCESSFUL;
                }
            } else {
                VirtualMemory::FreePoolMemory(UserApc);
                return STATUS_UNSUCCESSFUL;
            }

            return STATUS_SUCCESS;
        }
    }
}

