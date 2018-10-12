#include <fltKernel.h>
#include <stdarg.h>

#include "../API/MemoryUtils.h"
#include "../API/ProcessesUtils.h"
#include "../API/Locks.h"
#include "../API/LinkedList.h"
#include "../API/CommPort.h"
#include "../API/ObCallbacks.h"
#include "../API/PsCallbacks.h"
#include "../API/StringsAPI.h"

#include "FilterCallbacks.h"

#include "WdkTypes.h"
#include "FltTypes.h"

namespace Communication {
    static CommPort Server;

    LPCWSTR PortName = L"\\Kernel-Bridge"; 

    NTSTATUS StartServer(PFLT_FILTER FilterHandle) {
        return Server.StartServer(
            FilterHandle, 
            PortName,
            []( // OnMessage received:
                CommPort::CLIENT_INFO& Client,
                CommPort::CLIENT_REQUEST& Request,
                OUT PULONG ReturnLength
            ) -> NTSTATUS {
                UNREFERENCED_PARAMETER(Client);
                UNREFERENCED_PARAMETER(Request);
                UNREFERENCED_PARAMETER(ReturnLength);
                KdPrint(("[Kernel-Bridge]: Message received!\r\n"));
                return STATUS_SUCCESS;
            }
        );
    }

    VOID StopServer() {
        Server.StopServer();
    }

    bool IsClientAppropriate(const CommPort::CLIENT_INFO& Client, KbFltTypes Type, OPTIONAL HANDLE IgnoredThreadId = NULL) {
        if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) return false;
        auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
        if (ClientContext->Type != Type) return false;
        return !IgnoredThreadId || reinterpret_cast<HANDLE>(ClientContext->Client.ThreadId) != IgnoredThreadId;    
    }
}

namespace KbCallbacks {
    static ObCallbacks ObHandlesFilter;
    static PsProcessCallback PsProcessFilter;
    static PsThreadCallback PsThreadFilter;
    static PsImageCallback PsImageFilter;

    NTSTATUS StartObHandlesFilter() {
        return ObHandlesFilter.SetupCallbacks(
            [](PVOID Context, POB_PRE_OPERATION_INFORMATION Info) -> OB_PREOP_CALLBACK_STATUS {
                UNREFERENCED_PARAMETER(Context);
                KB_FLT_OB_CALLBACK_INFO FltInfo = {};
                FltInfo.Client.ProcessId = reinterpret_cast<UINT64>(PsGetCurrentProcessId());
                FltInfo.Client.ThreadId = reinterpret_cast<UINT64>(PsGetCurrentThreadId());

                if (Info->ObjectType == *PsProcessType) {
                    FltInfo.Target.ProcessId = reinterpret_cast<UINT64>(
                        PsGetProcessId(static_cast<PEPROCESS>(Info->Object))
                    );
                } else if (Info->ObjectType == *PsThreadType) {
                    FltInfo.Target.ProcessId = reinterpret_cast<UINT64>(
                        PsGetProcessId(static_cast<PEPROCESS>(IoThreadToProcess(static_cast<PETHREAD>(Info->Object))))    
                    );
                    FltInfo.Target.ThreadId = reinterpret_cast<UINT64>(
                        PsGetThreadId(static_cast<PETHREAD>(Info->Object))    
                    );
                }

                FltInfo.CreateDesiredAccess    = Info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
                FltInfo.DuplicateDesiredAccess = Info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
                FltInfo.CreateResultAccess     = Info->Parameters->CreateHandleInformation.DesiredAccess;
                FltInfo.DuplicateResultAccess  = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

                using namespace Communication;
                auto& Clients = Server.GetClients();
                
                Clients.LockShared();

                // Check whether we are in context of one of filtering threads:
                for (auto& Client : Clients) {
                    if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) continue;
                    auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
                    if (FltInfo.Client.ProcessId == ClientContext->Client.ProcessId) {
                        Clients.Unlock();
                        return OB_PREOP_SUCCESS;
                    }
                }
                
                // Broadcasting:
                for (auto& Client : Clients) {
                    // Check whether the filter type is ObCallbacks:
                    if (!IsClientAppropriate(Client, KbObCallbacks)) continue;
                    
                    KB_FLT_OB_CALLBACK_INFO Request = FltInfo;
                    Server.Send(Client.ClientPort, &Request, sizeof(Request), &Request, sizeof(Request), 350);
                    FltInfo.CreateResultAccess = Request.CreateResultAccess;
                    FltInfo.DuplicateResultAccess = Request.DuplicateResultAccess;
                }

                Clients.Unlock();

                Info->Parameters->CreateHandleInformation.DesiredAccess    = FltInfo.CreateResultAccess;
                Info->Parameters->DuplicateHandleInformation.DesiredAccess = FltInfo.DuplicateResultAccess;

                return OB_PREOP_SUCCESS;
            }
        );
    }

    VOID StopObHandlesFilter() {
        ObHandlesFilter.RemoveCallbacks();
    }

    NTSTATUS StartPsProcessFilter() {
        return PsProcessFilter.SetupCallback(
            [](HANDLE ParentId, HANDLE ProcessId, BOOLEAN Created) -> VOID {
                KB_FLT_PS_PROCESS_INFO Info = {};
                Info.ParentId = reinterpret_cast<WdkTypes::HANDLE>(ParentId);
                Info.ProcessId = reinterpret_cast<WdkTypes::HANDLE>(ProcessId);
                Info.Created = Created;

                using namespace Communication;
                auto& Clients = Server.GetClients();

                HANDLE CurrentThreadId = PsGetCurrentThreadId();

                Clients.LockShared();
                for (auto& Client : Clients) {
                    if (!IsClientAppropriate(Client, KbPsProcess, CurrentThreadId)) continue;

                    // We're not waiting for response:
                    Server.Send(Client.ClientPort, &Info, sizeof(Info));
                }
                Clients.Unlock();
            }
        );
    }

    VOID StopPsProcessFilter() {
        PsProcessFilter.RemoveCallback();
    }

    NTSTATUS StartPsThreadFilter() {
        return PsThreadFilter.SetupCallback(
            [](HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Created) -> VOID {
                KB_FLT_PS_THREAD_INFO Info = {};
                Info.ProcessId = reinterpret_cast<WdkTypes::HANDLE>(ProcessId);
                Info.ThreadId = reinterpret_cast<WdkTypes::HANDLE>(ThreadId);
                Info.Created = Created;

                using namespace Communication;
                auto& Clients = Server.GetClients();

                HANDLE CurrentThreadId = PsGetCurrentThreadId();

                Clients.LockShared();
                for (auto& Client : Clients) {
                    if (!IsClientAppropriate(Client, KbPsThread, CurrentThreadId)) continue;

                    // We're not waiting for response:
                    Server.Send(Client.ClientPort, &Info, sizeof(Info));
                }
                Clients.Unlock();
            }
        );
    }

    VOID StopPsThreadFilter() {
        PsThreadFilter.RemoveCallback();
    }

    NTSTATUS StartPsImageFilter() {
        return PsImageFilter.SetupCallback(
            [](PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) -> VOID {
                KB_FLT_PS_IMAGE_INFO Info = {};
                Info.ProcessId = reinterpret_cast<WdkTypes::HANDLE>(ProcessId);
                Info.BaseAddress = reinterpret_cast<WdkTypes::PVOID>(ImageInfo->ImageBase);
                Info.ImageSize = ImageInfo->ImageSize;
                if (FullImageName && FullImageName->Buffer && FullImageName->Length && FullImageName->MaximumLength) {
                    RtlCopyMemory(
                        Info.FullImageName, 
                        FullImageName->Buffer, 
                        FullImageName->Length >= sizeof(Info.FullImageName) 
                            ? sizeof(Info.FullImageName) - 1
                            : FullImageName->Length
                    );
                }

                using namespace Communication;
                auto& Clients = Server.GetClients();

                Clients.LockShared();
                for (auto& Client : Clients) {
                    if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) continue;
                    auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
                    if (ClientContext->Type != KbPsImage) continue;

                    // We're not waiting for response:
                    Server.Send(Client.ClientPort, &Info, sizeof(Info));
                }
                Clients.Unlock();
            }
        );
    }

    VOID StopPsImageFilter() {
        PsImageFilter.RemoveCallback();
    }
}

static WideString GetWin32Path(const PFILE_OBJECT FileObject) {
    if (!FileObject || !FileObject->FileName.Buffer) return WideString();
    UNICODE_STRING VolumeName;
    if (NT_SUCCESS(IoVolumeDeviceToDosName(FileObject->DeviceObject, &VolumeName))) {
        WideString Volume(&VolumeName);
        ExFreePool(VolumeName.Buffer);
        return Volume + FileObject->FileName.Buffer;
    } else {
        return FileObject->FileName.Buffer;
    }
}

namespace FltHandlers {
    NTSTATUS PreCreate(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        WideString Path = GetWin32Path(Data->Iopb->TargetFileObject);
        if (!Path.GetLength()) return STATUS_SUCCESS;

        KB_FLT_PRE_CREATE_INFO Info = {};
        HANDLE ProcessId = PsGetCurrentProcessId();
        HANDLE CurrentThreadId = PsGetCurrentThreadId();
        Info.ProcessId = reinterpret_cast<WdkTypes::HANDLE>(ProcessId);
        Info.AccessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        Path.CopyTo(Info.Path, (sizeof(Info.Path) / sizeof(Info.Path[0])) - 1);

        using namespace Communication;
        auto& Clients = Server.GetClients();

        Clients.LockShared();
        for (auto& Client : Clients) {
            if (!IsClientAppropriate(Client, KbFltPreCreate, CurrentThreadId)) continue;

            Server.Send(Client.ClientPort, &Info, sizeof(Info), &Info, sizeof(Info), 350);

            // Restoring constant fields:
            Info.ProcessId = reinterpret_cast<WdkTypes::HANDLE>(ProcessId);
            Info.AccessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        }
        Clients.Unlock();

        return Info.Status;
    }

    NTSTATUS PostRead(
        _Inout_  PFLT_CALLBACK_DATA Data,
        _In_     PCFLT_RELATED_OBJECTS FltObjects,
        _In_opt_ PVOID CompletionContext,
        _In_     FLT_POST_OPERATION_FLAGS Flags
    ) {
        UNREFERENCED_PARAMETER(Data);
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);
        UNREFERENCED_PARAMETER(Flags);

        return STATUS_SUCCESS;
    }

    NTSTATUS PreWrite(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        struct {
            PMDL* Mdl;
            ULONG* Size;
            PVOID* UserBuffer;
        } Params = {};

        if (!NT_SUCCESS(FltDecodeParameters(Data, &Params.Mdl, &Params.UserBuffer, &Params.Size, NULL))) 
            return STATUS_SUCCESS; // We're not attempt to filter it

        WideString Path = GetWin32Path(Data->Iopb->TargetFileObject);
        if (!Path.GetLength()) return STATUS_SUCCESS;

        KB_FLT_PRE_WRITE_INFO Info = {};
        HANDLE ProcessId = PsGetCurrentProcessId();
        HANDLE CurrentThreadId = PsGetCurrentThreadId();
        
        using namespace Communication;
        auto& Clients = Server.GetClients();

        Clients.LockShared();
        for (auto& Client : Clients) {
            if (!IsClientAppropriate(Client, KbFltPreWrite, CurrentThreadId)) continue;

            // Every iteration restoring constant fields:
            Info.ProcessId = reinterpret_cast<WdkTypes::HANDLE>(ProcessId);
            Info.Mdl = Params.Mdl ? reinterpret_cast<WdkTypes::PMDL>(*Params.Mdl) : NULL;
            Info.Size = Params.Size ? *Params.Size : 0;
            Path.CopyTo(Info.Path, (sizeof(Info.Path) / sizeof(Info.Path[0])) - 1);

            Server.Send(Client.ClientPort, &Info, sizeof(Info), &Info, sizeof(Info), 3000);
        }
        Clients.Unlock();

        return Info.Status;
    }
}

FLT_PREOP_CALLBACK_STATUS
FilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    // If we at DPC or greater we're unable to use communication ports...
    if (KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Check whether we have what to handle:
    if (!Data->Iopb->TargetFileObject)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    NTSTATUS Status = STATUS_SUCCESS;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        Status = FltHandlers::PreCreate(Data, FltObjects, CompletionContext);
        break;
    case IRP_MJ_WRITE:
        Status = FltHandlers::PreWrite(Data, FltObjects, CompletionContext);
        break;
    }

    if (!NT_SUCCESS(Status)) {
        Data->IoStatus.Status = Status;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FilterPostOperation(
    _Inout_  PFLT_CALLBACK_DATA Data,
    _In_     PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS Flags
) {
    if (KeGetCurrentIrql() > APC_LEVEL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!Data->Iopb->TargetFileObject)
        return FLT_POSTOP_FINISHED_PROCESSING;

    NTSTATUS Status = STATUS_SUCCESS;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_READ:
        Status = FltHandlers::PostRead(Data, FltObjects, CompletionContext, Flags);
        break;
    }

    if (!NT_SUCCESS(Status)) {
        Data->IoStatus.Status = Status;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
