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

#include "IOCTLs.h"

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

    bool IsProcessSubscribed(CommPort::ClientsList& Clients, HANDLE ProcessId) {
        for (const auto& Client : Clients) {
            if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) continue;
            auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
            if (ClientContext->Client.ProcessId == reinterpret_cast<UINT64>(ProcessId)) return true;
        }
        return false;
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
                Info.ParentId = reinterpret_cast<UINT64>(ParentId);
                Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
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
                Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
                Info.ThreadId = reinterpret_cast<UINT64>(ThreadId);
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
                Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
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

static WideString GetWin32Path(const PFLT_CALLBACK_DATA Data) {
    if (!Data || !Data->Iopb || !Data->Iopb->TargetFileObject) return WideString();
    const PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;
    if (!FileObject || !FileObject->DeviceObject || !FileObject->FileName.Buffer) return WideString();
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL || KeAreAllApcsDisabled())
        return WideString(&FileObject->FileName);

    UNICODE_STRING VolumeName;
    if (NT_SUCCESS(IoVolumeDeviceToDosName(FileObject->DeviceObject, &VolumeName))) {
        WideString Volume(&VolumeName);
        ExFreePool(VolumeName.Buffer);
        return Volume + WideString(&FileObject->FileName);
    }
    else {
        return WideString(&FileObject->FileName);
    }

    //POBJECT_NAME_INFORMATION Name = NULL;
    //if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &Name)) && Name) {
    //    WideString Path(&Name->Name);
    //    ExFreePool(Name);
    //    return Path;
    //} else {
    //    return WideString(&FileObject->FileName);
    //}
}

static WideString GetNtFileName(const PFLT_CALLBACK_DATA Data) {
    if (!Data || !Data->Iopb || !Data->Iopb->TargetFileObject) return WideString();

    PFLT_FILE_NAME_INFORMATION Info = NULL;
    NTSTATUS Status = FltGetFileNameInformation(
        Data, 
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &Info
    );

    if (!NT_SUCCESS(Status) || !Info) return WideString();

    FltParseFileNameInformation(Info);
    WideString FileName(&Info->Name);

    FltReleaseFileNameInformation(Info);

    return FileName;
}

static WideString GetFilePath(const PFLT_CALLBACK_DATA Data) {
    WideString Path = GetWin32Path(Data);
    if (!Path.GetLength()) Path = GetNtFileName(Data);
    return Path;
}

namespace FltHandlers {
    enum FltDirection {
        FltPreOp,
        FltPostOp
    };

    NTSTATUS FltCreateHandler(
        FltDirection Direction,
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        // Check whether MajorNumber is valid:
        if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) 
            return STATUS_SUCCESS;

        KbFltTypes HandlerType = KbFltNone;
        switch (Direction) {
        case FltPreOp:
            HandlerType = KbFltPreCreate;
            break;
        case FltPostOp:
            HandlerType = KbFltPostCreate;
            break;
        default:
            return STATUS_SUCCESS; // Unknown direction
        }

        WideString Path = GetFilePath(Data);

        KB_FLT_CREATE_INFO Info = {};
        HANDLE ProcessId = PsGetCurrentProcessId();
        HANDLE ThreadId = PsGetCurrentThreadId();
        Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
        Info.ThreadId = reinterpret_cast<UINT64>(ThreadId);
        Info.AccessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        Path.CopyTo(Info.Path, (sizeof(Info.Path) / sizeof(Info.Path[0])) - 1);

        using namespace Communication;
        auto& Clients = Server.GetClients();

        Clients.LockShared();
        for (auto& Client : Clients) {
            if (!IsClientAppropriate(Client, HandlerType, ThreadId)) continue;

            Server.Send(Client.ClientPort, &Info, sizeof(Info), &Info, sizeof(Info), 350);

            // Restoring constant fields:
            Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
            Info.ThreadId = reinterpret_cast<UINT64>(ThreadId);
            Info.AccessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        }
        Clients.Unlock();

        return Info.Status;
    }

    NTSTATUS FltReadWriteHandler(
        FltDirection Direction,
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ _Inout_ PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        UCHAR IrpMjNumber = Data->Iopb->MajorFunction;
        KbFltTypes HandlerType = KbFltNone;
        switch (Direction) {
        case FltPreOp:
            switch (IrpMjNumber) {
            case IRP_MJ_READ:
                HandlerType = KbFltPreRead;
                break;
            case IRP_MJ_WRITE:
                HandlerType = KbFltPreWrite;
                break;
            default:
                return STATUS_SUCCESS; // Invalid IRP_MJ_*** for this handler
            }
            break;
        case FltPostOp:
            switch (IrpMjNumber) {
            case IRP_MJ_READ:
                HandlerType = KbFltPostRead;
                break;
            case IRP_MJ_WRITE:
                HandlerType = KbFltPostWrite;
                break;
            default:
                return STATUS_SUCCESS; // Invalid IRP_MJ_*** for this handler
            }
            break;
        default:
            return STATUS_SUCCESS; // Unknown direction
        }

        if (!NT_SUCCESS(FltLockUserBuffer(Data)))
            return STATUS_SUCCESS; // Well, we aren't filtering due to locking failure

        WideString Path = GetFilePath(Data);
        
        KB_FLT_READ_WRITE_INFO Info = {};
        HANDLE ProcessId = PsGetCurrentProcessId();
        HANDLE ThreadId = PsGetCurrentThreadId();
        PMDL Mdl = NULL;
        ULONG Size = 0;

        switch (HandlerType) {
        case KbFltPreRead:
        case KbFltPostRead:
            Mdl = Data->Iopb->Parameters.Read.MdlAddress;
            Size = Data->Iopb->Parameters.Read.Length;
            break;
        case KbFltPreWrite:
        case KbFltPostWrite:
            Mdl = Data->Iopb->Parameters.Write.MdlAddress;
            Size = Data->Iopb->Parameters.Write.Length;
            break;
        default:
            return STATUS_SUCCESS; // Invalid HandlerType fot this request
        }

        using namespace Communication;
        auto& Clients = Server.GetClients();

        Clients.LockShared();
        if (!IsProcessSubscribed(Clients, ProcessId)) for (auto& Client : Clients) {
            if (!IsClientAppropriate(Client, HandlerType, ThreadId)) continue;

            // Every iteration restoring constant fields:
            Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
            Info.ThreadId = reinterpret_cast<UINT64>(ThreadId);
            Info.LockedMdl = reinterpret_cast<WdkTypes::PMDL>(Mdl);
            Info.Size = Size;
            Path.CopyTo(Info.Path, (sizeof(Info.Path) / sizeof(Info.Path[0])) - 1);

            Server.Send(Client.ClientPort, &Info, sizeof(Info), &Info, sizeof(Info), 5000);
        }
        Clients.Unlock();

        return Info.Status;    
    }

    NTSTATUS FltDeviceControlHandler(
        FltDirection Direction,
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Flt_CompletionContext_Outptr_ _Inout_ PVOID* CompletionContext
    ) {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        UCHAR IrpMjNumber = Data->Iopb->MajorFunction;
        KbFltTypes HandlerType = KbFltNone;
        switch (Direction) {
        case FltPreOp:
            switch (IrpMjNumber) {
            case IRP_MJ_DEVICE_CONTROL:
                HandlerType = KbFltPreDeviceControl;
                break;
            case IRP_MJ_INTERNAL_DEVICE_CONTROL:
                HandlerType = KbFltPreInternalDeviceControl;
                break;
            case IRP_MJ_FILE_SYSTEM_CONTROL:
                HandlerType = KbFltPreFileSystemControl;
                break;
            default:
                return STATUS_SUCCESS; // Invalid IRP_MJ_*** for this handler
            }
            break;
        case FltPostOp:
            switch (IrpMjNumber) {
            case IRP_MJ_DEVICE_CONTROL:
                HandlerType = KbFltPostDeviceControl;
                break;
            case IRP_MJ_INTERNAL_DEVICE_CONTROL:
                HandlerType = KbFltPostInternalDeviceControl;
                break;
            case IRP_MJ_FILE_SYSTEM_CONTROL:
                HandlerType = KbFltPostFileSystemControl;
                break;
            default:
                return STATUS_SUCCESS; // Invalid IRP_MJ_*** for this handler
            }
            break;
        default:
            return STATUS_SUCCESS; // Unknown direction
        }

        WideString Path = GetFilePath(Data);

        KB_FLT_DEVICE_CONTROL_INFO Info = {};
        HANDLE ProcessId = PsGetCurrentProcessId();
        HANDLE ThreadId = PsGetCurrentThreadId();
        ULONG Ioctl = Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;
        ULONG InputSize = Data->Iopb->Parameters.DeviceIoControl.Common.InputBufferLength;
        ULONG OutputSize = Data->Iopb->Parameters.DeviceIoControl.Common.OutputBufferLength;
        PMDL InputMdl = NULL;
        PMDL OutputMdl = NULL;

        switch (EXTRACT_CTL_METHOD(Ioctl)) {
        case METHOD_BUFFERED: {
            PVOID SystemBuffer = Data->Iopb->Parameters.DeviceIoControl.Buffered.SystemBuffer;
            if (SystemBuffer && InputSize)
                InputMdl = Mdl::AllocMdlAndLockPages(SystemBuffer, InputSize);
            if (SystemBuffer && OutputSize)
                OutputMdl = Mdl::AllocMdlAndLockPages(SystemBuffer, InputSize, KernelMode, IoWriteAccess);
            break;
        }
        case METHOD_IN_DIRECT:
        case METHOD_OUT_DIRECT: {
            PVOID InputSystemBuffer = Data->Iopb->Parameters.DeviceIoControl.Direct.InputSystemBuffer;
            if (InputSystemBuffer && InputSize)
                InputMdl = Mdl::AllocMdlAndLockPages(InputSystemBuffer, InputSize);
            if (NT_SUCCESS(FltLockUserBuffer(Data)))
                OutputMdl = Data->Iopb->Parameters.DeviceIoControl.Direct.OutputMdlAddress;
            break;
        }
        case METHOD_NEITHER:
            PVOID InputUserBuffer = Data->Iopb->Parameters.DeviceIoControl.Neither.InputBuffer;
            if (InputUserBuffer && InputSize)
                InputMdl = Mdl::AllocMdlAndLockPages(InputUserBuffer, InputSize);
            if (NT_SUCCESS(FltLockUserBuffer(Data)))
                OutputMdl = Data->Iopb->Parameters.DeviceIoControl.Neither.OutputMdlAddress;
            break;
        }

        using namespace Communication;
        auto& Clients = Server.GetClients();

        Clients.LockShared();
        if (!IsProcessSubscribed(Clients, ProcessId)) for (auto& Client : Clients) {
            if (!IsClientAppropriate(Client, HandlerType, ThreadId)) continue;

            // Every iteration restoring constant fields:
            Info.ProcessId = reinterpret_cast<UINT64>(ProcessId);
            Info.ThreadId = reinterpret_cast<UINT64>(ThreadId);
            Info.InputLockedMdl = reinterpret_cast<WdkTypes::PMDL>(InputMdl);
            Info.OutputLockedMdl = reinterpret_cast<WdkTypes::PMDL>(OutputMdl);
            Info.InputSize = InputSize;
            Info.OutputSize = OutputSize;
            Info.Ioctl = Ioctl;
            Path.CopyTo(Info.Path, (sizeof(Info.Path) / sizeof(Info.Path[0])) - 1);

            Server.Send(Client.ClientPort, &Info, sizeof(Info), &Info, sizeof(Info), 5000);
        }
        Clients.Unlock();

        switch (EXTRACT_CTL_METHOD(Ioctl)) {
        case METHOD_BUFFERED:
            if (OutputMdl) 
                Mdl::UnlockPagesAndFreeMdl(OutputMdl);
            [[fallthrough]];
        case METHOD_IN_DIRECT:
        case METHOD_OUT_DIRECT:
        case METHOD_NEITHER:
            if (InputMdl) 
                Mdl::UnlockPagesAndFreeMdl(InputMdl);
            break;
        }

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
        Status = FltHandlers::FltCreateHandler(FltHandlers::FltPreOp, Data, FltObjects, CompletionContext);
        break;
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        Status = FltHandlers::FltReadWriteHandler(FltHandlers::FltPreOp, Data, FltObjects, CompletionContext);
        break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        Status = FltHandlers::FltDeviceControlHandler(FltHandlers::FltPreOp, Data, FltObjects, CompletionContext);
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
    UNREFERENCED_PARAMETER(Flags);

    if (KeGetCurrentIrql() > APC_LEVEL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!Data->Iopb->TargetFileObject)
        return FLT_POSTOP_FINISHED_PROCESSING;

    NTSTATUS Status = STATUS_SUCCESS;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        Status = FltHandlers::FltCreateHandler(FltHandlers::FltPostOp, Data, FltObjects, &CompletionContext);
        break;
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        Status = FltHandlers::FltReadWriteHandler(FltHandlers::FltPostOp, Data, FltObjects, &CompletionContext);
        break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        Status = FltHandlers::FltDeviceControlHandler(FltHandlers::FltPostOp, Data, FltObjects, &CompletionContext);
        break;
    }

    if (!NT_SUCCESS(Status)) {
        Data->IoStatus.Status = Status;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
