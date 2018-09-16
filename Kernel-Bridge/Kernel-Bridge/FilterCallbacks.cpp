#include <fltKernel.h>

#include "../API/MemoryUtils.h"
#include "../API/Locks.h"
#include "../API/LinkedList.h"
#include "../API/CommPort.h"
#include "../API/ObCallbacks.h"
#include "../API/PsCallbacks.h"

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
                    if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) continue;
                    auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
                    if (ClientContext->Type != KbObCallbacks) continue;
                    
                    constexpr int Timeout = 350; // Timeout per request, ms

                    KB_FLT_OB_CALLBACK_INFO Request = FltInfo;
                    Server.Send(Client.ClientPort, &Request, sizeof(Request), &Request, sizeof(Request), Timeout);
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
                    if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) continue;
                    auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
                    if (ClientContext->Type != KbPsProcess) continue;
                    if (reinterpret_cast<HANDLE>(ClientContext->Client.ThreadId) == CurrentThreadId) continue;

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
                    if (Client.SizeOfContext != sizeof(KB_FLT_CONTEXT)) continue;
                    auto ClientContext = static_cast<PKB_FLT_CONTEXT>(Client.ConnectionContext);
                    if (ClientContext->Type != KbPsThread) continue;
                    if (reinterpret_cast<HANDLE>(ClientContext->Client.ThreadId) == CurrentThreadId) continue;

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

FLT_PREOP_CALLBACK_STATUS
FilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FilterPostOperation(
    _Inout_  PFLT_CALLBACK_DATA Data,
    _In_     PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
