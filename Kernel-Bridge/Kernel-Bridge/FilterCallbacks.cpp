#include <fltKernel.h>

#include "../API/MemoryUtils.h"
#include "../API/Locks.h"
#include "../API/LinkedList.h"
#include "../API/CommPort.h"
#include "../API/ObCallbacks.h"

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
    static ObCallbacks ObFilter;

    NTSTATUS StartObFilter() {
        return ObFilter.SetupCallbacks(
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

    VOID StopObFilter() {
        ObFilter.RemoveCallbacks();
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
