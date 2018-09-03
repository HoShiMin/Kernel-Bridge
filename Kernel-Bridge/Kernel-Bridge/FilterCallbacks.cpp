#include <fltKernel.h>

#include "../API/Locks.h"
#include "../API/LinkedList.h"
#include "../API/CommPort.h"

#include "FilterCallbacks.h"

namespace Communication {
    CommPort Server;

    NTSTATUS StartServer(PFLT_FILTER FilterHandle) {
        return Server.StartServer(
            FilterHandle, 
            L"\\Kernel-Bridge",
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
