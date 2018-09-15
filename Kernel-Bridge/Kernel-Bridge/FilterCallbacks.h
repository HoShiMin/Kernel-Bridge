#pragma once

namespace Communication {
    NTSTATUS StartServer(PFLT_FILTER FilterHandle);
    VOID StopServer();
}

namespace KbCallbacks {
    NTSTATUS StartObFilter();
    VOID StopObFilter();
}

EXTERN_C_START

FLT_PREOP_CALLBACK_STATUS
FilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FilterPostOperation(
    _Inout_  PFLT_CALLBACK_DATA Data,
    _In_     PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS Flags
);

EXTERN_C_END