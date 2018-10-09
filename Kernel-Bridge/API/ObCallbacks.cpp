#include <wdm.h>

#include "ObCallbacks.h"
#include "Importer.h"

ObCallbacks::ObCallbacks() : RegistrationHandle(NULL) {
    // For the WinXP support we should import them dynamically:
    DynObRegisterCallbacks = static_cast<_ObRegisterCallbacks>(
        Importer::GetKernelProcAddress(L"ObRegisterCallbacks")
    );
    DynObUnRegisterCallbacks = static_cast<_ObUnRegisterCallbacks>(
        Importer::GetKernelProcAddress(L"ObUnRegisterCallbacks")
    );
}

ObCallbacks::ObCallbacks(
    OPTIONAL OB_PREOP_CALLBACK_STATUS(NTAPI *PreCallback)(
        PVOID RegistrationContext, 
        POB_PRE_OPERATION_INFORMATION OperationInformation
    ),
    OPTIONAL VOID (NTAPI *PostCallback)(
        PVOID RegistrationContext,
        POB_POST_OPERATION_INFORMATION OperationInformation
    ),
    OPTIONAL PVOID RegistrationContext,
    ObCallbackType CallbackType,
    OB_OPERATION OperationType
) : ObCallbacks() {
    SetupCallbacks(PreCallback, PostCallback, RegistrationContext, CallbackType, OperationType);
}

ObCallbacks::~ObCallbacks() {
    RemoveCallbacks();
}

NTSTATUS ObCallbacks::SetupCallbacks(
    OPTIONAL OB_PREOP_CALLBACK_STATUS(NTAPI *PreCallback)(
        PVOID RegistrationContext, 
        POB_PRE_OPERATION_INFORMATION OperationInformation
    ),
    OPTIONAL VOID (NTAPI *PostCallback)(
        PVOID RegistrationContext,
        POB_POST_OPERATION_INFORMATION OperationInformation
    ),
    OPTIONAL PVOID RegistrationContext,
    ObCallbackType CallbackType,
    OB_OPERATION OperationType
) {
    if (RegistrationHandle) RemoveCallbacks();

    if (!DynObRegisterCallbacks || !DynObUnRegisterCallbacks) 
        return STATUS_NOT_SUPPORTED;

    if ((CallbackType == (ctProcesses | ctThreads)) || (CallbackType == ctMaxValue)) 
        CallbackType = ctAll;

    if (!PreCallback && !PostCallback) 
        return STATUS_INVALID_PARAMETER;

    OB_OPERATION_REGISTRATION Operations[ctMaxValue - 1] = {};
    
    Operations[ctProcesses - 1].ObjectType = PsProcessType;
    Operations[ctProcesses - 1].Operations = OperationType;
    Operations[ctProcesses - 1].PreOperation = PreCallback;
    Operations[ctProcesses - 1].PostOperation = PostCallback;
    
    Operations[ctThreads - 1].ObjectType = PsThreadType;
    Operations[ctThreads - 1].Operations = OperationType;
    Operations[ctThreads - 1].PreOperation = PreCallback;
    Operations[ctThreads - 1].PostOperation = PostCallback;

    OB_CALLBACK_REGISTRATION Registration = {};
    Registration.Version = OB_FLT_REGISTRATION_VERSION;
    Registration.OperationRegistrationCount = CallbackType == ctAll 
        ? sizeof(Operations) / sizeof(*Operations) 
        : 1;
    RtlInitUnicodeString(&Registration.Altitude, L"389020");
    Registration.RegistrationContext = RegistrationContext;
    Registration.OperationRegistration = CallbackType == ctAll 
        ? reinterpret_cast<POB_OPERATION_REGISTRATION>(&Operations)
        : reinterpret_cast<POB_OPERATION_REGISTRATION>(&Operations[CallbackType - 1]);

    return DynObRegisterCallbacks(&Registration, &RegistrationHandle);
}

VOID ObCallbacks::RemoveCallbacks() {
    if (RegistrationHandle)
        DynObUnRegisterCallbacks(RegistrationHandle);
    RegistrationHandle = NULL;
}