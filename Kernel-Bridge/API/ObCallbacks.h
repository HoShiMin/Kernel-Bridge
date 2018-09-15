#pragma once

class ObCallbacks final {
private:
    using _ObRegisterCallbacks = NTSTATUS(NTAPI*)(
        POB_CALLBACK_REGISTRATION CallbackRegistration,
        PVOID* RegistrationHandle    
    );
    using _ObUnRegisterCallbacks = NTSTATUS(NTAPI*)(
        PVOID RegistrationHandle
    );

    PVOID RegistrationHandle;
    _ObRegisterCallbacks DynObRegisterCallbacks;
    _ObUnRegisterCallbacks DynObUnRegisterCallbacks;

public:
    ObCallbacks(const ObCallbacks&) = delete;
    ObCallbacks(ObCallbacks&&) = delete;
    ObCallbacks& operator = (const ObCallbacks&) = delete;
    ObCallbacks& operator = (ObCallbacks&&) = delete;

    enum ObCallbackType {
        ctAll,
        ctProcesses,
        ctThreads,
        ctMaxValue // Same as ctAll
    };

    ObCallbacks();
    ObCallbacks(
        OPTIONAL OB_PREOP_CALLBACK_STATUS(NTAPI *PreCallback)(
            PVOID RegistrationContext, 
            POB_PRE_OPERATION_INFORMATION OperationInformation
        ),
        OPTIONAL VOID (NTAPI *PostCallback)(
            PVOID RegistrationContext,
            POB_POST_OPERATION_INFORMATION OperationInformation
        ) = NULL,
        OPTIONAL PVOID RegistrationContext = NULL,
        ObCallbackType ObjectType = ObCallbackType::ctAll,
        OB_OPERATION OperationType = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE    
    );
    ~ObCallbacks();

    NTSTATUS SetupCallbacks(
        OPTIONAL OB_PREOP_CALLBACK_STATUS(NTAPI *PreCallback)(
            PVOID RegistrationContext, 
            POB_PRE_OPERATION_INFORMATION OperationInformation
        ),
        OPTIONAL VOID (NTAPI *PostCallback)(
            PVOID RegistrationContext,
            POB_POST_OPERATION_INFORMATION OperationInformation
        ) = NULL,
        OPTIONAL PVOID RegistrationContext = NULL,
        ObCallbackType ObjectType = ObCallbackType::ctAll,
        OB_OPERATION OperationType = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE
    );
    VOID RemoveCallbacks();
};