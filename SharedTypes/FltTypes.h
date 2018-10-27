#pragma once

enum KbFltTypes {
    KbObCallbacks,
    KbPsProcess,
    KbPsThread,
    KbPsImage,
    KbFltPreCreate,
    KbFltPostCreate,
    KbFltPreRead,
    KbFltPostRead,
    KbFltPreWrite,
    KbFltPostWrite,
    KbFltPreDeviceControl,
    KbFltPostDeviceControl,
    KbFltPreInternalDeviceControl,
    KbFltPostInternalDeviceControl,
    KbFltPreFileSystemControl,
    KbFltPostFileSystemControl,
    KbFltNone
};

DECLARE_STRUCT(KB_FLT_CONTEXT, {
    KbFltTypes Type;
    WdkTypes::CLIENT_ID Client;    
});

DECLARE_STRUCT(KB_FLT_OB_CALLBACK_INFO, {
    WdkTypes::CLIENT_ID Client;
    WdkTypes::CLIENT_ID Target;
    ACCESS_MASK CreateDesiredAccess;
    ACCESS_MASK DuplicateDesiredAccess;
    ACCESS_MASK CreateResultAccess;
    ACCESS_MASK DuplicateResultAccess;
});

DECLARE_STRUCT(KB_FLT_PS_PROCESS_INFO, {
    UINT64 ParentId;
    UINT64 ProcessId;
    BOOLEAN Created;
});

DECLARE_STRUCT(KB_FLT_PS_THREAD_INFO, {
    UINT64 ProcessId;
    UINT64 ThreadId;
    BOOLEAN Created;
});

DECLARE_STRUCT(KB_FLT_PS_IMAGE_INFO, {
    UINT64 ProcessId;
    WdkTypes::PVOID BaseAddress;
    UINT64 ImageSize;
    WCHAR FullImageName[384]; // Fixed size! Enough for paths.
});

DECLARE_STRUCT(KB_FLT_CREATE_INFO, {
    UINT64 ProcessId;
    UINT64 ThreadId;
    ACCESS_MASK AccessMask;
    WdkTypes::NTSTATUS Status;
    WCHAR Path[384]; // Fixed size! Enough for paths.
});

DECLARE_STRUCT(KB_FLT_READ_WRITE_INFO, {
    UINT64 ProcessId;
    UINT64 ThreadId; 
    WdkTypes::PMDL LockedMdl;
    ULONG Size;
    WdkTypes::NTSTATUS Status;
    WCHAR Path[384];
});

DECLARE_STRUCT(KB_FLT_DEVICE_CONTROL_INFO, {
    UINT64 ProcessId;
    UINT64 ThreadId; 
    WdkTypes::PMDL InputLockedMdl;
    WdkTypes::PMDL OutputLockedMdl;
    ULONG InputSize;
    ULONG OutputSize;
    ULONG Ioctl;
    WdkTypes::NTSTATUS Status;
    WCHAR Path[384];
});