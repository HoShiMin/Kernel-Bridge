#pragma once

enum KbFltTypes {
    KbObCallbacks,
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