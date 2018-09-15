#include <Windows.h>
#include <fltUser.h>
#include <vector>

#include <WdkTypes.h>
#include <FltTypes.h>

#include "CommPort.h"
#include "Flt-Bridge.h"

#include <iostream>

LPCWSTR PortName = L"\\Kernel-Bridge";

ObCallbacks::ObCallbacks() : Port(), hThread(NULL), Callback(NULL), ConnectStatus(ERROR_SUCCESS) {
    hSubscriptionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

ObCallbacks::~ObCallbacks() {
    Unsubscribe();
    CloseHandle(hSubscriptionEvent);
}

BOOL ObCallbacks::Subscribe(_Callback Listener) {
    if (hThread != NULL || !Listener) return FALSE;
    Callback = Listener;
    hThread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ListenerThread), this, 0, NULL);
    if (!hThread) return FALSE;
    WaitForSingleObject(hSubscriptionEvent, INFINITE);
    if (!SUCCEEDED(ConnectStatus)) {
        CloseHandle(hThread);
        hThread = NULL;
        return FALSE;
    }
    ResetEvent(hSubscriptionEvent);

    return SUCCEEDED(ConnectStatus);
}

VOID ObCallbacks::Unsubscribe() {
    if (!hThread) return;
    Port.Disconnect();
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    hThread = NULL;
}

VOID WINAPI ObCallbacks::ListenerThread(ObCallbacks* Self) {
    KB_FLT_CONTEXT Context = {};
    Context.Type = KbObCallbacks;
    Context.Client.ProcessId = GetCurrentProcessId();
    Context.Client.ThreadId = GetCurrentThreadId();

    Self->ConnectStatus = Self->Port.Connect(PortName, &Context, sizeof(Context));
    SetEvent(Self->hSubscriptionEvent);
    if (!SUCCEEDED(Self->ConnectStatus)) ExitThread(0);

    HRESULT Status;
    do {
        MessagePacket<KB_FLT_OB_CALLBACK_INFO> Message;
        Status = Self->Port.Recv(*reinterpret_cast<CommPortPacket*>(&Message));
        if (SUCCEEDED(Status)) {
            auto Data = static_cast<PKB_FLT_OB_CALLBACK_INFO>(Message.GetData());
            if (Self->Callback) Self->Callback(Self->Port, *Data);
            
            // Filling reply:
            ReplyPacket<KB_FLT_OB_CALLBACK_INFO> Reply;
            Reply.SetMessageId(Message.GetMessageId());
            Reply.SetReplyStatus(ERROR_SUCCESS);
            *static_cast<PKB_FLT_OB_CALLBACK_INFO>(Reply.GetData()) = *Data;
            
            Status = Self->Port.Reply(Reply);
        }
    } while (SUCCEEDED(Status) || Status == ERROR_FLT_NO_WAITER_FOR_REPLY);

    ExitThread(0);
}