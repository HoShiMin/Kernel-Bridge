#pragma once

class ObCallbacks {
public:
    using _Callback = VOID(WINAPI*)(CommPort& Port, IN OUT KB_FLT_OB_CALLBACK_INFO& Info);
private:
    CommPort Port;
    HANDLE hThread;
    _Callback Callback;

    HRESULT ConnectStatus;
    HANDLE hSubscriptionEvent;
    static VOID WINAPI ListenerThread(ObCallbacks* Self);
public:
    ObCallbacks();
    ~ObCallbacks();

    BOOL Subscribe(_Callback Listener);
    VOID Unsubscribe();
};