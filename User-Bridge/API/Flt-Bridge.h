#pragma once

/*
    Depends on:
    - Windows.h
    - fltUser.h
    - functional
    - WdkTypes.h
    - FltTypes.h
    - CommPort.h
*/

template <typename PacketDataType, KbFltTypes PacketType>
class CommPortListener {
public:
    using _Callback = std::function<void(CommPort& Port, MessagePacket<PacketDataType>& Message)>;
private:
    CommPort Port;
    HANDLE hThread;
    _Callback Callback;

    HRESULT ConnectStatus;
    HANDLE hSubscriptionEvent;

    static bool CallCallbackSafe(CommPortListener* Self, MessagePacket<PacketDataType>& Message) {
        if (Self->Callback) {
            __try {
                Self->Callback(Self->Port, Message);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }
        return true;
    }

    static VOID WINAPI ListenerThread(CommPortListener* Self) {
        KB_FLT_CONTEXT Context = {};
        Context.Type = PacketType;
        Context.Client.ProcessId = GetCurrentProcessId();
        Context.Client.ThreadId = GetCurrentThreadId();

        static LPCWSTR PortName = L"\\Kernel-Bridge";
        Self->ConnectStatus = Self->Port.Connect(PortName, &Context, sizeof(Context));
        SetEvent(Self->hSubscriptionEvent);
        if (!SUCCEEDED(Self->ConnectStatus)) ExitThread(0);

        HRESULT Status;
        do {
            MessagePacket<PacketDataType> Message;
            Status = Self->Port.Recv(*reinterpret_cast<CommPortPacket*>(&Message));
            if (SUCCEEDED(Status)) {
                CallCallbackSafe(Self, Message);
            }
        } while (SUCCEEDED(Status));
        ExitThread(0);    
    }
public:
    CommPortListener() : Port(), hThread(NULL), Callback(NULL), ConnectStatus(ERROR_SUCCESS) {
        hSubscriptionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    }
    ~CommPortListener() {
        Unsubscribe();
        CloseHandle(hSubscriptionEvent);    
    } 

    BOOL Subscribe(_Callback Listener) {
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

    VOID Unsubscribe() {
        if (!hThread) return;
        Port.Disconnect();
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        hThread = NULL;    
    }
};