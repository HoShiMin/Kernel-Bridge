#pragma once

class CommPort {
public:
    using CLIENT_INFO = struct {
        CommPort* ServerInstance;
        PFLT_PORT ClientPort;
        PVOID ConnectionContext;
        ULONG SizeOfContext;
    };

    class ClientsList : public EResource, public LinkedList<CLIENT_INFO> {
    public:
        ClientsList() : EResource(), LinkedList<CLIENT_INFO>() {}
        ~ClientsList() = default;
    };
    
    using CLIENT_REQUEST = struct {
        IN PVOID InputBuffer;
        ULONG InputSize;
        OUT PVOID OutputBuffer;
        ULONG OutputSize;
    };
    
    using _OnMessage = NTSTATUS(NTAPI*)(CLIENT_INFO& Client, CLIENT_REQUEST& Request, OUT PULONG ReturnLength);

private:
    PFLT_FILTER ParentFilter;

    using SERVER_COOKIE = struct {
        CommPort* ServerInstance;
        PVOID UserCookie;
    };
    SERVER_COOKIE ServerCookie;

    PFLT_PORT ServerPort;

    ClientsList Clients;

    _OnMessage OnMessageCallback;

    static NTSTATUS OnConnectInternal(
        IN PFLT_PORT ClientPort,
        IN PVOID ServerPortCookie,
        IN PVOID ConnectionContext,
        IN ULONG SizeOfContext,
        OUT PVOID *ConnectionPortCookie    
    );

    static VOID OnDisconnectInternal(
        IN PVOID ConnectionCookie
    );

    static NTSTATUS OnMessageInternal(
        IN PVOID PortCookie,
        IN PVOID InputBuffer OPTIONAL,
        IN ULONG InputBufferLength,
        OUT PVOID OutputBuffer OPTIONAL,
        IN ULONG OutputBufferLength,
        OUT PULONG ReturnOutputBufferLength
    );

public:
    CommPort();
    ~CommPort();

    CommPort(const CommPort&) = delete;
    CommPort(CommPort&&) = delete;
    CommPort& operator = (const CommPort&) = delete;
    CommPort& operator = (CommPort&&) = delete;

    NTSTATUS StartServer(
        PFLT_FILTER Filter, 
        LPCWSTR PortName, 
        _OnMessage OnMessage,
        LONG MaxConnections = 128,
        OPTIONAL PVOID Cookie = NULL
    );

    VOID StopServer();

    ClientsList& GetClients() { return Clients; }

    NTSTATUS Send(
        PFLT_PORT Client, 
        IN PVOID Buffer, 
        ULONG Size, 
        OUT PVOID Response = NULL, 
        ULONG ResponseSize = 0,
        ULONG Timeout = 0
    );
};