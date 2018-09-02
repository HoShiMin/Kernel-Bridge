#include <fltKernel.h>

#include "MemoryUtils.h"

#include "Locks.h"
#include "LinkedList.h"
#include "CommunicationPort.h"

CommunicationPort::CommunicationPort() 
: ParentFilter(NULL), ServerCookie({}), ServerPort(NULL), Clients(), OnMessageCallback(NULL) {}

CommunicationPort::~CommunicationPort() {
    StopServer();
}



NTSTATUS CommunicationPort::StartServer(
    PFLT_FILTER Filter, 
    LPCWSTR PortName,
    _OnMessage OnMessage,
    LONG MaxConnections,
    OPTIONAL PVOID Cookie
)  {
    ParentFilter = Filter;
    OnMessageCallback = OnMessage;

    ServerCookie.ServerInstance = this;
    ServerCookie.UserCookie = Cookie;

    UNICODE_STRING Name = {};
    RtlInitUnicodeString(&Name, PortName);

    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    NTSTATUS Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Kernel-Bridge]: Create security descriptor failure (0x%X)\r\n", Status));
        return Status;
    }

    OBJECT_ATTRIBUTES ObjectAttributes = {};
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, SecurityDescriptor);

    Status = FltCreateCommunicationPort(
        ParentFilter,
        &ServerPort,
        &ObjectAttributes,
        &ServerCookie,
        OnConnectInternal,
        OnDisconnectInternal,
        OnMessageInternal,
        MaxConnections
    );

    FltFreeSecurityDescriptor(SecurityDescriptor);

    if (NT_SUCCESS(Status))
        KdPrint(("[Kernel-Bridge]: Comm.Port created!\r\n"));
    else
        KdPrint(("[Kernel-Bridge]: Comm.Port failure (0x%X)\r\n", Status));
    
    return Status;
}

VOID CommunicationPort::StopServer() {
    if (ServerPort) FltCloseCommunicationPort(ServerPort);
    // Disconnecting all connected clients:
    Clients.ForEachExclusive([](CLIENT_INFO& Value) -> ClientsList::ExclusiveAction {
        FltCloseClientPort(Value.ServerInstance->ParentFilter, &Value.ClientPort);
        return ClientsList::exContinue;
    });
}



NTSTATUS CommunicationPort::OnConnectInternal(
    IN PFLT_PORT ClientPort,
    IN PVOID ServerPortCookie,
    IN PVOID ConnectionContext,
    IN ULONG SizeOfContext,
    OUT PVOID *ConnectionPortCookie
) {
    KdPrint(("[Kernel-Bridge]: Comm.Port OnConnect\r\n"));

    auto ServerCookie = static_cast<SERVER_COOKIE*>(ServerPortCookie);

    CLIENT_INFO Client = {};
    Client.ServerInstance = ServerCookie->ServerInstance;
    Client.ClientPort = ClientPort;
    
    if (ConnectionContext && SizeOfContext) { 
        PVOID ContextBuffer = VirtualMemory::AllocFromPool(SizeOfContext);
        RtlCopyMemory(ContextBuffer, ConnectionContext, SizeOfContext);
        Client.ConnectionContext = ContextBuffer;
        Client.SizeOfContext = SizeOfContext;
    }

    *ConnectionPortCookie = static_cast<PVOID>(ServerCookie->ServerInstance->Clients.InsertTail(Client));
    return STATUS_SUCCESS;
}

VOID CommunicationPort::OnDisconnectInternal(
    IN PVOID ConnectionContext
) {
    KdPrint(("[Kernel-Bridge]: Comm.Port OnDisconnect\r\n"));

    auto ClientEntry = static_cast<ClientsList::_Entry*>(ConnectionContext);
    if (ClientEntry->Value.ClientPort) 
        FltCloseClientPort(ClientEntry->Value.ServerInstance->ParentFilter, &ClientEntry->Value.ClientPort);
    if (ClientEntry->Value.ConnectionContext && ClientEntry->Value.SizeOfContext) {
        VirtualMemory::FreePoolMemory(ClientEntry->Value.ConnectionContext);
    }
    CommunicationPort* Instance = ClientEntry->Value.ServerInstance;
    Instance->Clients.Remove(ClientEntry);
}

NTSTATUS CommunicationPort::OnMessageInternal(
    IN PVOID PortCookie,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnOutputBufferLength
) {
    auto ClientEntry = static_cast<ClientsList::_Entry*>(PortCookie);
    _OnMessage Handler = ClientEntry->Value.ServerInstance->OnMessageCallback;
    if (Handler) { 
        CLIENT_REQUEST Request = {};
        Request.InputBuffer = InputBuffer;
        Request.InputSize = InputBufferLength;
        Request.OutputBuffer = OutputBuffer;
        Request.OutputSize = OutputBufferLength;
        return Handler(ClientEntry->Value, Request, ReturnOutputBufferLength);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CommunicationPort::Send(
    PFLT_PORT Client, 
    IN PVOID Buffer, 
    ULONG Size, 
    OUT PVOID Response, 
    ULONG ResponseSize,
    ULONG MsecTimeout
) {
    if (MsecTimeout == 0xFFFFFFFF) // Infinite wait:
        return FltSendMessage(ParentFilter, &Client, Buffer, Size, Response, &ResponseSize, NULL);

    LARGE_INTEGER _Timeout; // In 100-ns units
    _Timeout.QuadPart = static_cast<UINT64>(MsecTimeout) * 10 * 1000;
    return FltSendMessage(ParentFilter, &Client, Buffer, Size, Response, &ResponseSize, &_Timeout);
}