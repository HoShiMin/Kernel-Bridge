#include <fltKernel.h>

#include "MemoryUtils.h"

#include "Locks.h"
#include "LinkedList.h"
#include "CommPort.h"

CommPort::CommPort() 
: ParentFilter(NULL), ServerCookie({}), ServerPort(NULL), Clients(), OnMessageCallback(NULL) {}

CommPort::~CommPort() {
    StopServer();
}



NTSTATUS CommPort::StartServer(
    PFLT_FILTER Filter, 
    LPCWSTR PortName,
    _OnMessage OnMessage,
    LONG MaxConnections,
    OPTIONAL PVOID Cookie
)  {
    if (ServerPort) StopServer();

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
        KdPrint(("[Kernel-Bridge]: Comm.Port failure: 0x%X\r\n", Status));
    
    return Status;
}

VOID CommPort::StopServer() {
    if (ServerPort) FltCloseCommunicationPort(ServerPort);
    // Disconnecting all connected clients:
    Clients.LockExclusive();
    for (auto& Client : Clients) {
        FltCloseClientPort(ParentFilter, &Client.ClientPort);
    }
    Clients.Unlock();
}



NTSTATUS CommPort::OnConnectInternal(
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

    // Add 'Client' to clients list:
    auto ServerInstance = static_cast<CommPort*>(ServerCookie->ServerInstance);
    ServerInstance->Clients.LockExclusive();
    *ConnectionPortCookie = static_cast<PVOID>(ServerInstance->Clients.InsertTail(Client));
    ServerInstance->Clients.Unlock();

    return STATUS_SUCCESS;
}

VOID CommPort::OnDisconnectInternal(
    IN PVOID ConnectionContext
) {
    KdPrint(("[Kernel-Bridge]: Comm.Port OnDisconnect\r\n"));

    // Free client-specific info:
    auto ClientEntry = static_cast<ClientsList::ListEntry*>(ConnectionContext);
    if (ClientEntry->GetValue()->ClientPort) 
        FltCloseClientPort(ClientEntry->GetValue()->ServerInstance->ParentFilter, &ClientEntry->GetValue()->ClientPort);
    if (ClientEntry->GetValue()->ConnectionContext && ClientEntry->GetValue()->SizeOfContext) {
        VirtualMemory::FreePoolMemory(ClientEntry->GetValue()->ConnectionContext);
    }

    // Unlink client from clients list:
    CommPort* ServerInstance = ClientEntry->GetValue()->ServerInstance;
    ServerInstance->Clients.LockExclusive();
    ServerInstance->Clients.Remove(ClientEntry);
    ServerInstance->Clients.Unlock();
}

NTSTATUS CommPort::OnMessageInternal(
    IN PVOID PortCookie,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnOutputBufferLength
) {
    auto ClientEntry = static_cast<ClientsList::ListEntry*>(PortCookie);
    _OnMessage Handler = ClientEntry->GetValue()->ServerInstance->OnMessageCallback;
    if (Handler) { 
        CLIENT_REQUEST Request = {};
        Request.InputBuffer = InputBuffer;
        Request.InputSize = InputBufferLength;
        Request.OutputBuffer = OutputBuffer;
        Request.OutputSize = OutputBufferLength;
        return Handler(*ClientEntry->GetValue(), Request, ReturnOutputBufferLength);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CommPort::Send(
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
    _Timeout.QuadPart = - static_cast<INT64>(MsecTimeout) * 10 * 1000; // Relative time is negative!
    return FltSendMessage(ParentFilter, &Client, Buffer, Size, Response, &ResponseSize, &_Timeout);
}