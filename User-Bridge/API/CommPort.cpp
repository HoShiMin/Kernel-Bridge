#include <Windows.h>
#include <fltuser.h>

#pragma comment(lib, "FltLib.lib")

#include "CommPort.h"

CommPort::CommPort() : hPort(NULL), Connected(FALSE) {}

CommPort::~CommPort() {
    Disconnect();
}

HRESULT CommPort::Connect(LPCWSTR PortName, PVOID Context, WORD SizeOfContext) {
    HRESULT Status = FilterConnectCommunicationPort(
        PortName,
        0,
        Context,
        SizeOfContext,
        NULL,
        &hPort
    );
    Connected = Status == S_OK;
    return Status;
}

VOID CommPort::Disconnect() {
    if (hPort) CloseHandle(hPort);
}

HRESULT CommPort::Send(
    IN PVOID Input, 
    DWORD InputSize, 
    OUT PVOID Output, 
    DWORD OutputSize, 
    OUT OPTIONAL PULONG ReturnLength
) {
    DWORD Returned = 0;
    HRESULT Status = FilterSendMessage(hPort, Input, InputSize, Output, OutputSize, &Returned);
    if (ReturnLength) *ReturnLength = Returned;
    return Status;
}

HRESULT CommPort::Recv(_Out_ CommPortPackage& ReceivedMessage) {
    return FilterGetMessage(
        hPort,
        static_cast<PFILTER_MESSAGE_HEADER>(ReceivedMessage.GetHeader()),
        ReceivedMessage.GetSize(),
        NULL
    );
}

HRESULT CommPort::Reply(const _In_ CommPortPackage& ReplyMessage) {
    return FilterReplyMessage(hPort, static_cast<PFILTER_REPLY_HEADER>(ReplyMessage.GetHeader()), ReplyMessage.GetSize());
}
