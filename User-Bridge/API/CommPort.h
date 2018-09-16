#pragma once

class CommPortPacket {
public:
    CommPortPacket() = default;
    ~CommPortPacket() = default;
    virtual PVOID GetHeader() = 0;
    virtual PVOID GetData() = 0;
    virtual ULONG GetSize() const = 0;
};

template <typename T>
class MessagePacket : public CommPortPacket {
private:
    struct {
        FILTER_MESSAGE_HEADER Header;
        T Data;
    } Packet;
public:
    MessagePacket() : Packet({}) {}
    ~MessagePacket() {}

    PVOID GetHeader() override { return static_cast<PVOID>(&Packet.Header); }
    PVOID GetData() override { return static_cast<PVOID>(&Packet.Data); }
    ULONG GetSize() const override { return sizeof(Packet); }

    ULONG GetReplyLength() const { return Packet.Header.ReplyLength; }
    ULONGLONG GetMessageId() const { return Packet.Header.MessageId; }
};

template <typename T>
class ReplyPacket : public CommPortPacket {
private:
    struct {
        FILTER_REPLY_HEADER Header;
        T Data;
    } Packet;
public:
    ReplyPacket() : CommPortPacket(), Packet({}) {}
    ReplyPacket(CommPortPacket& Message, ULONG Status) : ReplyPacket() {
        SetMessageId(static_cast<PFILTER_MESSAGE_HEADER>(Message.GetHeader())->MessageId);
        SetReplyStatus(Status);
    }
    ReplyPacket(CommPortPacket& Message, ULONG Status, const T& Data) : ReplyPacket(Message, Status) {
        SetData(Data);
    }
    ~ReplyPacket() {}
    
    PVOID GetData() override { return static_cast<PVOID>(&Packet.Data); }
    PVOID GetHeader() override { return static_cast<PVOID>(&Packet.Header); }
    ULONG GetSize() const override { return sizeof(Packet); }
    
    VOID SetData(const T& Data) { Packet.Data = Data; }
    VOID SetReplyStatus(NTSTATUS Status) { Packet.Header.Status = Status; }
    VOID SetMessageId(ULONGLONG MessageId) { Packet.Header.MessageId = MessageId; }
};

class CommPort {
private:
    HANDLE hPort;
    BOOL Connected;
public:
    CommPort();
    ~CommPort();

    HRESULT Connect(LPCWSTR PortName, PVOID Context, WORD SizeOfContext);
    VOID Disconnect();

    HRESULT Send(
        IN PVOID Input, 
        DWORD InputSize, 
        OUT PVOID Output, 
        DWORD OutputSize, 
        OUT OPTIONAL PULONG ReturnLength = NULL
    );
    HRESULT Recv(_Out_ CommPortPacket& ReceivedMessage);
    HRESULT Reply(_In_ CommPortPacket& ReplyMessage);
};