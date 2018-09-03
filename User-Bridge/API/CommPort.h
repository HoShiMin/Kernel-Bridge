#pragma once

class CommPortPackage {
public:
    CommPortPackage() = default;
    ~CommPortPackage() = default;
    virtual PVOID GetHeader() const = 0;
    virtual PVOID GetData() const = 0;
    virtual ULONG GetSize() const = 0;
};

template <typename T>
class MessagePackage : public CommPortPackage {
private:
    struct {
        FILTER_MESSAGE_HEADER Header;
        T Data;
    } Package;
public:
    MessagePackage() : CommPortPackage(), Package({}) {}
    ~MessagePackage() {}

    PFILTER_MESSAGE_HEADER GetHeader() const override { return &Package.Header; }
    T* GetData() const override { return &Package.Data; }
    ULONG GetSize() const override { return sizeof(Package); }

    ULONG GetReplyLength() const { return Package.Header.ReplyLength; }
    ULONGLONG GetMessageId() const { return Package.Header.MessageId; }
};

template <typename T>
class ReplyPackage : public CommPortPackage {
private:
    struct {
        FILTER_REPLY_HEADER Header;
        T Data;
    } Package;
public:
    ReplyPackage() : CommPortPackage(), Package({}) {}
    ~ReplyPackage() {}
    
    T* GetData() const override { return &Package.Data; }
    PFILTER_REPLY_HEADER GetHeader() const override { return &Package.Header; }
    ULONG GetSize() const override { return sizeof(Package); }
    
    VOID SetReplyLength(NTSTATUS Status) { Package.Header.Status = Status; }
    VOID SetMessageId(ULONGLONG MessageId) { Package.Header.MessageId = MessageId; }
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
    HRESULT Recv(_Out_ CommPortPackage& ReceivedMessage);
    HRESULT Reply(const _In_ CommPortPackage& ReplyMessage);
};