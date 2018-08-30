#pragma once

template <typename T>
class LinkedList {
private:
    EResource Lock;
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) KSPIN_LOCK SpinLock;
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) LIST_ENTRY Head;
    using _Entry = struct {
        LIST_ENTRY Entry;
        T Value;
    };
    _Entry* AllocEntry(const T& Value) const {
        auto Entry = static_cast<_Entry*>(VirtualMemory::AllocFromPool(sizeof(_Entry)));
        InitializeListHead(&Entry->Entry);
        Entry->Value = Value;
        return Entry;
    }
public:
    LinkedList() : Head({}) {
        KeInitializeSpinLock(&SpinLock);
        InitializeListHead(&Head);
    }

    ~LinkedList() {
        ForEachWriteRemove([](T& Value) -> WriteRemoveAction { 
            UNREFERENCED_PARAMETER(Value);
            return wrRemoveContinue;
        });
    }

    void InterlockedInsertTail(const T& Value) {
        Lock.LockExclusive();
        auto Entry = static_cast<_Entry*>(VirtualMemory::AllocFromPool(sizeof(_Entry)));
        InitializeListHead(&Entry->Entry);
        Entry->Value = Value;
        ExInterlockedInsertTailList(&Head, &Entry->Entry, &SpinLock);
        Lock.Unlock();
    }

    void InterlockedInsertHead(const T& Value) {
        Lock.LockExclusive();
        auto Entry = AllocEntry(Value);
        ExInterlockedInsertHeadList(&Head, &Entry->Entry, &SpinLock);
        Lock.Unlock();
    }

    void InterlockedRemoveHead() {
        Lock.LockExclusive();
        auto Entry = ExInterlockedRemoveHeadList(&Head, &SpinLock);
        VirtualMemory::FreePoolMemory(Entry);
        Lock.Unlock();
    }

    void InsertTail(const T& Value) {
        Lock.LockExclusive();
        auto Entry = AllocEntry(Value);
        InsertTailList(&Head, &Entry->Entry);
        Lock.Unlock();
    }

    void InsertHead(const T& Value) {
        Lock.LockExclusive();
        auto Entry = AllocEntry(Value);
        InsertTailList(&Head, &Entry->Entry);
        Lock.Unlock();
    }

    void RemoveHead() {
        Lock.LockExclusive();
        RemoveHeadList(&Head);
        Lock.Unlock();
    }

    void RemoveTail() {
        Lock.LockExclusive();
        RemoveTailList(&Head);
        Lock.Unlock();
    }

    enum ReadAction {
        rdContinue,
        rdBreak
    };

    using _ReadCallback = ReadAction(*)(const T& Value);
    void ForEachRead(_ReadCallback Callback) {
        if (!Callback) return;

        Lock.LockShared();
        if (IsListEmpty(&Head)) { 
            Lock.Unlock();
            return;
        }

        auto Entry = reinterpret_cast<_Entry*>(Head.Flink);
        do {
            auto Action = Callback(Entry->Value);
            switch (Action) {
            case rdContinue: continue;
            case rdBreak: break;
            }
        } while (Entry->Entry.Flink != Entry->Entry.Blink);

        Lock.Unlock();
    }

    enum WriteRemoveAction {
        wrContinue,
        wrBreak,
        wrRemoveContinue,
        wrRemoveBreak
    };

    using _WriteRemoveCallback = WriteRemoveAction(*)(T& Value);
    void ForEachWriteRemove(_WriteRemoveCallback Callback) {
        if (!Callback) return;

        Lock.LockExclusive();
        if (IsListEmpty(&Head)) { 
            Lock.Unlock();
            return;
        }

        auto Entry = reinterpret_cast<_Entry*>(Head.Flink);
        if (&Entry->Entry != &Head) do {
            auto Action = Callback(Entry->Value);
            switch (Action) {
            case wrContinue: continue;
            case wrBreak: break;
            case wrRemoveContinue: {
                RemoveEntryList(&Entry->Entry);
                VirtualMemory::FreePoolMemory(Entry);
                continue;
            }
            case wrRemoveBreak: {
                RemoveEntryList(&Entry->Entry);
                VirtualMemory::FreePoolMemory(Entry);
                break;            
            }
            }
        } while (Entry->Entry.Flink != Entry->Entry.Blink);

        Lock.Unlock();
    }
};