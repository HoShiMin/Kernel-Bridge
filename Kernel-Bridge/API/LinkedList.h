#pragma once

template <typename T>
class LinkedList {
public:
    using _Entry = struct {
        LIST_ENTRY Entry;
        T Value;
    };
private:
    EResource Lock;
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) KSPIN_LOCK SpinLock;
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) LIST_ENTRY Head;

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
        ForEachExclusive([](T& Value) -> ExclusiveAction { 
            UNREFERENCED_PARAMETER(Value);
            return exRemoveContinue;
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

    _Entry* InsertTail(const T& Value) {
        Lock.LockExclusive();
        auto Entry = AllocEntry(Value);
        InsertTailList(&Head, &Entry->Entry);
        Lock.Unlock();
        return Entry;
    }

    _Entry* InsertHead(const T& Value) {
        Lock.LockExclusive();
        auto Entry = AllocEntry(Value);
        InsertTailList(&Head, &Entry->Entry);
        Lock.Unlock();
        return Entry;
    }

    void Remove(_Entry* Entry) {
        Lock.LockExclusive();
        RemoveEntryList(&Entry->Entry);
        VirtualMemory::FreePoolMemory(Entry);
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



    enum SharedAction {
        shContinue,
        shBreak
    };

    using _SharedCallback = SharedAction(*)(const T& Value);
    void ForEachShared(_SharedCallback Callback) {
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
            case shContinue: continue;
            case shBreak: break;
            }
        } while (Entry->Entry.Flink != Entry->Entry.Blink);

        Lock.Unlock();
    }

    enum ExclusiveAction {
        exContinue,
        exBreak,
        exRemoveContinue,
        exRemoveBreak
    };

    using _ExclusiveCallback = ExclusiveAction(*)(T& Value);
    void ForEachExclusive(_ExclusiveCallback Callback) {
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
            case exContinue: continue;
            case exBreak: break;
            case exRemoveContinue: {
                RemoveEntryList(&Entry->Entry);
                VirtualMemory::FreePoolMemory(Entry);
                continue;
            }
            case exRemoveBreak: {
                RemoveEntryList(&Entry->Entry);
                VirtualMemory::FreePoolMemory(Entry);
                break;            
            }
            }
        } while (Entry->Entry.Flink != Entry->Entry.Blink);

        Lock.Unlock();
    }
};