#pragma once

/* 
  Depends on:
   - wdm.h
*/

template <typename T>
class LinkedList {
private:
    using _Entry = struct {
        LIST_ENTRY ChainEntry;
        PVOID EntryObject;
        T Value;
    };
public:
    class ListEntry {
    private:
        _Entry Entry;
    public:
        ListEntry(const T& Value) : Entry({}) {
            InitializeListHead(&Entry.ChainEntry);
            Entry.EntryObject = this;
            Entry.Value = Value;
        }

        ~ListEntry() = default;

        PLIST_ENTRY GetChainEntry() { return &Entry.ChainEntry; }
        T* GetValue() { return &Entry.Value; }
        ListEntry* GetInstance() { return static_cast<ListEntry*>(Entry.EntryObject); }
        _Entry* GetEntry() { return &Entry; }
    };

    class ListIterator {
    private:
        PLIST_ENTRY ListHead;
        _Entry* Current;
    public:
        ListIterator() : Current(NULL) {}
        ListIterator(PLIST_ENTRY Head, ListEntry* Entry) : ListHead(Head), Current(Entry->GetEntry()) {}
        ~ListIterator() = default;

        ListEntry* GetEntry() { return static_cast<ListEntry*>(Current->EntryObject); }

        ListIterator& operator ++ () {
            Current = Current->ChainEntry.Flink != ListHead
                ? reinterpret_cast<_Entry*>(Current->ChainEntry.Flink)
                : NULL;
            return *this;
        }

        ListIterator& operator -- () {
            Current = Current->ChainEntry.Flink != ListHead
                ? reinterpret_cast<_Entry*>(Current->ChainEntry.Blink)
                : NULL;
            return *this;
        }

        T& operator * () { return Current->Value; }

        bool operator == (const ListIterator& Iterator) const {
            return !Iterator.Current || !Current
                ? Iterator.Current == Current
                : Iterator.Current->EntryObject == Current->EntryObject;
        }

        bool operator != (const ListIterator& Iterator) const {
            return !Iterator.Current || !Current
                ? Iterator.Current != Current
                : Iterator.Current->EntryObject != Current->EntryObject;
        }
    };
private:
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) KSPIN_LOCK SpinLock;
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) LIST_ENTRY Head;

    ListIterator Finalizer;
public:
    LinkedList(const LinkedList&) = delete;
    LinkedList(LinkedList&&) = delete;
    LinkedList& operator = (const LinkedList&) = delete;
    LinkedList& operator = (LinkedList&&) = delete;

    LinkedList() : Head({}), Finalizer() {
        KeInitializeSpinLock(&SpinLock);
        InitializeListHead(&Head);
    }

    ~LinkedList() {
        Clear();
    }

    void Clear() {
        if (IsEmpty()) return;
        ListIterator it = begin();
        while (it != end()) {
            auto Entry = it.GetEntry();
            ++it;
            Remove(Entry);
        }
    }

    void InterlockedInsertTail(const T& Value) {
        auto Entry = new ListEntry(Value);
        ExInterlockedInsertTailList(&Head, Entry->GetChainEntry(), &SpinLock);
    }

    void InterlockedInsertHead(const T& Value) {
        auto Entry = new ListEntry(Value);
        ExInterlockedInsertHeadList(&Head, Entry->GetChainEntry(), &SpinLock);
    }

    void InterlockedRemoveHead() {
        auto Entry = ExInterlockedRemoveHeadList(&Head, &SpinLock);
        delete Entry;
    }

    ListEntry* InsertTail(const T& Value) {
        auto Entry = new ListEntry(Value);
        InsertTailList(&Head, Entry->GetChainEntry());
        return Entry;
    }

    ListEntry* InsertHead(const T& Value) {
        auto Entry = new ListEntry(Value);
        InsertTailList(&Head, Entry->GetChainEntry());
        return Entry;
    }

    void Remove(ListEntry* Entry) {
        RemoveEntryList(Entry->GetChainEntry());
        delete Entry->GetInstance();
    }

    void RemoveHead() {
        RemoveHeadList(&Head);
    }

    void RemoveTail() {
        RemoveTailList(&Head);
    }

    bool IsEmpty() const {
        return IsListEmpty(&Head);
    }

    ListIterator begin() {
        return ListIterator(&Head, static_cast<ListEntry*>((reinterpret_cast<_Entry*>(Head.Flink))->EntryObject));
    }

    ListIterator end() {
        return Finalizer;
    }
};