#pragma once

// Dependencies:
// - wdm.h (or fltKernel.h)

// ENTER_***_REGION are callable from IRQL <= APC_LEVEL

// Disables delivery of user and normal kernel APC's, 
// except special kernel APCs:
#define ENTER_CRITICAL_REGION() KeEnterCriticalRegion()
#define LEAVE_CRITICAL_REGION() KeLeaveCriticalRegion()

// Disables delivery of all APCs, including special kernel:
#define ENTER_GUARDED_REGION() KeEnterGuardedRegion()
#define LEAVE_GUARDED_REGION() KeLeaveGuardedRegion()

#define ALIGNED __declspec(align(MEMORY_ALLOCATION_ALIGNMENT))

// Lock() and Unlock() raises IRQL to APC_LEVEL and acquires the mutex,
// LockAtApc() and UnlockAtApc() not raises an IRQL and assumes that thread
// is already in APC_LEVEL or in critical region or in call of FsRtlEnterFileSystem.
// TryToAcquire() raises IRQL to APC_LEVEL if acquiring was successful.

class FastMutex final {
private:
    ALIGNED FAST_MUTEX Mutex;
public:
    FastMutex(const FastMutex&) = delete;
    FastMutex(FastMutex&&) = delete;
    FastMutex& operator = (const FastMutex&) = delete;
    FastMutex& operator = (FastMutex&&) = delete;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    FastMutex() : Mutex({}) {
        ExInitializeFastMutex(&Mutex);
    }

    ~FastMutex() = default;

    _IRQL_raises_(APC_LEVEL)
    _IRQL_saves_global_(OldIrql, Mutex)
    VOID Lock() {
        ExAcquireFastMutex(&Mutex);
    };

    _IRQL_requires_(APC_LEVEL)
    _IRQL_restores_global_(OldIrql, Mutex)
    VOID Unlock() {
        ExReleaseFastMutex(&Mutex);
    };

    _IRQL_requires_(APC_LEVEL)
    VOID LockAtApc() {
        ExAcquireFastMutexUnsafe(&Mutex);
    };

    _IRQL_requires_(APC_LEVEL)
    VOID UnlockFromApc() {
        ExReleaseFastMutexUnsafe(&Mutex);
    };

    _IRQL_raises_(APC_LEVEL)
    _IRQL_saves_global_(OldIrql, Mutex)
    BOOLEAN TryToAcquire() {
        return ExTryToAcquireFastMutex(&Mutex);
    }
};

class GuardedMutex final {
private:
    ALIGNED KGUARDED_MUTEX Mutex;
public:
    GuardedMutex(const GuardedMutex&) = delete;
    GuardedMutex(GuardedMutex&&) = delete;
    GuardedMutex& operator = (const GuardedMutex&) = delete;
    GuardedMutex& operator = (GuardedMutex&&) = delete;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    GuardedMutex() : Mutex({}) {
        KeInitializeGuardedMutex(&Mutex);
    }

    ~GuardedMutex() = default;
    
    _IRQL_requires_max_(APC_LEVEL)
    VOID Lock() {
        KeAcquireGuardedMutex(&Mutex);
    };

    _IRQL_requires_max_(APC_LEVEL)
    VOID Unlock() {
        KeReleaseGuardedMutex(&Mutex);
    };

    _IRQL_requires_(APC_LEVEL)
    VOID LockAtApc() {
        KeAcquireGuardedMutexUnsafe(&Mutex);
    };

    _IRQL_requires_(APC_LEVEL)
    VOID UnlockFromApc() {
        KeReleaseGuardedMutexUnsafe(&Mutex);
    };

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN TryToAcquire() {
        return KeTryToAcquireGuardedMutex(&Mutex);
    }
};


// SpinLock raises IRQL to DISPATCH_LEVEL and acquires a spinlock.
// If thread is already at DISPATCH_LEVEL, you can use LockAtDpc()/UnlockFromDpc():
class SpinLock final {
private:
    ALIGNED KSPIN_LOCK Spinlock;
    KLOCK_QUEUE_HANDLE LockHandle;
public:
    SpinLock(const SpinLock&) = delete;
    SpinLock(SpinLock&&) = delete;
    SpinLock& operator = (const SpinLock&) = delete;
    SpinLock& operator = (SpinLock&&) = delete;

    SpinLock() : Spinlock(0), LockHandle({}) {
        KeInitializeSpinLock(&Spinlock);
    }

    ~SpinLock() = default;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _IRQL_saves_global_(QueuedSpinLock,LockHandle)
    _IRQL_raises_(DISPATCH_LEVEL)
    VOID Lock() {
        KeAcquireInStackQueuedSpinLock(&Spinlock, &LockHandle);
    }

    _IRQL_requires_(DISPATCH_LEVEL)
    _IRQL_restores_global_(QueuedSpinLock,LockHandle)
    VOID Unlock() {
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }

    _IRQL_requires_(DISPATCH_LEVEL)
    VOID LockAtDpc() {
        KeAcquireInStackQueuedSpinLockAtDpcLevel(&Spinlock, &LockHandle);
    }

    _IRQL_requires_(DISPATCH_LEVEL)
    VOID UnlockFromDpc() {
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle);
    }
};


class EResource {
private:
    ERESOURCE Resource;
public:
    EResource(const EResource&) = delete;
    EResource(EResource&&) = delete;
    EResource& operator = (const EResource&) = delete;
    EResource& operator = (EResource&&) = delete;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    EResource() : Resource({}) {
        ExInitializeResourceLite(&Resource);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    NTSTATUS Reinitialize() {
        return ExReinitializeResourceLite(&Resource);
    }

    _IRQL_requires_max_(APC_LEVEL)
    ~EResource() {
        ExDeleteResourceLite(&Resource);
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN LockShared(BOOLEAN Wait = TRUE) {
        ENTER_CRITICAL_REGION();
        return ExAcquireResourceSharedLite(&Resource, Wait);
    }

    _IRQL_requires_max_(APC_LEVEL)
    BOOLEAN LockExclusive(BOOLEAN Wait = TRUE) {
        ENTER_CRITICAL_REGION();
        return ExAcquireResourceExclusiveLite(&Resource, Wait);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    VOID Unlock() {
        ExReleaseResourceLite(&Resource);
        LEAVE_CRITICAL_REGION();
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    ULONG GetOwnersCount() {
        return ExIsResourceAcquiredLite(&Resource);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    ULONG GetSharedOwnersCount() {
        return ExIsResourceAcquiredSharedLite(&Resource);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsAcquired() {
        return static_cast<BOOLEAN>(GetOwnersCount() > 0);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsAcquiredShared() {
        return static_cast<BOOLEAN>(GetSharedOwnersCount() > 0);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsAcquiredExclusive() {
        return ExIsResourceAcquiredExclusiveLite(&Resource);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    ULONG GetSharedWaiters() {
        return ExGetSharedWaiterCount(&Resource);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    ULONG GetExclusiveWaiters() {
        return ExGetExclusiveWaiterCount(&Resource);
    }

    // Converts exclusive lock to shared if current thread locked
    // ERESOURCE with exclusive access:
    _IRQL_requires_max_(APC_LEVEL)
    VOID ConvertExclusiveToShared() {
        ExConvertExclusiveToSharedLite(&Resource);
    }
};

class Atomic32 final {
private:
    volatile ALIGNED LONG AtomicValue;
public:
    Atomic32() : AtomicValue(0) {};
    explicit Atomic32(LONG InitialValue) : AtomicValue(InitialValue) {}
    ~Atomic32() = default;

    LONG Equals(LONG Value) { return Get() == Value; }

    LONG Get() { return InterlockedCompareExchange(&AtomicValue, 0, 0); }
    LONG Set(LONG Value) { return InterlockedExchange(&AtomicValue, Value); }
    LONG Add(LONG Value) { return InterlockedAdd(&AtomicValue, Value); }
    LONG Inc() { return InterlockedIncrement(&AtomicValue); }
    LONG Dec() { return InterlockedDecrement(&AtomicValue); }
    
    LONG And(LONG Value) { return InterlockedAnd(&AtomicValue, Value); }
    LONG Or(LONG Value) { return InterlockedOr(&AtomicValue, Value); }
    LONG Xor(LONG Value) { return InterlockedXor(&AtomicValue, Value); }

    // if (Atomic == Comperand) Atomic = Value:
    LONG CompareExchange(LONG Comperand, LONG Value) { return InterlockedCompareExchange(&AtomicValue, Value, Comperand); }

    // Returns a previous value of specified bit position:
    BOOLEAN BitTestAndSet(LONG Offset) { return InterlockedBitTestAndSet(&AtomicValue, Offset); }
    BOOLEAN BitTestAndReset(LONG Offset) { return InterlockedBitTestAndReset(&AtomicValue, Offset); }

    Atomic32& operator = (LONG Value) { Set(Value); return *this; }
    Atomic32& operator + (LONG Value) { Add(Value); return *this; }
    Atomic32& operator - (LONG Value) { Add(-Value); return *this; }
    Atomic32& operator ++ (int) { Inc(); return *this; }
    Atomic32& operator -- (int) { Dec(); return *this; }
    bool operator == (LONG Value) { return Equals(Value); }
    bool operator != (LONG Value) { return !Equals(Value); }
    bool operator > (LONG Value) { return Get() > Value; }
    bool operator < (LONG Value) { return Get() < Value; }
    bool operator >= (LONG Value) { return Get() >= Value; }
    bool operator <= (LONG Value) { return Get() <= Value; }
    Atomic32& operator &= (LONG Value) { And(Value); return *this; }
    Atomic32& operator |= (LONG Value) { Or(Value); return *this; }
    Atomic32& operator ^= (LONG Value) { Xor(Value); return *this; }
    operator LONG() { return Get(); }
};

class Atomic64 final {
private:
    volatile ALIGNED LONG64 AtomicValue;
public:
    Atomic64() : AtomicValue(0) {}
    explicit Atomic64(LONG64 InitialValue) : AtomicValue(InitialValue) {}
    ~Atomic64() = default;

    LONG64 Equals(LONG64 Value) { return Get() == Value; } 

    LONG64 Get() { return InterlockedCompareExchange64(&AtomicValue, 0, 0); }
    LONG64 Set(LONG64 Value) { return InterlockedExchange64(&AtomicValue, Value); }
    LONG64 Add(LONG64 Value) { return InterlockedAdd64(&AtomicValue, Value); }
    LONG64 Inc() { return InterlockedIncrement64(&AtomicValue); }
    LONG64 Dec() { return InterlockedDecrement64(&AtomicValue); }

    LONG64 And(LONG64 Value) { return InterlockedAnd64(&AtomicValue, Value); }
    LONG64 Or(LONG64 Value) { return InterlockedOr64(&AtomicValue, Value); }
    LONG64 Xor(LONG64 Value) { return InterlockedXor64(&AtomicValue, Value); }

    // if (Atomic == Comperand) Atomic = Value:
    LONG64 CompareExchange(LONG64 Comperand, LONG64 Value) { return InterlockedCompareExchange64(&AtomicValue, Value, Comperand); }

#ifdef _AMD64_
    // Returns a previous value of specified bit position:
    BOOLEAN BitTestAndSet(LONG64 Offset) { return InterlockedBitTestAndSet64(&AtomicValue, Offset); }
    BOOLEAN BitTestAndReset(LONG64 Offset) { return InterlockedBitTestAndReset64(&AtomicValue, Offset); }
#endif

    Atomic64& operator = (LONG64 Value) { Set(Value); return *this; }
    Atomic64& operator + (LONG64 Value) { Add(Value); return *this; }
    Atomic64& operator - (LONG64 Value) { Add(-Value); return *this; }
    Atomic64& operator ++ (int) { Inc(); return *this; }
    Atomic64& operator -- (int) { Dec(); return *this; }
    bool operator == (LONG64 Value) { return Equals(Value); }
    bool operator != (LONG64 Value) { return !Equals(Value); }
    bool operator > (LONG64 Value) { return Get() > Value; }
    bool operator < (LONG64 Value) { return Get() < Value; }
    bool operator >= (LONG64 Value) { return Get() >= Value; }
    bool operator <= (LONG64 Value) { return Get() <= Value; }
    Atomic64& operator &= (LONG64 Value) { And(Value); return *this; }
    Atomic64& operator |= (LONG64 Value) { Or(Value); return *this; }
    Atomic64& operator ^= (LONG64 Value) { Xor(Value); return *this; }
    operator LONG64() { return Get(); }
};

class AtomicPointer final {
private:
    volatile ALIGNED PVOID AtomicValue;
public:
    AtomicPointer(const AtomicPointer&) = delete;
    AtomicPointer(AtomicPointer&&) = delete;
    AtomicPointer& operator = (const AtomicPointer&) = delete;
    AtomicPointer& operator = (AtomicPointer&&) = delete;

    explicit AtomicPointer(PVOID InitialValue = NULL) : AtomicValue(InitialValue) {}
    ~AtomicPointer() = default;

    BOOLEAN Equals(PVOID Value) { return Get() == Value; }

    PVOID Get() { return InterlockedCompareExchangePointer(&AtomicValue, 0, 0); }
    PVOID Set(PVOID Value) { return InterlockedExchangePointer(&AtomicValue, Value); }

    AtomicPointer& operator = (PVOID Value) { Set(Value); return *this; }
    BOOLEAN operator == (PVOID Value) { return Equals(Value); }
    BOOLEAN operator != (PVOID Value) { return !Equals(Value); }
    operator PVOID() { return Get(); }
};

// Pass FastMutex or GuardedMutex to this template:
template <class T>
class CriticalSection final {
private:
    T Mutex;
    AtomicPointer Owner;
    Atomic64 LocksCount;
public:
    CriticalSection(const CriticalSection&) = delete;
    CriticalSection(CriticalSection&&) = delete;
    CriticalSection& operator = (const CriticalSection&) = delete;
    CriticalSection& operator = (CriticalSection&&) = delete;

    CriticalSection() : Owner(NULL), LocksCount(0) {}
    ~CriticalSection() = default;

    _IRQL_raises_(APC_LEVEL)
    _IRQL_saves_global_(OldIrql, Mutex)
    void Enter() {
        PETHREAD CurrentThread = PsGetCurrentThread();
        if (Owner == CurrentThread) {
            LocksCount++;
            return;
        }
        Mutex.Lock();
        Owner = CurrentThread;
        LocksCount = 1;
    }

    _IRQL_requires_(APC_LEVEL)
    _IRQL_restores_global_(OldIrql, Mutex)
    void Leave() {
        LONG64 Locks = LocksCount;
        if (Locks == 0) return;
        if (Locks == 1) {
            LocksCount = 0;
            Owner = NULL;
            Mutex.Unlock();
        } else {
            LocksCount--;
        }
    }
};

using FastCriticalSection = CriticalSection<FastMutex>;
using GuardedCriticalSection = CriticalSection<GuardedMutex>;

class SpinCriticalSection final {
private:
    SpinLock SpinMutex;
    AtomicPointer Owner;
    Atomic64 LocksCount;
public:
    SpinCriticalSection(const SpinCriticalSection&) = delete;
    SpinCriticalSection(SpinCriticalSection&&) = delete;
    SpinCriticalSection& operator = (const SpinCriticalSection&) = delete;
    SpinCriticalSection& operator = (SpinCriticalSection&&) = delete;

    SpinCriticalSection() : Owner(NULL), LocksCount(0) {}
    ~SpinCriticalSection() = default;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _IRQL_raises_(DISPATCH_LEVEL)
    _IRQL_saves_global_(QueuedSpinLock,SpinMutex)
    void Enter() {
        PETHREAD CurrentThread = PsGetCurrentThread();
        if (Owner == CurrentThread) {
            LocksCount++;
            return;
        }
        SpinMutex.Lock();
        Owner = CurrentThread;
        LocksCount = 1;
    }

    _IRQL_requires_(DISPATCH_LEVEL)
    _IRQL_restores_global_(QueuedSpinLock,SpinMutex)
    void Leave() {
        LONG64 Locks = LocksCount;
        if (Locks == 0) return;
        if (Locks == 1) {
            LocksCount = 0;
            Owner = NULL;
            SpinMutex.Unlock();
        } else {
            LocksCount--;
        }
    }
};