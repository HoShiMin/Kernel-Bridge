#include "pch.h"

#include "WdkTypes.h"
#include "CtlTypes.h"
#include "User-Bridge.h"

#include "Kernel-Tests.h"

#include <intrin.h>

bool BeeperTest::RunTest() {
    using namespace IO::Beeper;
    KbSetBeeperRegime();
    KbSetBeeperFrequency(1000);
    KbStartBeeper();
    Sleep(500);
    KbStopBeeper();
    return true;
}

bool IoplTest::RunTest() {
    using namespace IO::Iopl;

    bool Status = false;
    BOOL RaisingStatus = KbRaiseIopl();
    if (!RaisingStatus) return false;
    __try {
        __outbyte(0x43, 0xB6); // Set beeper regime
        Status = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = false;
    }
    return KbResetIopl();
}

bool VirtualMemoryTest::RunTest() {
    using namespace VirtualMemory;

    constexpr int Size = 1048576;
    WdkTypes::PVOID Address;
    BOOL Status = KbAllocKernelMemory(Size, TRUE, &Address);
    if (!Status) Log(L"KbAllocKernelMemory == FALSE");
    if (!Address) { 
        Log(L"Address == NULL");
        return FALSE;
    }

    bool TestStatus = false;

    PVOID UserMemory = NULL;
    __try {
        UserMemory = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Status = KbFillMemory(reinterpret_cast<WdkTypes::PVOID>(UserMemory), 0x90, Size);
        if (!Status) Log(L"KbFillMemory == FALSE");

        Status = KbCopyMoveMemory(Address, reinterpret_cast<WdkTypes::PVOID>(UserMemory), Size, FALSE);
        if (!Status) Log(L"KbCopyMoveMemory == FALSE");

        BOOLEAN Equals = FALSE;
        Status = KbEqualMemory(reinterpret_cast<WdkTypes::PVOID>(UserMemory), Address, Size, &Equals);
        if (!Status) Log(L"KbEqualMemory == FALSE");

        TestStatus = KbFreeKernelMemory(Address);
        if (!TestStatus) Log(L"KbFreeKernelMemory == FALSE");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TestStatus = false;
    }

    if (UserMemory) VirtualFree(UserMemory, 0, MEM_RELEASE);

    return TestStatus;
}

bool MdlTest::RunTest() {
    using namespace Mdl;

    constexpr int Size = 1048576;
    PVOID Buffer = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    bool TestStatus = false;

    Mdl::MAPPING_INFO MappingInfo = {};
    BOOL Status = KbMapMemory(&MappingInfo, 0, 0, reinterpret_cast<WdkTypes::PVOID>(Buffer), Size);
    if (!Status) Log(L"KbMapMemory == FALSE");

    if (!Status || !MappingInfo.MappedAddress || !MappingInfo.Mdl) {
        VirtualFree(Buffer, 0, MEM_RELEASE);
        return false;
    }

    PVOID Mapped = reinterpret_cast<PVOID>(MappingInfo.MappedAddress);

    BOOL Equals = FALSE;
    __try {
        FillMemory(Mapped, Size, 0xC6);
        Equals = !memcmp(Buffer, Mapped, Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log(L"Filling and comparing failure!");
        Equals = FALSE;
    }

    if (!KbUnmapMemory(&MappingInfo)) Log(L"KbUnmapMemory == FALSE");
    VirtualFree(Buffer, 0, MEM_RELEASE);

    return Equals;
}

bool PhysicalMemoryTest::RunTest() {
    using namespace PhysicalMemory;
    using namespace Mdl;

    UINT64 Value = 0x1EE7C0DEC0FFEE;
    VirtualLock(&Value, sizeof(Value));

    bool TestStatus = false;

    __try {
        WdkTypes::PVOID PhysicalAddress = NULL;
        BOOL Status = KbGetPhysicalAddress(NULL, reinterpret_cast<WdkTypes::PVOID>(&Value), &PhysicalAddress);
        if (!Status) Log(L"KbGetPhysicalAddress == FALSE");
        if (!PhysicalAddress) {
            VirtualUnlock(&Value, sizeof(Value));
            return FALSE;
        }

        WdkTypes::PVOID VirtualAddress = NULL;
        Status = KbMapPhysicalMemory(PhysicalAddress, sizeof(Value), WdkTypes::MmNonCached, &VirtualAddress);
        if (!Status) Log(L"KbMapPhysicalMemory == FALSE");

        Mdl::MAPPING_INFO MappingInfo = {};
        KbMapMemory(&MappingInfo, 0, 0, VirtualAddress, sizeof(Value));

        PUINT64 Mapping = reinterpret_cast<PUINT64>(MappingInfo.MappedAddress);

        if (*Mapping != Value) {
            Log(L"*Mapping != Value");
            VirtualUnlock(&Value, sizeof(Value));
            return FALSE;                
        }

        *Mapping = 0xC0FFEE;
        if (Value != 0xC0FFEE) Log(L"Value != 0xC0FFEE");

        KbUnmapMemory(&MappingInfo);

        UINT64 Buffer = 0;
        Status = KbReadPhysicalMemory(PhysicalAddress, &Buffer, sizeof(Buffer), WdkTypes::MmNonCached);
        if (!Status) Log(L"KbReadPhysicalMemory == FALSE");

        if (Buffer != Value) Log(L"Buffer != Value");

        Buffer = 0x900DDA7E;
        Status = KbWritePhysicalMemory(PhysicalAddress, &Buffer, sizeof(Buffer), WdkTypes::MmNonCached);
        if (!Status) Log(L"KbWritePhysicalMemory == FALSE");

        if (Value != Buffer) Log(L"Value != Buffer 0x900DDA7E");

        TestStatus = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log(L"Something goes wrong");
    }

    VirtualUnlock(&Value, sizeof(Value));
    return TestStatus;
}

bool ProcessesTest::RunTest() {
        
    using namespace Processes;
    using namespace Descriptors;
    using namespace Threads;
    using namespace MemoryManagement;
    using namespace Apc;

    BOOL TestStatus = true;

    ULONG ProcessId = GetCurrentProcessId();
    ULONG ThreadId = GetCurrentThreadId();

    BOOL Status = FALSE;

    WdkTypes::PEPROCESS Process = NULL;
    TestStatus &= Status = KbGetEprocess(ProcessId, &Process);
    if (!Process) Log(L"Process == NULL");

    WdkTypes::PETHREAD Thread = NULL;
    TestStatus &= Status = KbGetEthread(ThreadId, &Thread);
    if (!Process) Log(L"Thread == NULL");

    KbDereferenceObject(Process);
    KbDereferenceObject(Thread);

    WdkTypes::HANDLE hProcess = NULL;
    TestStatus &= Status = KbOpenProcess(ProcessId, &hProcess);
    if (!Status) Log(L"KbOpenProcess == FALSE");

    KbCloseHandle(hProcess);

    constexpr int Size = 1048576;
    WdkTypes::PVOID Buffer = NULL;
    TestStatus &= Status = KbAllocUserMemory(ProcessId, PAGE_READWRITE, Size, &Buffer);
    if (!Status) Log(L"KbAllocUserMemory == FALSE");

    if (Status) {
        PVOID uBuffer = reinterpret_cast<PVOID>(Buffer);
        FillMemory(uBuffer, Size, 0x90);

        UINT64 Data = 0;
        TestStatus &= Status = KbReadProcessMemory(ProcessId, Buffer, &Data, sizeof(Data));
        if (!Status) Log(L"KbReadProcessMemory == FALSE");
        if (Data != 0x9090909090909090) Log(L"Data != 0x9090909090909090");

        Data = 0x1122334455667788;
        TestStatus &= Status = KbWriteProcessMemory(ProcessId, Buffer, &Data, sizeof(Data));
        if (!Status) Log(L"KbWriteProcessMemory == FALSE");
        Data = 0;
        TestStatus &= Status = KbReadProcessMemory(ProcessId, Buffer, &Data, sizeof(Data));
        if (!Status) Log(L"KbReadProcessMemory == FALSE");
        if (Data != 0x1122334455667788) Log(L"Data != 0x1122334455667788");

        TestStatus &= Status = KbFreeUserMemory(ProcessId, Buffer);
        if (!Status) Log(L"KbFreeUserMemory == FALSE");
    }

    _ApcProc Apc = [](PVOID Arg) -> VOID {
        std::cout << " > Called from APC: " << Arg << std::endl;
    };

    TestStatus &= KbQueueUserApc(
        ThreadId, 
        reinterpret_cast<WdkTypes::PVOID>(Apc),
        static_cast<WdkTypes::PVOID>(0x12345)
    );

    return static_cast<bool>(TestStatus);
}

bool ShellTest::RunTest() {
    using namespace KernelShells;
    ULONG Result = 1337;
    KbExecuteShellCode(
        [](KernelShells::_GetKernelProcAddress GetKernelProcAddress, PVOID Argument) -> ULONG {
            ULONG Value = *static_cast<PULONG>(Argument);
            using _KeStallExecutionProcessor = VOID(WINAPI*)(ULONG Microseconds);
            auto Stall = reinterpret_cast<_KeStallExecutionProcessor>(GetKernelProcAddress(L"KeStallExecutionProcessor"));
            Stall(1);
            return Value == 1337 ? 10 : 0;
        },
        &Result,
        &Result
    );
    return Result == 10;
}

bool StuffTest::RunTest() {
    using namespace Stuff;

    BOOL TestStatus = TRUE;
    BOOL Status = FALSE;

    WdkTypes::PVOID KernelAddress = NULL;
    TestStatus &= Status = KbGetKernelProcAddress(L"KeStallExecutionProcessor", &KernelAddress);
    if (!Status) Log(L"KbGetKernelProcAddress == FALSE");
    if (!KernelAddress) Log(L"KernelAddress == NULL");

    return static_cast<bool>(Status);
}