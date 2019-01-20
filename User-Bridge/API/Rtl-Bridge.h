#pragma once

/*
    Depends on:
    - Windows.h
    - WdkTypes.h
    - CtlTypes.h
    - User-Bridge.h
*/

namespace KbRtl {
    enum KbLdrStatus {
        KbLdrSuccess,
        KbLdrImportNotResolved,
        KbLdrOrdinalImportNotSupported,
        KbLdrKernelMemoryNotAllocated,
        KbLdrTransitionFailure,
        KbLdrCreationFailure
    };

    // 'DriverImage' is a raw *.sys file data
    // 'DriverName' is a system name of driver in format L"\\Driver\\YourDriverName"
    KbLdrStatus WINAPI KbRtlMapDriverMemory(PVOID DriverImage, LPCWSTR DriverName);
    KbLdrStatus WINAPI KbRtlMapDriverFile(LPCWSTR DriverPath, LPCWSTR DriverName);

    // 'ModuleImage' is a raw *.sys file data
    // 'ModuleName' is a custom unique name for the loadable module
    KbLdrStatus WINAPI KbRtlLoadModuleMemory(PVOID ModuleImage, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);
    KbLdrStatus WINAPI KbRtlLoadModuleFile(LPCWSTR ModulePath, LPCWSTR ModuleName, OUT WdkTypes::HMODULE* hModule);

    class PhysMem {
    public:
        static VOID Read(WdkTypes::PVOID Address, OUT PVOID Buffer, ULONG Size, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            if (!PhysicalMemory::KbReadPhysicalMemory(Address, Buffer, Size, CachingType))
                throw GetLastError();
        }

        static VOID Write(WdkTypes::PVOID Address, IN PVOID Buffer, ULONG Size, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            if (!PhysicalMemory::KbWritePhysicalMemory(Address, Buffer, Size, CachingType))
                throw GetLastError();
        }

        static BYTE ReadByte(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            BYTE Buffer = 0;
            Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
            return Buffer;
        }

        static WORD ReadWord(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            WORD Buffer = 0;
            Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
            return Buffer;
        }

        static DWORD ReadDword(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            DWORD Buffer = 0;
            Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
            return Buffer;
        }

        static DWORD64 ReadQword(WdkTypes::PVOID PhysicalAddress, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            DWORD64 Buffer = 0;
            Read(PhysicalAddress, &Buffer, sizeof(Buffer), CachingType);
            return Buffer;
        }

        static VOID WriteByte(WdkTypes::PVOID PhysicalAddress, BYTE Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
        }

        static VOID WriteWord(WdkTypes::PVOID PhysicalAddress, WORD Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
        }

        static VOID WriteDword(WdkTypes::PVOID PhysicalAddress, DWORD Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
        }

        static VOID WriteQword(WdkTypes::PVOID PhysicalAddress, DWORD64 Value, WdkTypes::MEMORY_CACHING_TYPE CachingType) {
            Write(PhysicalAddress, &Value, sizeof(Value), CachingType);
        }

        static WdkTypes::PVOID GetPhysAddress(WdkTypes::PVOID Address) {
            WdkTypes::PVOID PA = NULL;
            if (!PhysicalMemory::KbGetPhysicalAddress(NULL, Address, &PA))
                throw GetLastError();
            return PA;
        }

        static WdkTypes::PVOID GetVirtualForPhysical(WdkTypes::PVOID PhysicalAddress) {
            WdkTypes::PVOID VirtualAddress = NULL;
            PhysicalMemory::KbGetVirtualForPhysical(PhysicalAddress, &VirtualAddress);
            return VirtualAddress;
        }
    };

    class VirtMem {
    public:
        static VOID Read(WdkTypes::PVOID Dest, WdkTypes::PVOID Src, ULONG Size) {
            if (!VirtualMemory::KbCopyMoveMemory(Dest, Src, Size, FALSE))
                throw GetLastError();
        }

        static VOID Write(WdkTypes::PVOID Dest, WdkTypes::PVOID Src, ULONG Size) {
            if (!VirtualMemory::KbCopyMoveMemory(Dest, Src, Size, FALSE))
                throw GetLastError();
        }

        static BYTE ReadByte(WdkTypes::PVOID VirtualAddress) {
            BYTE Buffer = 0;
            Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        static WORD ReadWord(WdkTypes::PVOID VirtualAddress) {
            WORD Buffer = 0;
            Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        static DWORD ReadDword(WdkTypes::PVOID VirtualAddress) {
            DWORD Buffer = 0;
            Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        static DWORD64 ReadQword(WdkTypes::PVOID VirtualAddress) {
            DWORD64 Buffer = 0;
            Read(reinterpret_cast<WdkTypes::PVOID>(&Buffer), VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        static VOID WriteByte(WdkTypes::PVOID VirtualAddress, BYTE Value) {
            Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
        }

        static VOID WriteWord(WdkTypes::PVOID VirtualAddress, WORD Value) {
            Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
        }

        static VOID WriteDword(WdkTypes::PVOID VirtualAddress, DWORD Value) {
            Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
        }

        static VOID WriteQword(WdkTypes::PVOID VirtualAddress, DWORD64 Value) {
            Write(VirtualAddress, reinterpret_cast<WdkTypes::PVOID>(&Value), sizeof(Value));
        }
    };

    class ProcMem {
        ULONG Pid;
    public:
        ProcMem(ULONG ProcessId) : Pid(ProcessId) {}
        
        VOID Attach(ULONG ProcessId) {
            Pid = ProcessId;
        }

        static WdkTypes::PVOID Alloc(ULONG ProcessId, ULONG Size, ULONG Protect = PAGE_EXECUTE_READWRITE) {
            WdkTypes::PVOID BaseAddress = NULL;
            if (!Processes::MemoryManagement::KbAllocUserMemory(ProcessId, Protect, Size, &BaseAddress))
                throw GetLastError();
            return BaseAddress;
        }

        WdkTypes::PVOID Alloc(ULONG Size, ULONG Protect = PAGE_EXECUTE_READWRITE) {
            return Alloc(Pid, Size, Protect);
        }

        static VOID Free(ULONG ProcessId, WdkTypes::PVOID BaseAddress) {
            if (Processes::MemoryManagement::KbFreeUserMemory(ProcessId, BaseAddress))
                throw GetLastError();
        }

        VOID Free(WdkTypes::PVOID BaseAddress) {
            Free(Pid, BaseAddress);
        }

        static VOID Read(ULONG ProcessId, PVOID Dest, WdkTypes::PVOID Src, ULONG Size) {
            if (!Processes::MemoryManagement::KbReadProcessMemory(ProcessId, Src, Dest, Size))
                throw GetLastError();
        }

        VOID Read(PVOID Dest, WdkTypes::PVOID Src, ULONG Size) const {
            Read(Pid, Dest, Src, Size);
        }

        static VOID Write(ULONG ProcessId, WdkTypes::PVOID Dest, PVOID Src, ULONG Size, BOOLEAN PerformCopyOnWrite = TRUE) {
            if (!Processes::MemoryManagement::KbWriteProcessMemory(ProcessId, Dest, Src, Size, PerformCopyOnWrite))
                throw GetLastError();
        }

        VOID Write(WdkTypes::PVOID Dest, PVOID Src, ULONG Size, BOOLEAN PerformCopyOnWrite = TRUE) {
            Write(Pid, Dest, Src, Size, PerformCopyOnWrite);
        }

        static BYTE ReadByte(ULONG ProcessId, WdkTypes::PVOID VirtualAddress) {
            BYTE Buffer = 0;
            Read(ProcessId, &Buffer, VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        BYTE ReadByte(WdkTypes::PVOID VirtualAddress) const {
            return ReadByte(Pid, VirtualAddress);
        }

        static WORD ReadWord(ULONG ProcessId, WdkTypes::PVOID VirtualAddress) {
            WORD Buffer = 0;
            Read(ProcessId, &Buffer, VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        WORD ReadWord(WdkTypes::PVOID VirtualAddress) const {
            return ReadWord(Pid, VirtualAddress);
        }

        static DWORD ReadDword(ULONG ProcessId, WdkTypes::PVOID VirtualAddress) {
            DWORD Buffer = 0;
            Read(ProcessId, &Buffer, VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        DWORD ReadDword(WdkTypes::PVOID VirtualAddress) const {
            return ReadDword(Pid, VirtualAddress);
        }

        static DWORD64 ReadQword(ULONG ProcessId, WdkTypes::PVOID VirtualAddress) {
            DWORD64 Buffer = 0;
            Read(ProcessId, &Buffer, VirtualAddress, sizeof(Buffer));
            return Buffer;
        }

        DWORD64 ReadQword(WdkTypes::PVOID VirtualAddress) const {
            return ReadQword(Pid, VirtualAddress);
        }

        static VOID WriteByte(ULONG ProcessId, WdkTypes::PVOID VirtualAddress, BYTE Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            Write(ProcessId, VirtualAddress, &Value, sizeof(Value), PerformCopyOnWrite);
        }

        VOID WriteByte(WdkTypes::PVOID VirtualAddress, BYTE Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            WriteByte(Pid, VirtualAddress, Value, PerformCopyOnWrite);
        }

        static VOID WriteWord(ULONG ProcessId, WdkTypes::PVOID VirtualAddress, WORD Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            Write(ProcessId, VirtualAddress, &Value, sizeof(Value), PerformCopyOnWrite);
        }

        VOID WriteWord(WdkTypes::PVOID VirtualAddress, WORD Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            WriteWord(Pid, VirtualAddress, Value, PerformCopyOnWrite);
        }

        static VOID WriteDword(ULONG ProcessId, WdkTypes::PVOID VirtualAddress, DWORD Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            Write(ProcessId, VirtualAddress, &Value, sizeof(Value), PerformCopyOnWrite);
        }

        VOID WriteDword(WdkTypes::PVOID VirtualAddress, DWORD Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            WriteDword(Pid, VirtualAddress, Value, PerformCopyOnWrite);
        }

        static VOID WriteQword(ULONG ProcessId, WdkTypes::PVOID VirtualAddress, DWORD64 Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            Write(ProcessId, VirtualAddress, &Value, sizeof(Value), PerformCopyOnWrite);
        }

        VOID WriteQword(WdkTypes::PVOID VirtualAddress, DWORD64 Value, BOOLEAN PerformCopyOnWrite = TRUE) {
            WriteQword(Pid, VirtualAddress, Value, PerformCopyOnWrite);
        }
    };
}