#pragma once

namespace Sections {
    NTSTATUS CreateSection(
        OUT PHANDLE hSection,
        OPTIONAL LPCWSTR Name,
        UINT64 MaximumSize,
        ACCESS_MASK DesiredAccess,
        ULONG SecObjFlags,
        ULONG SecPageProtection,
        ULONG AllocationAttributes,
        OPTIONAL HANDLE hFile
    );

    NTSTATUS OpenSection(
        OUT PHANDLE hSection,
        LPCWSTR Name,
        ACCESS_MASK DesiredAccess,
        ULONG SecObjFlags
    );

    NTSTATUS MapViewOfSection(
        HANDLE hSection,
        HANDLE hProcess,
        IN OUT PVOID* BaseAddress,
        SIZE_T CommitSize,
        IN OUT OPTIONAL UINT64* SectionOffset,
        IN OUT SIZE_T* ViewSize,
        SECTION_INHERIT InheritDisposition = ViewUnmap,
        ULONG AllocationType = MEM_RESERVE,
        ULONG Win32Protect = PAGE_READWRITE
    );

    NTSTATUS UnmapViewOfSection(HANDLE hProcess, PVOID BaseAddress);
}