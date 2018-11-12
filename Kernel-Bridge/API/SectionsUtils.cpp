#include <wdm.h>

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
    ) {
        UNICODE_STRING SecName = {};
        if (Name) RtlInitUnicodeString(&SecName, Name);

        OBJECT_ATTRIBUTES Attributes = {};
        
        InitializeObjectAttributes(&Attributes, Name ? &SecName : NULL, SecObjFlags, NULL, NULL);
        
        return ZwCreateSection(
            hSection,
            DesiredAccess,
            &Attributes,
            reinterpret_cast<PLARGE_INTEGER>(&MaximumSize),
            SecPageProtection,
            AllocationAttributes,
            hFile
        );
    }

    NTSTATUS OpenSection(
        OUT PHANDLE hSection,
        LPCWSTR Name,
        ACCESS_MASK DesiredAccess,
        ULONG SecObjFlags
    ) {
        if (!Name) return STATUS_INVALID_PARAMETER;

        UNICODE_STRING SecName = {};
        RtlInitUnicodeString(&SecName, Name);

        OBJECT_ATTRIBUTES Attributes = {};
        InitializeObjectAttributes(&Attributes, &SecName, SecObjFlags, NULL, NULL);

        return ZwOpenSection(hSection, DesiredAccess, &Attributes);
    }

    NTSTATUS MapViewOfSection(
        HANDLE hSection,
        HANDLE hProcess,
        IN OUT PVOID* BaseAddress,
        SIZE_T CommitSize,
        IN OUT OPTIONAL UINT64* SectionOffset,
        IN OUT SIZE_T* ViewSize,
        SECTION_INHERIT InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect
    ) {
        return ZwMapViewOfSection(
            hSection,
            hProcess,
            BaseAddress,
            NULL,
            CommitSize,
            reinterpret_cast<PLARGE_INTEGER>(SectionOffset),
            ViewSize,
            InheritDisposition,
            AllocationType,
            Win32Protect
        );
    }

    NTSTATUS UnmapViewOfSection(HANDLE hProcess, PVOID BaseAddress) {
        return ZwUnmapViewOfSection(hProcess, BaseAddress);
    }
}