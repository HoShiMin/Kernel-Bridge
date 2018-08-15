#include <fltKernel.h>
#include "FilesAPI.h"

FilesAPI::FilesAPI(
    LPCWSTR FilePath, 
    CREATE_FILE_TYPE Type, 
    ACCESS_MASK AccessMask, 
    ULONG ShareAccess
) : hFile(NULL) {

    UNICODE_STRING Path;
    RtlInitUnicodeString(&Path, FilePath);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes, 
        &Path, 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    IO_STATUS_BLOCK IoStatusBlock = {};
    LARGE_INTEGER AllocationSize = {};

    ULONG CreateDisposition = FILE_OVERWRITE;
    switch (Type) {
    case fCreateEmpty:
        CreateDisposition = FILE_OVERWRITE_IF;
        break;
    case fOpenExisting:
        CreateDisposition = FILE_OPEN;
        break;
    case fOpenOrCreate:
        CreateDisposition = FILE_OPEN_IF;
        break;
    }

    CreationStatus = ZwCreateFile(
        &hFile, 
        AccessMask,
        &ObjectAttributes,
        &IoStatusBlock,
        &AllocationSize,
        FILE_ATTRIBUTE_NORMAL,
        ShareAccess,
        CreateDisposition,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
}

NTSTATUS FilesAPI::Read(OUT PVOID Buffer, ULONG Size, OPTIONAL UINT64 Offset) const {
    IO_STATUS_BLOCK IoStatusBlock = {};
    return ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, Size, reinterpret_cast<PLARGE_INTEGER>(&Offset), NULL);
}

NTSTATUS FilesAPI::Write(IN PVOID Buffer, ULONG Size, OPTIONAL UINT64 Offset) const {
    IO_STATUS_BLOCK IoStatusBlock = {};
    return ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, Size, reinterpret_cast<PLARGE_INTEGER>(&Offset), NULL);
}

NTSTATUS FilesAPI::Close() {
    NTSTATUS Status = hFile ? ZwClose(hFile) : STATUS_SUCCESS;
    hFile = NULL;
    return Status;
}


NTSTATUS FilesAPI::CreateDir(LPCWSTR DirPath) {
    UNICODE_STRING Path;
    RtlInitUnicodeString(&Path, DirPath);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes, 
        &Path, 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    IO_STATUS_BLOCK IoStatusBlock = {};
    LARGE_INTEGER AllocationSize = {};

    HANDLE hDir = NULL;
    NTSTATUS Status = ZwCreateFile(
        &hDir, 
        SYNCHRONIZE,
        &ObjectAttributes,
        &IoStatusBlock,
        &AllocationSize,
        FILE_ATTRIBUTE_NORMAL,
        0, // Non-shared access
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
        NULL,
        0
    );
    if (NT_SUCCESS(Status) && hDir) ZwClose(hDir);
    return Status;
}

NTSTATUS FilesAPI::DeleteFile(LPCWSTR FilePath) {
    UNICODE_STRING Path;
    RtlInitUnicodeString(&Path, FilePath);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes, 
        &Path, 
        OBJ_CASE_INSENSITIVE, 
        NULL, 
        NULL
    );

    return ZwDeleteFile(&ObjectAttributes);
}