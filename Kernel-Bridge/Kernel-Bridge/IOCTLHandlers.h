#pragma once

typedef struct _IOCTL_INFO {
    PVOID InputBuffer;
    PVOID OutputBuffer;
    ULONG InputBufferSize;
    ULONG OutputBufferSize;
    ULONG ControlCode;
} IOCTL_INFO, *PIOCTL_INFO;

NTSTATUS FASTCALL DispatchIOCTL(IN PIOCTL_INFO RequestInfo, OUT PSIZE_T ResponseLength);