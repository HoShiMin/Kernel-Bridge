#pragma once

#define IOCTL(Code, Method) (CTL_CODE(0x8000, (Code), Method, FILE_ANY_ACCESS))
#define EXTRACT_CTL_CODE(Ioctl)   ((unsigned short)(((Ioctl) & 0b0011111111111100) >> 2))
#define EXTRACT_CTL_METHOD(Ioctl) ((unsigned short)((Ioctl) & 0b11))

#define CTL_BASE (0x800)

BOOL InstallDriver(LPCWSTR FilePath, LPCWSTR DriverName, DWORD DriverType = SERVICE_KERNEL_DRIVER);
BOOL InstallMinifilter(LPCWSTR FilePath, LPCWSTR DriverName, LPCWSTR Altitude);
BOOL DeleteDriver(LPCWSTR DriverName);

HANDLE OpenDevice(LPCWSTR DeviceName);

BOOL SendIOCTL(
    IN HANDLE hDevice,
    IN DWORD Ioctl,
    IN PVOID InputBuffer,
    IN ULONG InputBufferSize,
    IN PVOID OutputBuffer,
    IN ULONG OutputBufferSize,
    OPTIONAL OUT PDWORD BytesReturned = NULL,
    OPTIONAL IN DWORD Method = METHOD_NEITHER
);

BOOL SendRawIOCTL(
    IN HANDLE hDevice,
    IN DWORD Ioctl,
    IN PVOID InputBuffer,
    IN ULONG InputBufferSize,
    IN PVOID OutputBuffer,
    IN ULONG OutputBufferSize,
    OPTIONAL OUT PDWORD BytesReturned = NULL
);
