#pragma once

#include <Windows.h>
#include <winternl.h>

BOOL InstallDriver(LPCWSTR FilePath, LPCWSTR DriverName, DWORD DriverType = SERVICE_KERNEL_DRIVER);
BOOL DeleteDriver(LPCWSTR DriverName);

HANDLE OpenDevice(LPCWSTR DeviceName);

#define IOCTL(Code, Method) (CTL_CODE(0x8000, Code, Method, FILE_ANY_ACCESS))

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
	OPTIONAL OUT PDWORD BytesReturned = NULL,
	OPTIONAL IN DWORD Method = METHOD_NEITHER
);