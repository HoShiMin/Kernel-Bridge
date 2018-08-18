#include <Windows.h>

#include "DriversUtils.h"

BOOL InstallDriver(LPCWSTR FilePath, LPCWSTR DriverName, DWORD DriverType) 
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (hSCManager == NULL) return FALSE;
    
    SC_HANDLE hService = CreateService(
        hSCManager, DriverName, DriverName, 
        SERVICE_ALL_ACCESS, DriverType, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, FilePath, 
        NULL, NULL, NULL, NULL, NULL
    );

    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    LPCWSTR Arguments = NULL;
    BOOL Status = StartService(hService, 0, &Arguments);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return Status;
}

BOOL DeleteDriver(LPCWSTR DriverName) 
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) return FALSE;

    SC_HANDLE hService = OpenService(hSCManager, DriverName, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    SERVICE_STATUS ServiceStatus;
    BOOL Status = ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
    if (Status) Status = DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return Status;
}

HANDLE OpenDevice(LPCWSTR NativeDeviceName) 
{
    return CreateFile(
        NativeDeviceName, 
        0, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_SYSTEM, 
        NULL
    );
}

BOOL SendIOCTL(
    IN HANDLE hDevice,
    IN DWORD Ioctl,
    IN PVOID InputBuffer,
    IN ULONG InputBufferSize,
    IN PVOID OutputBuffer,
    IN ULONG OutputBufferSize,
    OPTIONAL OUT PDWORD BytesReturned,
    OPTIONAL IN DWORD Method
) {
    DWORD RawIoctl = CTL_CODE(0x8000, Ioctl, Method, FILE_ANY_ACCESS);
    DWORD Returned = 0;
    BOOL Status = DeviceIoControl(hDevice, RawIoctl, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, &Returned, NULL);
    if (BytesReturned) *BytesReturned = Returned;
    return Status;
}

BOOL SendRawIOCTL(
    IN HANDLE hDevice,
    IN DWORD Ioctl,
    IN PVOID InputBuffer,
    IN ULONG InputBufferSize,
    IN PVOID OutputBuffer,
    IN ULONG OutputBufferSize,
    OPTIONAL OUT PDWORD BytesReturned,
    OPTIONAL IN DWORD Method
) {
    DWORD Returned = 0;
    BOOL Status = DeviceIoControl(hDevice, Ioctl, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, &Returned, NULL);
    if (BytesReturned) *BytesReturned = Returned;
    return Status;
}