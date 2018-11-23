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

BOOL SetupFilterInstance(LPCWSTR DriverName, LPCWSTR InstanceName, LPCWSTR Altitude, DWORD Flags, BOOL SetAsDefaultInstance)
{
    WCHAR PathBuffer[MAX_PATH] = {};
    wcscpy_s(PathBuffer, MAX_PATH, L"System\\CurrentControlSet\\Services\\");
    wcscat_s(PathBuffer, MAX_PATH, DriverName);

    // Registering an instance with specified flags and altitude:
    HKEY hKey = NULL;
    LSTATUS RegStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, PathBuffer, 0, KEY_ALL_ACCESS, &hKey);
    if (RegStatus != ERROR_SUCCESS) return FALSE;

    HKEY hInstancesKey = NULL;
    DWORD Disposition = 0;
    RegStatus = RegCreateKeyEx(hKey, L"Instances", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInstancesKey, &Disposition);
    RegCloseKey(hKey);
    if (RegStatus != ERROR_SUCCESS) return FALSE;
    
    if (SetAsDefaultInstance) {
        RegStatus = RegSetValueEx(
            hInstancesKey, 
            L"DefaultInstance", 
            0, 
            REG_SZ, 
            reinterpret_cast<const BYTE*>(InstanceName), 
            (static_cast<DWORD>(wcsnlen_s(InstanceName, MAX_PATH)) + 1) * sizeof(WCHAR)
        );

        if (RegStatus != ERROR_SUCCESS) {
            RegCloseKey(hInstancesKey);
            return FALSE;
        }
    }

    HKEY hInstanceKey = NULL;
    RegStatus = RegCreateKeyEx(hInstancesKey, InstanceName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInstanceKey, &Disposition);
    if (RegStatus != ERROR_SUCCESS) {
        RegCloseKey(hInstancesKey);
        return FALSE;
    }
    RegCloseKey(hInstancesKey);

    RegStatus = RegSetValueEx(
        hInstanceKey, 
        L"Altitude", 
        0, 
        REG_SZ, 
        reinterpret_cast<const BYTE*>(Altitude), 
        (static_cast<DWORD>(wcsnlen_s(Altitude, MAX_PATH)) + 1) * sizeof(WCHAR)
    );

    if (RegStatus != ERROR_SUCCESS) {
        RegCloseKey(hInstanceKey);
        return FALSE;
    }

    RegStatus = RegSetValueEx(
        hInstanceKey, 
        L"Flags", 
        0, 
        REG_DWORD, 
        reinterpret_cast<const BYTE*>(&Flags), 
        sizeof(Flags)
    );

    RegCloseKey(hInstanceKey);

    return RegStatus == ERROR_SUCCESS;
}

BOOL InstallMinifilter(LPCWSTR FilePath, LPCWSTR DriverName, LPCWSTR Altitude) 
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (hSCManager == NULL) return FALSE;
    
    SC_HANDLE hService = CreateService(
        hSCManager, DriverName, DriverName, 
        SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, 
        FilePath, 
        L"FSFilter Activity Monitor", 
        NULL, 
        NULL,
        NULL, 
        NULL
    );

    CloseServiceHandle(hSCManager);

    if (hService == NULL) return FALSE;

    if (!SetupFilterInstance(DriverName, L"DefInst", Altitude, 0, TRUE)) {
        CloseServiceHandle(hService);
        return FALSE;
    }

    LPCWSTR Arguments = NULL;
    BOOL Status = StartService(hService, 0, &Arguments);

    CloseServiceHandle(hService);
   
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
    ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
    BOOL Status = DeleteService(hService);

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
    OPTIONAL OUT PDWORD BytesReturned
) {
    DWORD Returned = 0;
    BOOL Status = DeviceIoControl(hDevice, Ioctl, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, &Returned, NULL);
    if (BytesReturned) *BytesReturned = Returned;
    return Status;
}
