#pragma once

namespace KbRtl {
    enum KbMapDrvStatus {
        KbMapDrvSuccess,
        KbMapDrvImportNotResolved,
        KbMapDrvOrdinalImportNotSupported,
        KbMapDrvKernelMemoryNotAllocated,
        KbMapDrvTransitionFailure,
        KbMapDrvCreationFailure
    };

    // 'DriverImage' is a raw *.sys file
    // 'DriverName' is a system name of driver in format L"\\Driver\\YourDriverName"
    KbMapDrvStatus WINAPI KbMapDriver(PVOID DriverImage, LPCWSTR DriverName);
}