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

    KbMapDrvStatus WINAPI KbMapDriver(PVOID DriverImage, LPCWSTR DriverName);
}