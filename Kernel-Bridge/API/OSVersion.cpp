#include <wdm.h>
#include "OSVersion.h"

BOOLEAN OSVersion::Initialized = FALSE;
OSVersion::_OSVersion OSVersion::Version = {};

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OSVersion::Initialize() {
    if (Initialized) return;
    PsGetVersion(&Version.Major, &Version.Minor, NULL, NULL);
    Initialized = TRUE;
}

BOOLEAN OSVersion::IsGreaterThan(ULONG Major, ULONG Minor) {
    if (!Initialized) Initialize();
    return (Version.Major > Major) || (Version.Major == Major && Version.Minor >= Minor);
}

BOOLEAN OSVersion::IsWindowsXPOrGreater() {
    return IsGreaterThan(5, 1);
}

BOOLEAN OSVersion::IsWindowsXP64OrGreater() {
    return IsGreaterThan(5, 2);
}

BOOLEAN OSVersion::IsWindowsVistaOrGreater() {
    return IsGreaterThan(6, 0);
}

BOOLEAN OSVersion::IsWindows7OrGreater() {
    return IsGreaterThan(6, 1);
}

BOOLEAN OSVersion::IsWindows8OrGreater() {
    return IsGreaterThan(6, 2);
}

BOOLEAN OSVersion::IsWindows81OrGreater() {
    return IsGreaterThan(6, 3);
}

BOOLEAN OSVersion::IsWindows10OrGreater() {
    return IsGreaterThan(10, 0);
}