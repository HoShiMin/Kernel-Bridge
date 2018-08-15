#pragma once

class OSVersion final {
private:
    using _OSVersion = struct {
        ULONG Major;
        ULONG Minor;
    };
    static BOOLEAN Initialized;
    static _OSVersion Version;
    static VOID Initialize();
public:
    static BOOLEAN IsGreaterThan(ULONG Major, ULONG Minor);
    static BOOLEAN IsWindowsXPOrGreater();
    static BOOLEAN IsWindowsXP64OrGreater();
    static BOOLEAN IsWindowsVistaOrGreater();
    static BOOLEAN IsWindows7OrGreater();
    static BOOLEAN IsWindows8OrGreater();
    static BOOLEAN IsWindows81OrGreater();
    static BOOLEAN IsWindows10OrGreater();
};