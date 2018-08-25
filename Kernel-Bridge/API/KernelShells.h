#pragma once

namespace KernelShells {
    using _GetKernelProcAddress = PVOID(NTAPI*)(LPCWSTR RoutineName);
    using _ShellCode = ULONG(NTAPI*)(
        _GetKernelProcAddress GetKernelProcAddress,
        OPTIONAL IN OUT PVOID Argument
    );

    // Executes specified user- or kernel-shell into SEH-section and FPU-saved context,
    // Returns -1 (0xFFFFFFFF) if exception catched:
    _IRQL_requires_max_(APC_LEVEL)
    ULONG ExecuteShellCode(
        _ShellCode Shell,
        OPTIONAL IN OUT PVOID Argument
    );
}