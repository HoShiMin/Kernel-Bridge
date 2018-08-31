#pragma once

namespace Importer {
    // Get address of function from ntoskrnl.exe and FltMgr.dll:
    _IRQL_requires_max_(PASSIVE_LEVEL)
    PVOID NTAPI GetKernelProcAddress(LPCWSTR SystemRoutineName);
}