#include <fltKernel.h>
#include "Importer.h"

namespace Importer {
    _IRQL_requires_max_(PASSIVE_LEVEL)
    PVOID NTAPI GetKernelProcAddress(LPCWSTR SystemRoutineName) {
        UNICODE_STRING Name;
        RtlInitUnicodeString(&Name, SystemRoutineName);
        return MmGetSystemRoutineAddress(&Name);
    }
}