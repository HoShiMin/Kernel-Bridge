#include <fltKernel.h>
#include "GetProcAddress.h"

namespace Importer {
    _IRQL_requires_max_(PASSIVE_LEVEL)
    PVOID GetKernelProcAddress(LPCWSTR SystemRoutineName) {
        UNICODE_STRING Name;
        RtlInitUnicodeString(&Name, SystemRoutineName);
        return MmGetSystemRoutineAddress(&Name);
    }
}