#include <wdm.h>

#include "KernelShells.h"

#include "GetProcAddress.h"
#include "MemoryUtils.h"

namespace KernelShells {
    _IRQL_requires_max_(APC_LEVEL)
    ULONG ExecuteShellCode(
        _ShellCode Shell,
        OPTIONAL IN OUT PVOID Argument
    ) {
        ULONG Result = 0;

        KFLOATING_SAVE FpuState = {};
        BOOLEAN FpuSaved = KeSaveFloatingPointState(&FpuState) == STATUS_SUCCESS;

        __try {
            Result = Shell(Importer::GetKernelProcAddress, Argument);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Result = static_cast<ULONG>(-1);
        }

        if (FpuSaved) KeRestoreFloatingPointState(&FpuState);

        return Result;
    }

}