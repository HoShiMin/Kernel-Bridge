#include <wdm.h>

#include "KernelShells.h"

#include "Importer.h"
#include "MemoryUtils.h"
#include "CPU.h"

namespace KernelShells {
    _IRQL_requires_max_(APC_LEVEL)
    ULONG ExecuteShellCode(
        _ShellCode Shell,
        OPTIONAL IN OUT PVOID Argument
    ) {
        static volatile LONG EnteringsCount = 0;
        InterlockedIncrement(&EnteringsCount);

        ULONG Result = 0;

        KFLOATING_SAVE FpuState = {};
        BOOLEAN FpuSaved = KeSaveFloatingPointState(&FpuState) == STATUS_SUCCESS;

        KAFFINITY PreviousAffinity = KeQueryActiveProcessors();
        KeSetSystemAffinityThread(1); // Executing on 1st core of 1st processor

        if (CPU::IsSmepPresent()) CPU::DisableSmep();

        __try {
            Result = Shell(Importer::GetKernelProcAddress, Argument);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Result = static_cast<ULONG>(-1);
        }

        InterlockedDecrement(&EnteringsCount);
        if (!InterlockedCompareExchange(&EnteringsCount, 0, 0) && CPU::IsSmepPresent()) CPU::EnableSmep();

        KeSetSystemAffinityThread(PreviousAffinity);

        if (FpuSaved) KeRestoreFloatingPointState(&FpuState);

        return Result;
    }

}