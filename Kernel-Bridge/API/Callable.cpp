#include <ntifs.h>

extern "C" NTSYSAPI VOID NTAPI KeGenericCallDpc(IN PKDEFERRED_ROUTINE Routine, IN PVOID Context);
extern "C" NTSYSAPI VOID NTAPI KeSignalCallDpcDone(IN PVOID SystemArgument1);
extern "C" NTSYSAPI BOOLEAN NTAPI KeSignalCallDpcSynchronize(IN PVOID SystemArgument2);

extern "C" NTSYSAPI NTSTATUS NTAPI ZwYieldExecution();

namespace Callable
{
    bool CallInSystemContext(bool(*Callback)(void* Arg), void* Arg, bool Wait)
    {
        HANDLE hThread = NULL;

        struct PARAMS {
            bool(*Callback)(PVOID Arg);
            PVOID Arg;
            bool Result;
        } Params = {};
        Params.Callback = Callback;
        Params.Arg = Arg;

        OBJECT_ATTRIBUTES ObjectAttributes;
        InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        NTSTATUS Status = PsCreateSystemThread(
            &hThread,
            GENERIC_ALL,
            &ObjectAttributes,
            NULL,
            NULL,
            [](PVOID Arg)
            {
                PARAMS* Params = reinterpret_cast<PARAMS*>(Arg);
                Params->Result = Params->Callback(Params->Arg);
                PsTerminateSystemThread(STATUS_SUCCESS);
            },
            &Params
        );

        if (NT_SUCCESS(Status))
        {
            if (Wait)
            {
                ZwWaitForSingleObject(hThread, FALSE, NULL);
                ZwClose(hThread);
                return Params.Result;
            }
            else
            {
                ZwClose(hThread);
                return true;
            }
        }

        return false;
    }

    bool ForEachCpu(bool(*Callback)(void* Arg, unsigned int ProcessorNumber), void* Arg)
    {
        ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        for (ULONG i = 0; i < ProcessorsCount; i++)
        {
            PROCESSOR_NUMBER ProcessorNumber = {};
            KeGetProcessorNumberFromIndex(i, &ProcessorNumber);

            GROUP_AFFINITY Affinity = {}, PreviousAffinity = {};
            Affinity.Group = ProcessorNumber.Group;
            Affinity.Mask = 1LL << ProcessorNumber.Number;
            KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);

            ZwYieldExecution(); // Perform the context switch to apply the affinity

            bool Status = Callback(Arg, i);

            KeRevertToUserGroupAffinityThread(&PreviousAffinity);

            if (!Status) return false;
        }
        return true;
    }

    void DpcOnEachCpu(void(*Callback)(void* Arg), void* Arg)
    {
        struct DPC_DATA
        {
            decltype(Callback) Callback;
            PVOID Arg;
        };

        DPC_DATA DpcData = { Callback, Arg };

        KeGenericCallDpc([](PKDPC Dpc, PVOID Arg, PVOID SystemArgument1, PVOID SystemArgument2)
        {
            UNREFERENCED_PARAMETER(Dpc);
            auto* DpcData = reinterpret_cast<DPC_DATA*>(Arg);
            DpcData->Callback(DpcData->Arg);
            KeSignalCallDpcSynchronize(SystemArgument2);
            KeSignalCallDpcDone(SystemArgument1);
        }, &DpcData);
    }

    void QueueDpc(bool(*Callback)(void* Arg), void* Arg, unsigned char ProcessorNumber)
    {
        struct DPC_DATA
        {
            KDPC Dpc;
            decltype(Callback) Callback;
            void* Arg;
        };

        constexpr ULONG DpcTag = 'CPDK';
        DPC_DATA* DpcData = reinterpret_cast<DPC_DATA*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(*DpcData), DpcTag));
        memset(DpcData, 0, sizeof(*DpcData));
        DpcData->Callback = Callback;
        DpcData->Arg = Arg;

        KeInitializeDpc(&DpcData->Dpc, [](PKDPC Dpc, PVOID Arg, PVOID SystemArgument1, PVOID SystemArgument2)
        {
            UNREFERENCED_PARAMETER(Dpc);
            UNREFERENCED_PARAMETER(SystemArgument1);
            UNREFERENCED_PARAMETER(SystemArgument2);
            DPC_DATA* DpcData = reinterpret_cast<DPC_DATA*>(Arg);
            DpcData->Callback(DpcData->Arg);
            ExFreePoolWithTag(Dpc, DpcTag);
        }, DpcData);

        KeSetImportanceDpc(&DpcData->Dpc, HighImportance);
        KeSetTargetProcessorDpc(&DpcData->Dpc, ProcessorNumber);
        
        KeInsertQueueDpc(&DpcData->Dpc, NULL, NULL);
    }

    void QueueWaitDpc(bool(*Callback)(void* Arg), void* Arg, unsigned char ProcessorNumber)
    {
        struct DPC_DATA
        {
            decltype(Callback) Callback;
            void* Arg;
            volatile LONG Finished;
        };

        DPC_DATA DpcData = { Callback, Arg, 0 };

        constexpr ULONG DpcTag = 'CPDK';

        KDPC Dpc;
        KeInitializeDpc(&Dpc, [](PKDPC Dpc, PVOID Arg, PVOID SystemArgument1, PVOID SystemArgument2)
        {
            UNREFERENCED_PARAMETER(Dpc);
            UNREFERENCED_PARAMETER(SystemArgument1);
            UNREFERENCED_PARAMETER(SystemArgument2);
            DPC_DATA* DpcData = reinterpret_cast<DPC_DATA*>(Arg);
            DpcData->Callback(DpcData->Arg);
            InterlockedExchange(&DpcData->Finished, TRUE);
        }, &DpcData);

        KeSetImportanceDpc(&Dpc, HighImportance);
        KeSetTargetProcessorDpc(&Dpc, ProcessorNumber);

        KeInsertQueueDpc(&Dpc, NULL, NULL);

        while (InterlockedCompareExchange(&DpcData.Finished, TRUE, TRUE) != TRUE)
        {
            _mm_pause();
        }
    }

    void QueueThreadedDpc(bool(*Callback)(void* Arg), void* Arg, unsigned char ProcessorNumber)
    {
        struct DPC_DATA
        {
            KDPC Dpc;
            decltype(Callback) Callback;
            void* Arg;
        };

        constexpr ULONG DpcTag = 'CPDT'; // TDPC = Threaded DPC
        DPC_DATA* DpcData = reinterpret_cast<DPC_DATA*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(*DpcData), DpcTag));
        memset(DpcData, 0, sizeof(*DpcData));
        DpcData->Callback = Callback;
        DpcData->Arg = Arg;

        KeInitializeThreadedDpc(&DpcData->Dpc, [](PKDPC Dpc, PVOID Arg, PVOID SystemArgument1, PVOID SystemArgument2)
        {
            UNREFERENCED_PARAMETER(Dpc);
            UNREFERENCED_PARAMETER(SystemArgument1);
            UNREFERENCED_PARAMETER(SystemArgument2);
            DPC_DATA* DpcData = reinterpret_cast<DPC_DATA*>(Arg);
            DpcData->Callback(DpcData->Arg);
            ExFreePoolWithTag(Dpc, DpcTag);
        }, DpcData);

        KeSetImportanceDpc(&DpcData->Dpc, HighImportance);
        KeSetTargetProcessorDpc(&DpcData->Dpc, ProcessorNumber);

        KeInsertQueueDpc(&DpcData->Dpc, NULL, NULL);
    }

    void QueueWaitThreadedDpc(bool(*Callback)(void* Arg), void* Arg, unsigned char ProcessorNumber)
    {
        struct DPC_DATA
        {
            decltype(Callback) Callback;
            void* Arg;
            volatile LONG Finished;
        };

        DPC_DATA DpcData = { Callback, Arg, 0 };

        constexpr ULONG DpcTag = 'CPDT'; // TDPC = Threaded DPC

        KDPC Dpc;
        KeInitializeThreadedDpc(&Dpc, [](PKDPC Dpc, PVOID Arg, PVOID SystemArgument1, PVOID SystemArgument2)
        {
            UNREFERENCED_PARAMETER(Dpc);
            UNREFERENCED_PARAMETER(SystemArgument1);
            UNREFERENCED_PARAMETER(SystemArgument2);
            DPC_DATA* DpcData = reinterpret_cast<DPC_DATA*>(Arg);
            DpcData->Callback(DpcData->Arg);
            InterlockedExchange(&DpcData->Finished, TRUE);
        }, &DpcData);

        KeSetImportanceDpc(&Dpc, HighImportance);
        KeSetTargetProcessorDpc(&Dpc, ProcessorNumber);

        KeInsertQueueDpc(&Dpc, NULL, NULL);

        while (InterlockedCompareExchange(&DpcData.Finished, TRUE, TRUE) != TRUE)
        {
            _mm_pause();
        }
    }

    struct STOP_PROCESSORS_DATA
    {
        volatile LONG ProcessorsStopped;
        volatile LONG NeedToResume;
        KIRQL PreviousIrql;
        KDPC Dpcs[1];
    };

    _IRQL_raises_(DISPATCH_LEVEL)
    [[nodiscard]] void* StopMachine()
    {
        ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        SIZE_T StopDataSize = sizeof(STOP_PROCESSORS_DATA) + (ProcessorsCount - 2) * sizeof(KDPC); // Exclude the current CPU and one CPU is already reserved in STOP_PROCESSORS_DATA
        auto* StopData = reinterpret_cast<STOP_PROCESSORS_DATA*>(ExAllocatePoolWithTag(
            NonPagedPool,
            StopDataSize,
            'POTS'
        ));

        memset(StopData, 0, StopDataSize);

        StopData->PreviousIrql = KeRaiseIrqlToDpcLevel();

        ULONG CurrentProcessor = KeGetCurrentProcessorNumber();

        ULONG DpcIndex = 0;
        for (CCHAR i = 0; i < static_cast<CCHAR>(ProcessorsCount); ++i)
        {
            if (i == static_cast<CCHAR>(CurrentProcessor)) continue;

            auto* Dpc = &StopData->Dpcs[DpcIndex++];

            KeInitializeDpc(Dpc, [](PKDPC Dpc, PVOID Arg, PVOID SystemArgument1, PVOID SystemArgument2)
            {
                UNREFERENCED_PARAMETER(Dpc);
                UNREFERENCED_PARAMETER(SystemArgument1);
                UNREFERENCED_PARAMETER(SystemArgument2);
                STOP_PROCESSORS_DATA* StopData = reinterpret_cast<STOP_PROCESSORS_DATA*>(Arg);
                InterlockedIncrement(&StopData->ProcessorsStopped);
                while (InterlockedCompareExchange(&StopData->NeedToResume, TRUE, TRUE) == FALSE)
                {
                    _mm_pause();
                }
                InterlockedDecrement(&StopData->ProcessorsStopped);
            }, StopData);

            KeSetImportanceDpc(Dpc, HighImportance);
            KeSetTargetProcessorDpc(Dpc, i);

            KeInsertQueueDpc(Dpc, NULL, NULL);
        }

        while (InterlockedCompareExchange(
            &StopData->ProcessorsStopped,
            static_cast<LONG>(ProcessorsCount),
            static_cast<LONG>(ProcessorsCount)
        ) != static_cast<LONG>(ProcessorsCount)) {
            _mm_pause();
        }

        return StopData;
    }

    _IRQL_restores_
    void ResumeMachine(void* StopMachineData)
    {
        auto* Data = reinterpret_cast<STOP_PROCESSORS_DATA*>(StopMachineData);

        InterlockedExchange(&Data->NeedToResume, TRUE);        
        while (InterlockedCompareExchange(&Data->ProcessorsStopped, 0, 0) != 0)
        {
            _mm_pause();
        }
        KeLowerIrql(Data->PreviousIrql);
        ExFreePoolWithTag(Data, 'POTS');
    }
}