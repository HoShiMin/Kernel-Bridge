#pragma once

namespace Callable
{
    // Calls a callback in a system thread:
    bool CallInSystemContext(bool(*Callback)(void* Arg), void* Arg = nullptr, bool Wait = true);
    
    // Calls a callback on each CPU in a context of current thread:
    bool ForEachCpu(bool(*Callback)(void* Arg, unsigned int ProcessorNumber), void* Arg = nullptr);
    
    // Queues DPC to each CPU:
    void DpcOnEachCpu(void(*Callback)(void* Arg), void* Arg = nullptr);

    // Queues DPC to specified CPU and returns immediately:
    void QueueDpc(bool(*Callback)(void* Arg), void* Arg = nullptr, unsigned char ProcessorNumber = 0);

    // Queues DPC to specified CPU and waits until it done:
    void QueueWaitDpc(bool(*Callback)(void* Arg), void* Arg = nullptr, unsigned char ProcessorNumber = 0);

    // Queues threaded DPC to specified CPU and returns immediately:
    void QueueThreadedDpc(bool(*Callback)(void* Arg), void* Arg = nullptr, unsigned char ProcessorNumber = 0);

    // Queues treaded DPC to specified CPU and waits until it done:
    void QueueWaitThreadedDpc(bool(*Callback)(void* Arg), void* Arg = nullptr, unsigned char ProcessorNumber = 0);

    // Stops all CPUs except the current and raises IRQL of the current thread:
    _IRQL_raises_(DISPATCH_LEVEL)
    [[nodiscard]] void* StopMachine();

    // Resumes all stopped CPUs and restores IRQL of the current thread:
    _IRQL_restores_
    void ResumeMachine(void* StopMachineData);
}