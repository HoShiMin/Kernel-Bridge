#pragma once

// For the Hyper-V only:
extern "C" unsigned long long __fastcall __hyperv_vmcall(
    unsigned long long Rcx,
    unsigned long long Rdx,
    unsigned long long R8,
    unsigned long long R9
);

extern "C" unsigned long long __fastcall __kb_vmcall(
    unsigned long long Rcx,
    unsigned long long Rdx,
    unsigned long long R8,
    unsigned long long R9
);

namespace Hypervisor
{
    bool IsVirtualized();
    bool Virtualize();
    bool Devirtualize();

    bool InterceptPage(
        unsigned long long Pa,
        unsigned long long ReadPa,
        unsigned long long WritePa,
        unsigned long long ExecutePa,
        unsigned long long ExecuteReadPa,
        unsigned long long ExecuteWritePa
    );

    bool DeinterceptPage(unsigned long long Pa);
}