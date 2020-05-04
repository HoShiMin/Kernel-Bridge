#pragma once

// For the Hyper-V only:
extern "C" unsigned long long __fastcall HypercallHyperV(
    unsigned long long Rcx,
    unsigned long long Rdx,
    unsigned long long R8,
    unsigned long long R9
);

extern "C" unsigned long long __fastcall KbVmcall(
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
}