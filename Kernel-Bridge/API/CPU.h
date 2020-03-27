#pragma once

namespace CPU {
    void CLI();
    void STI();
    void HLT();
    
    void CPUID(unsigned int FunctionIdEax, int Regs[4]);
    void CPUIDEX(unsigned int FunctionIdEax, unsigned int SubfunctionIdEcx, int Regs[4]);

    unsigned long long RDMSR(unsigned long Index);
    void WRMSR(unsigned long Index, unsigned long long Value);

    unsigned long long RDPMC(unsigned long Counter);
    unsigned long long RDTSC();
    unsigned long long RDTSCP(unsigned int* TscAux);
    bool IsRdtscpPresent();

    void DisableWriteProtection();
    void EnableWriteProtection();

    bool IsSmepPresent();
    bool IsSmapPresent();
    void DisableSmep();
    void EnableSmep();
    void DisableSmap();
    void EnableSmap();
}