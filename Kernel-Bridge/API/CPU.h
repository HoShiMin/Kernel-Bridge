#pragma once

namespace CPU {
    void CLI();
    void STI();
    void HLT();
    
    unsigned long long RDMSR(unsigned long Index);
    void WRMSR(unsigned long Index, unsigned long long Value);

    typedef struct _CPUID_INFO {
        unsigned int Eax;
        unsigned int Ebx;
        unsigned int Ecx;
        unsigned int Edx;
    } CPUID_INFO, *PCPUID_INFO;

    void CPUID(int FunctionIdEax, PCPUID_INFO Cpuid);
    void CPUIDEX(int FunctionIdEax, int SubfunctionIdEcx, PCPUID_INFO Cpuid);

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