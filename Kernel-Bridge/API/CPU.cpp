extern "C" void _enable();
extern "C" void _disable();
extern "C" void __halt();
extern "C" unsigned long long __readmsr(unsigned long Index);
extern "C" void __writemsr(unsigned long Index, unsigned long long Value);
extern "C" void __cpuid(int Info[4], int FunctionIdEax);
extern "C" void __cpuidex(int Info[4], int FunctionIdEx, int SubfunctionIdEcx);
extern "C" unsigned long long __readpmc(unsigned long Counter);
extern "C" unsigned long long __rdtsc();
extern "C" unsigned long long __rdtscp(unsigned int* TscAux);
#ifdef _AMD64_
extern "C" unsigned long long __readcr0();
extern "C" void __writecr0(unsigned long long Value);
extern "C" unsigned long long __readcr4();
extern "C" void __writecr4(unsigned long long Value);
#elif _X86_
extern "C" unsigned long __readcr0();
extern "C" void __writecr0(unsigned long Value);
extern "C" unsigned long __readcr4();
extern "C" void __writecr4(unsigned long Value);
#endif

namespace CPU {
    void CLI() {
        _disable();
    }

    void STI() {
        _enable();
    }

    void HLT() {
        __halt();
    }

    void CPUID(unsigned int FunctionIdEax, int Regs[4]) {
        __cpuid(Regs, FunctionIdEax);
    }

    void CPUIDEX(unsigned int FunctionIdEax, unsigned int SubfunctionIdEcx, int Regs[4]) {
        __cpuidex(Regs, FunctionIdEax, SubfunctionIdEcx);
    }

    unsigned long long RDMSR(unsigned long Index) {
        return __readmsr(Index);
    }

    void WRMSR(unsigned long Index, unsigned long long Value) {
        __writemsr(Index, Value);
    }

    unsigned long long RDPMC(unsigned long Counter) {
        return __readpmc(Counter);
    }

    unsigned long long RDTSC() {
        return __rdtsc();
    }

    unsigned long long RDTSCP(unsigned int* TscAux) {
        return __rdtscp(TscAux);
    }

    bool IsRdtscpPresent() {
        int regs[4];
        __cpuid(regs, 0x80000001);
        return (regs[3] & (1 << 27)) != 0;
    }

    void DisableWriteProtection() {
        __writecr0(__readcr0() & ~(1 << 16));
    }

    void EnableWriteProtection() {
        __writecr0(__readcr0() | (1 << 16));
    }

    bool IsSmepPresent() {
        int regs[4];
        __cpuidex(regs, 7, 0);
        return (regs[1] & (1 << 7)) != 0;
    }

    bool IsSmapPresent() {
        int regs[4];
        __cpuidex(regs, 7, 0);
        return (regs[1] & (1 << 20)) != 0;
    }

    void DisableSmep() {
        __writecr4(__readcr4() & ~(1 << 20));
    }

    void EnableSmep() {
        __writecr4(__readcr4() | (1 << 20));
    }

    void DisableSmap() {
        __writecr4(__readcr4() & ~(1 << 21));
    }

    void EnableSmap() {
        __writecr4(__readcr4() | (1 << 21));
    }
}