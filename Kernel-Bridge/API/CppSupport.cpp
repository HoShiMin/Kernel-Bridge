using _PVFV = void (__cdecl *)(void); // PVFV = Pointer to Void Func(Void)
using _PIFV = int  (__cdecl *)(void); // PIFV = Pointer to Int Func(Void)
using _PVFI = void (__cdecl *)(int);  // PVFI = Pointer to Void Func(Int)

// C initializers:
#pragma data_seg(".CRT$XIA")
__declspec(allocate(".CRT$XIA")) _PIFV __xi_a[] = { 0 };
#pragma data_seg(".CRT$XIZ")
__declspec(allocate(".CRT$XIZ")) _PIFV __xi_z[] = { 0 };

// C++ initializers:
#pragma data_seg(".CRT$XCA")
__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { 0 };
#pragma data_seg(".CRT$XCZ")
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { 0 };

// C pre-terminators:
#pragma data_seg(".CRT$XPA")
__declspec(allocate(".CRT$XPA")) _PVFV __xp_a[] = { 0 };
#pragma data_seg(".CRT$XPZ")
__declspec(allocate(".CRT$XPZ")) _PVFV __xp_z[] = { 0 };

// C terminators:
#pragma data_seg(".CRT$XTA")
__declspec(allocate(".CRT$XTA")) _PVFV __xt_a[] = { 0 };
#pragma data_seg(".CRT$XTZ")
__declspec(allocate(".CRT$XTZ")) _PVFV __xt_z[] = { 0 };

#pragma data_seg()

#ifdef _AMD64_
#pragma comment(linker, "/merge:.CRT=.data")
#elif _X86_
#pragma comment(linker, "/merge:.CRT=.rdata")
#endif

static _PVFV onexitarray[32];
static _PVFV *onexitbegin, *onexitend;

extern "C" int __cdecl __init_on_exit_array() {
    onexitend = onexitbegin = onexitarray;
    *onexitbegin = 0;
    return 0;
}

#pragma data_seg(".CRT$XIB")      // run onexitinit automatically
__declspec(allocate(".CRT$XIB")) static _PIFV pinit = __init_on_exit_array;
#pragma data_seg()


int __cdecl _purecall() {
    // It's abnormal execution, so we should to detect it:
    __debugbreak();
    return 0;
}
 
static void execute_pvfv_array(_PVFV* begin, _PVFV* end) {
    _PVFV* fn = begin;
    while (fn != end) {
        if (*fn) (**fn)();
        ++fn;
    }
}

static int execute_pifv_array(_PIFV* begin, _PIFV* end) {
    _PIFV* fn = begin;
    while (fn != end) {
        if (*fn) {
            int result = (**begin)();
            if (result) return result;
        }
        ++fn;
    }
    return 0;
}

extern "C" int __crt_init() {
    int result = execute_pifv_array(__xi_a, __xi_z);
    if (result) return result;
    execute_pvfv_array(__xc_a, __xc_z);
    return 0;
}

extern "C" void __crt_deinit() {
    if (onexitbegin) {
        while (--onexitend >= onexitbegin)
            if (*onexitend != 0) (**onexitend)();
    }
    execute_pvfv_array(__xp_a, __xp_z);
    execute_pvfv_array(__xt_a, __xt_z);
}