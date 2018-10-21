#include <wdm.h>

using _PVFV = void (__cdecl *)(void); // PVFV = Pointer to Void Func(Void)
using _PIFV = int  (__cdecl *)(void); // PIFV = Pointer to Int Func(Void)

constexpr int max_destructors_count = 64;
static _PVFV onexitarray[max_destructors_count] = {};
static _PVFV *onexitbegin = nullptr, *onexitend = nullptr;

// C initializers:
#pragma section(".CRT$XIA", long, read)
__declspec(allocate(".CRT$XIA")) _PIFV __xi_a[] = { 0 };
#pragma section(".CRT$XIZ", long, read)
__declspec(allocate(".CRT$XIZ")) _PIFV __xi_z[] = { 0 };

// C++ initializers:
#pragma section(".CRT$XCA", long, read)
__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { 0 };
#pragma section(".CRT$XCZ", long, read)
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { 0 };

// C pre-terminators:
#pragma section(".CRT$XPA", long, read)
__declspec(allocate(".CRT$XPA")) _PVFV __xp_a[] = { 0 };
#pragma section(".CRT$XPZ", long, read)
__declspec(allocate(".CRT$XPZ")) _PVFV __xp_z[] = { 0 };

// C terminators:
#pragma section(".CRT$XTA", long, read)
__declspec(allocate(".CRT$XTA")) _PVFV __xt_a[] = { 0 };
#pragma section(".CRT$XTZ", long, read)
__declspec(allocate(".CRT$XTZ")) _PVFV __xt_z[] = { 0 };

#pragma data_seg()

#pragma comment(linker, "/merge:.CRT=.rdata")

extern "C" int __cdecl __init_on_exit_array() {
    onexitend = onexitbegin = onexitarray;
    *onexitbegin = 0;
    return 0;
}

extern "C" int __cdecl atexit(_PVFV fn) {
    // ToDo: replace with dynamically allocated list of destructors!
    if (onexitend > &onexitarray[max_destructors_count - 1]) 
        return 1; // Not enough space
    *onexitend = fn;
    onexitend++;
    return 0;
}

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
    __init_on_exit_array();
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

constexpr unsigned long CrtPoolTag = 'TRC_';

void* __cdecl operator new(size_t Size) {
    void* Pointer = ExAllocatePoolWithTag(NonPagedPool, Size, CrtPoolTag);
    if (Pointer) RtlZeroMemory(Pointer, Size);
    return Pointer;
}
 
void* __cdecl operator new(size_t Size, POOL_TYPE PoolType) {
    void* Pointer = ExAllocatePoolWithTag(PoolType, Size, CrtPoolTag);
    if (Pointer) RtlZeroMemory(Pointer, Size);
    return Pointer;
}

void* __cdecl operator new[](size_t Size) {
    void* Pointer = ExAllocatePoolWithTag(NonPagedPool, Size, CrtPoolTag);
    if (Pointer) RtlZeroMemory(Pointer, Size);
    return Pointer;
}
 
void* __cdecl operator new[](size_t Size, POOL_TYPE PoolType) {
    void* Pointer = ExAllocatePoolWithTag(PoolType, Size, CrtPoolTag);
    if (Pointer) RtlZeroMemory(Pointer, Size);
    return Pointer;
}
 
void __cdecl operator delete(void* Pointer) {
    ExFreePoolWithTag(Pointer, CrtPoolTag);
}
 
void __cdecl operator delete(void* Pointer, size_t Size) {
    UNREFERENCED_PARAMETER(Size);
    ExFreePoolWithTag(Pointer, CrtPoolTag);
}

void __cdecl operator delete[](void* Pointer) {
    ExFreePoolWithTag(Pointer, CrtPoolTag);
}

void __cdecl operator delete[](void* Pointer, size_t Size) {
    UNREFERENCED_PARAMETER(Size);
    ExFreePoolWithTag(Pointer, CrtPoolTag);
}