#pragma once

using _ImportNameCallback = PVOID(*)(LPCSTR LibName, LPCSTR FunctionName);
using _ImportOrdinalCallback = PVOID(*)(LPCSTR LibName, WORD Ordinal);
using _EntryPoint = BOOL(WINAPI*)(HMODULE hModule, DWORD dwReason, LPCONTEXT lpContext);

class PELoader {
private:
    PBYTE hModule;
    ULONG DeployedSize;

    SIZE_T PreviousLoadDelta;

    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;

    void FillImports(_ImportNameCallback ImportNameCallback, _ImportOrdinalCallback ImportOrdinalCallback);
public:
    PELoader(HMODULE RawModule, _ImportNameCallback ImportNameCallback, _ImportOrdinalCallback ImportOrdinalCallback);
    ~PELoader() { if (hModule) VirtualFree(hModule, 0, MEM_RELEASE); };
    void Relocate(HMODULE Base);
    HMODULE Get() const {
        return reinterpret_cast<HMODULE>(hModule);
    }
    ULONG GetDeployedSize() const {
        return DeployedSize;
    }
    _EntryPoint GetEntryPoint() const {
        return reinterpret_cast<_EntryPoint>(hModule + OptionalHeader->AddressOfEntryPoint);
    }
    _EntryPoint GetBaseRelativeEntryPoint(HMODULE Base) const {
        return reinterpret_cast<_EntryPoint>(reinterpret_cast<PBYTE>(Base) + OptionalHeader->AddressOfEntryPoint);
    }
};