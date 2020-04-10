#pragma once

using ImportNameCallback = PVOID(*)(LPCSTR LibName, LPCSTR FunctionName);
using ImportOrdinalCallback = PVOID(*)(LPCSTR LibName, WORD Ordinal);
using EntryPoint = BOOL(WINAPI*)(HMODULE hModule, DWORD dwReason, LPCONTEXT lpContext);

class PELoader
{
private:
    PBYTE m_hModule;
    ULONG m_deployedSize;

    SIZE_T m_originalImageBase;
    SIZE_T m_previousLoadDelta;

    PIMAGE_DOS_HEADER m_dosHeader;
    PIMAGE_NT_HEADERS m_ntHeaders;
    PIMAGE_OPTIONAL_HEADER m_optionalHeader;

    void fillImports(ImportNameCallback importNameCallback, ImportOrdinalCallback importOrdinalCallback);
public:
    PELoader(HMODULE rawModule, ImportNameCallback importNameCallback, ImportOrdinalCallback importOrdinalCallback);
    ~PELoader() { if (m_hModule) VirtualFree(m_hModule, 0, MEM_RELEASE); };
    
    void relocate(HMODULE Base);

    HMODULE get() const
    {
        return reinterpret_cast<HMODULE>(m_hModule);
    }

    ULONG getDeployedSize() const
    {
        return m_deployedSize;
    }
    EntryPoint getEntryPoint() const {
        return reinterpret_cast<EntryPoint>(m_hModule + m_optionalHeader->AddressOfEntryPoint);
    }
    EntryPoint getBaseRelativeEntryPoint(HMODULE base) const {
        return reinterpret_cast<EntryPoint>(reinterpret_cast<PBYTE>(base) + m_optionalHeader->AddressOfEntryPoint);
    }
};