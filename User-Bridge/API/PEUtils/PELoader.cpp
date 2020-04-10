#include <Windows.h>
#include "PEAnalyzer.h"
#include "PELoader.h"

#include <stdexcept>

PELoader::PELoader(
    HMODULE rawModule,
    ImportNameCallback importNameCallback,
    ImportOrdinalCallback importOrdinalCallback)
{
    PEAnalyzer pe(rawModule, true);

    m_deployedSize = pe.getImageSize();
    m_hModule = static_cast<PBYTE>(VirtualAlloc(NULL, m_deployedSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!m_hModule) 
        throw std::runtime_error("Unable to allocate memory");

    // Copying of headers:
    CopyMemory(m_hModule, rawModule, pe.getOptionalHeader()->SizeOfHeaders);

    // Copying of sections:
    for (const auto& sec : pe.getSectionsInfo())
    {
        CopyMemory(
            m_hModule + sec.offsetInMemory,
            reinterpret_cast<PBYTE>(rawModule) + sec.offsetInFile,
            sec.sizeOnDisk
        );
    }

    m_dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_hModule);
    m_ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(m_hModule + m_dosHeader->e_lfanew);
    m_optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER>(&m_ntHeaders->OptionalHeader);

    m_originalImageBase = m_optionalHeader->ImageBase;

    // Filling imports and exports:
    fillImports(importNameCallback, importOrdinalCallback);

    // Relocating to current memory block:
    m_previousLoadDelta = 0;
    relocate(reinterpret_cast<HMODULE>(m_hModule));
}

void PELoader::fillImports(
    ImportNameCallback importNameCallback,
    ImportOrdinalCallback importOrdinalCallback)
{
    auto importDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
        &m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    );

    if (importDir->Size == 0) return;

    auto imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(m_hModule + importDir->VirtualAddress);
    while (imports->FirstThunk)
    {
        LPCSTR libName = reinterpret_cast<LPCSTR>(m_hModule + imports->Name);
        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(m_hModule + imports->FirstThunk);
        auto originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(m_hModule + imports->OriginalFirstThunk);
        
        while (thunk->u1.AddressOfData)
        {
            auto namedImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(m_hModule + originalThunk->u1.AddressOfData);

            const SIZE_T OrdinalPresentMask = (SIZE_T)0x80 << (SIZE_T)((sizeof(SIZE_T) - 1) * 8);
            const SIZE_T OrdinalMask = OrdinalPresentMask - 1;

            if ((thunk->u1.Function & OrdinalMask) == OrdinalMask)
            {
                thunk->u1.Function = reinterpret_cast<SIZE_T>(
                    importOrdinalCallback(libName, static_cast<WORD>(thunk->u1.Function & OrdinalMask))
                );
            }
            else
            {
                thunk->u1.Function = reinterpret_cast<SIZE_T>(
                    importNameCallback(libName, namedImport->Name)
                );
            }

            ++thunk;
            ++originalThunk;
        }

        ++imports;
    }
}

void PELoader::relocate(HMODULE base)
{
    // Check whether we have (or have no) relocs:
    if (m_ntHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) return;

    auto relocsDir = static_cast<PIMAGE_DATA_DIRECTORY>(
        &m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    );

    if (relocsDir->Size == 0) return;

    m_optionalHeader->ImageBase = reinterpret_cast<SIZE_T>(base);
    SIZE_T loadDelta = reinterpret_cast<SIZE_T>(base) - m_originalImageBase;

    auto relocs = reinterpret_cast<PIMAGE_BASE_RELOCATION>(m_hModule + relocsDir->VirtualAddress);
    auto relocsFinalAddress = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(relocs) + relocsDir->Size);
    while (relocs < relocsFinalAddress)
    {
        DWORD relocsRva = relocs->VirtualAddress;

        DWORD relocsCount = (relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD relocEntry = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(relocs) + sizeof(IMAGE_BASE_RELOCATION));
        
        for (unsigned int i = 0; i < relocsCount; ++i, ++relocEntry)
        {
            WORD reloc = *relocEntry;

            constexpr DWORD relocsOffsetMask = 0b0000111111111111; // Lower 12 bits
            DWORD relocRva = relocsRva + (reloc & relocsOffsetMask);
            BYTE type = static_cast<BYTE>(reloc >> 12);
            
            PVOID relocAddress = reinterpret_cast<PWORD>(m_hModule + relocRva);

            switch (type) {
            case IMAGE_REL_BASED_HIGH: {
                *static_cast<PWORD>(relocAddress) += HIWORD(loadDelta) - HIWORD(m_previousLoadDelta);
                break;
            }
            case IMAGE_REL_BASED_LOW: {
                *static_cast<PWORD>(relocAddress) += LOWORD(loadDelta) - LOWORD(m_previousLoadDelta);
                break;
            }
            case IMAGE_REL_BASED_HIGHLOW: {
                *static_cast<PSIZE_T>(relocAddress) += loadDelta - m_previousLoadDelta;
                break;
            }
            case IMAGE_REL_BASED_DIR64: {
                *static_cast<UNALIGNED DWORD_PTR*>(relocAddress) += loadDelta - m_previousLoadDelta;
                break;
            }
            case IMAGE_REL_BASED_ABSOLUTE:
            case IMAGE_REL_BASED_HIGHADJ:
                break;
            }
        }

        relocs = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(relocs) + relocs->SizeOfBlock);
    }

    m_previousLoadDelta = loadDelta;
}