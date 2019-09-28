#include <Windows.h>
#include "PEAnalyzer.h"
#include "PELoader.h"

PELoader::PELoader(HMODULE RawModule, _ImportNameCallback ImportNameCallback, _ImportOrdinalCallback ImportOrdinalCallback) {
    PEAnalyzer pe(RawModule, TRUE);

    DeployedSize = pe.GetImageSize();
    hModule = static_cast<PBYTE>(VirtualAlloc(NULL, DeployedSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!hModule) 
        throw std::exception("Unable to allocate memory");

    // Copying of headers:
    CopyMemory(hModule, RawModule, pe.GetOptionalHeader()->SizeOfHeaders);

    // Copying of sections:
    for (const auto& Section : pe.GetSectionsInfo()) {
        CopyMemory(
            hModule + Section.OffsetInMemory,
            reinterpret_cast<PBYTE>(RawModule) + Section.OffsetInFile,
            Section.SizeOnDisk
        );
    }

    DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(hModule + DosHeader->e_lfanew);
    OptionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER>(&NtHeaders->OptionalHeader);

    OriginalImageBase = OptionalHeader->ImageBase;

    // Filling imports and exports:
    FillImports(ImportNameCallback, ImportOrdinalCallback);

    // Relocating to current memory block:
    PreviousLoadDelta = 0;
    Relocate(reinterpret_cast<HMODULE>(hModule));
}

void PELoader::FillImports(_ImportNameCallback ImportNameCallback, _ImportOrdinalCallback ImportOrdinalCallback) {
    auto ImportDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
        &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    );

    if (ImportDir->Size == 0) return;

    auto Imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(hModule + ImportDir->VirtualAddress);
    while (Imports->FirstThunk != 0) {
        LPCSTR LibName = reinterpret_cast<LPCSTR>(hModule + Imports->Name);
        auto Thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + Imports->FirstThunk);
        auto OriginalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + Imports->OriginalFirstThunk);
        while (Thunk->u1.AddressOfData) {
            auto NamedImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(hModule + OriginalThunk->u1.AddressOfData);

            const SIZE_T OrdinalPresentMask = (SIZE_T)0x80 << (SIZE_T)((sizeof(SIZE_T) - 1) * 8);
            const SIZE_T OrdinalMask = OrdinalPresentMask - 1;

            if ((Thunk->u1.Function & OrdinalMask) == OrdinalMask) {
                Thunk->u1.Function = reinterpret_cast<SIZE_T>(
                    ImportOrdinalCallback(LibName, static_cast<WORD>(Thunk->u1.Function & OrdinalMask))
                );
            } else {
                Thunk->u1.Function = reinterpret_cast<SIZE_T>(
                    ImportNameCallback(LibName, NamedImport->Name)
                );
            }

            Thunk++;
            OriginalThunk++;
        }
        Imports++;
    }
}

void PELoader::Relocate(HMODULE Base) {
    // Check whether we have (or have no) relocs:
    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) return;

    auto RelocsDir = static_cast<PIMAGE_DATA_DIRECTORY>(
        &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    );

    if (RelocsDir->Size == 0) return;

    OptionalHeader->ImageBase = reinterpret_cast<SIZE_T>(Base);
    SIZE_T LoadDelta = reinterpret_cast<SIZE_T>(Base) - OriginalImageBase;

    auto Relocs = reinterpret_cast<PIMAGE_BASE_RELOCATION>(hModule + RelocsDir->VirtualAddress);
    auto RelocsFinalAddress = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(Relocs) + RelocsDir->Size);
    while (Relocs < RelocsFinalAddress) {
        DWORD RelocsRva = Relocs->VirtualAddress;

        DWORD RelocsCount = (Relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD RelocEntry = (PWORD)((PBYTE)Relocs + sizeof(IMAGE_BASE_RELOCATION));
        for (unsigned int i = 0; i < RelocsCount; i++, RelocEntry++) {
            WORD Reloc = *RelocEntry;

            constexpr DWORD RelocsOffsetMask = 0b0000111111111111; // Lower 12 bits
            DWORD RelocRva = RelocsRva + (Reloc & RelocsOffsetMask);
            BYTE Type = static_cast<BYTE>(Reloc >> 12);
            
            PVOID RelocAddress = reinterpret_cast<PWORD>(hModule + RelocRva);

            switch (Type) {
            case IMAGE_REL_BASED_HIGH: {
                *static_cast<PWORD>(RelocAddress) += HIWORD(LoadDelta) - HIWORD(PreviousLoadDelta);
                break;
            }
            case IMAGE_REL_BASED_LOW: {
                *static_cast<PWORD>(RelocAddress) += LOWORD(LoadDelta) - LOWORD(PreviousLoadDelta);
                break;
            }
            case IMAGE_REL_BASED_HIGHLOW: {
                *static_cast<PSIZE_T>(RelocAddress) += LoadDelta - PreviousLoadDelta;
                break;
            }
            case IMAGE_REL_BASED_DIR64: {
                *static_cast<UNALIGNED DWORD_PTR*>(RelocAddress) += LoadDelta - PreviousLoadDelta;
                break;
            }
            case IMAGE_REL_BASED_ABSOLUTE:
            case IMAGE_REL_BASED_HIGHADJ:
                break;
            }
        }

        Relocs = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(Relocs) + Relocs->SizeOfBlock);
    }

    PreviousLoadDelta = LoadDelta;
}