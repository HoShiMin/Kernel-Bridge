#pragma once

#include <vector>
#include <unordered_map>
#include <Windows.h>

/*
    RAW или Offset - смещение от начала файла
    RVA - смещение в загруженном модуле в памяти
    VA = ImageBase + RVA - реальный адрес чего-либо в памяти модуля
    RVA -> Offset: SectionRAW + (RVA - SectionRVA)
                                            ^- Хранится в заголовке секции
*/

#define MZ_SIGNATURE 0x5A4D // MZ
#define PE_SIGNATURE 0x4550 // PE

#define PE32_SIGNATURE 0x010B
#define PE64_SIGNATURE 0x020B

#define SEC_NAME_SIZE 8

typedef struct _SECTION_INFO {
    DWORD OffsetInMemory;
    DWORD OffsetInFile;
    DWORD SizeInMemory;
    DWORD SizeOnDisk;
    DWORD Characteristics;
    WORD NumberOfRelocs;
    CHAR Name[SEC_NAME_SIZE + 1];
} SECTION_INFO, *PSECTION_INFO;

typedef std::vector<SECTION_INFO> SECTIONS_SET;

typedef struct _RELOC_INFO {
    DWORD Rva; // Page RVA + Offset
    BYTE Type;
} RELOC_INFO, *PRELOC_INFO;

typedef std::vector<RELOC_INFO> RELOCS_SET;

typedef struct _IMPORT_INFO {
    PVOID OFT; // OFT = OriginalFirstThunk
    PVOID FT; // FT = FirstThunk, адрес в IAT (реальный адрес в памяти)
    BOOL IsOrdinalImport;
    SIZE_T Ordinal;
    WORD Hint;
    std::string Name;
} IMPORT_INFO, *PIMPORT_INFO;

typedef std::vector<IMPORT_INFO> IMPORTS_SET;
typedef std::unordered_map<std::string, IMPORTS_SET> IMPORTS_MAP; // LibName -> Imports

typedef struct _DELAYED_IMPORT_INFO {
    DWORD Attributes;
    HMODULE hModule;
    std::string DllName;
    IMPORTS_SET Imports;
} DELAYED_IMPORT_INFO, *PDELAYED_IMPORT_INFO;

typedef std::vector<DELAYED_IMPORT_INFO> DELAYED_IMPORTS_SET;

typedef struct _EXPORT_INFO {
    PVOID VA;
    DWORD RVA;
    DWORD Ordinal;
    BOOL OrdinalExport;
    std::string Name;
} EXPORT_INFO, *PEXPORT_INFO;

typedef std::vector<EXPORT_INFO> EXPORTS_SET;

typedef struct _EXPORTS_INFO {
    DWORD TimeStamp;
    DWORD NumberOfNames;
    DWORD NumberOfFunctions;
    std::string Name;
    EXPORTS_SET Exports;
} EXPORTS_INFO, *PEXPORTS_INFO;

class PEAnalyzer {
private:
    BOOL IsRawModule;
    BOOL IsValidPESignatures;

    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;

    ULONG ImageSize;

    PVOID LocalBase;

    PVOID ImageBase;
    PVOID EntryPoint;

    BOOL NeedToAlign;
    DWORD FileAlignment;
    DWORD SectionAlignment;

    SECTIONS_SET Sections;
    RELOCS_SET Relocs;
    IMPORTS_MAP Imports;
    DELAYED_IMPORTS_SET DelayedImports;
    EXPORTS_INFO Exports;

    BOOL ValidatePESignatures();

    void FillSectionsInfo();
    void FillRelocsInfo();
    void FillImportsInfo();
    void FillDelayedImportsInfo();
    void FillExportsInfo();

    void FillImportsSet(PIMAGE_THUNK_DATA Thunk, PIMAGE_THUNK_DATA OriginalThunk, OUT IMPORTS_SET& ImportsSet);
public:
    PEAnalyzer();
    PEAnalyzer(HMODULE hModule, BOOL RawModule);
    ~PEAnalyzer();

    BOOL LoadModule(HMODULE hModule, BOOL RawModule);

    void Clear();

    const SECTIONS_SET& GetSectionsInfo() const { return Sections; }
    const RELOCS_SET& GetRelocsInfo() const { return Relocs; }
    const IMPORTS_MAP& GetImportsInfo() const { return Imports; }
    const DELAYED_IMPORTS_SET& GetDelayedImports() const { return DelayedImports; }
    const EXPORTS_INFO& GetExportsInfo() const { return Exports; }

    ULONG GetImageSize() const { return ImageSize; }
    PVOID GetImageBase() const { return ImageBase; }
    PVOID GetLocalBase() const { return LocalBase; }
    PVOID GetEntryPoint() const { return EntryPoint; }

    PIMAGE_DOS_HEADER GetDosHeader() const { return DosHeader; }
    PIMAGE_NT_HEADERS GetNtHeaders() const { return NtHeaders; }
    PIMAGE_OPTIONAL_HEADER GetOptionalHeader() const { return OptionalHeader; }

    BOOL IsValidPE() const { return IsValidPESignatures; };

    SIZE_T Rva2Offset(SIZE_T Rva) const;
};