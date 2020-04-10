#pragma once

#include <vector>
#include <unordered_map>
#include <Windows.h>

/*
    RAW or Offset - offset from the beginning of file
    RVA - offset in the loaded module (in memory)
    VA = ImageBase + RVA - real address of something in memory of the module
    RVA -> Offset: SectionRAW + (RVA - SectionRVA)
                                            ^- In section's header
*/

constexpr int SEC_NAME_SIZE = 8;

struct SECTION_INFO
{
    DWORD offsetInMemory;
    DWORD offsetInFile;
    DWORD sizeInMemory;
    DWORD sizeOnDisk;
    DWORD characteristics;
    WORD numberOfRelocs;
    CHAR name[SEC_NAME_SIZE + 1];
};

typedef std::vector<SECTION_INFO> SECTIONS_SET;

struct RELOC_INFO
{
    DWORD rva; // Page RVA + Offset
    BYTE relocType;
};

typedef std::vector<RELOC_INFO> RELOCS_SET;

struct IMPORT_INFO
{
    PVOID oft; // OFT = OriginalFirstThunk
    PVOID ft; // FT = FirstThunk, адрес в IAT (реальный адрес в памяти)
    bool isOrdinalImport;
    SIZE_T ordinal;
    WORD hint;
    std::string name;
};

typedef std::vector<IMPORT_INFO> IMPORTS_SET;
typedef std::unordered_map<std::string, IMPORTS_SET> IMPORTS_MAP; // LibName -> imports

struct DELAYED_IMPORT_INFO
{
    DWORD attributes;
    HMODULE hModule;
    std::string dllName;
    IMPORTS_SET imports;
};

typedef std::vector<DELAYED_IMPORT_INFO> DELAYED_IMPORTS_SET;

struct EXPORT_INFO
{
    PVOID va;
    DWORD rva;
    DWORD ordinal;
    bool ordinalExport;
    std::string name;
};

typedef std::vector<EXPORT_INFO> EXPORTS_SET;

struct EXPORTS_INFO
{
    DWORD timeStamp;
    DWORD numberOfNames;
    DWORD numberOfFunctions;
    std::string name;
    EXPORTS_SET exports;
};

class PEAnalyzer
{
private:
    bool m_isRawModule;
    bool m_areValidPeSignatures;

    PIMAGE_DOS_HEADER m_dosHeader;
    PIMAGE_NT_HEADERS m_ntHeaders;
    PIMAGE_OPTIONAL_HEADER m_optionalHeader;

    ULONG m_imageSize;

    PVOID m_localBase;

    PVOID m_imageBase;
    PVOID m_entryPoint;

    BOOL m_needToAlign;
    DWORD m_fileAlignment;
    DWORD m_sectionAlignment;

    SECTIONS_SET m_sections;
    RELOCS_SET m_relocs;
    IMPORTS_MAP m_imports;
    DELAYED_IMPORTS_SET m_delayedImports;
    EXPORTS_INFO m_exports;

    bool validatePeSignatures();

    void fillSectionsInfo();
    void fillRelocsInfo();
    void fillImportsInfo();
    void fillDelayedImportsInfo();
    void fillExportsInfo();

    void fillImportsSet(__in PIMAGE_THUNK_DATA thunk, __in PIMAGE_THUNK_DATA originalThunk, __out IMPORTS_SET& importsSet);

public:
    PEAnalyzer();
    PEAnalyzer(HMODULE hModule, bool isRawModule);
    ~PEAnalyzer();

    bool load(HMODULE hModule, bool isRawModule);

    void clear();

    [[nodiscard]] const SECTIONS_SET& getSectionsInfo() const { return m_sections; }
    [[nodiscard]] const RELOCS_SET& getRelocsInfo() const { return m_relocs; }
    [[nodiscard]] const IMPORTS_MAP& getImportsInfo() const { return m_imports; }
    [[nodiscard]] const DELAYED_IMPORTS_SET& getDelayedImports() const { return m_delayedImports; }
    [[nodiscard]] const EXPORTS_INFO& getExportsInfo() const { return m_exports; }

    [[nodiscard]] ULONG getImageSize() const { return m_imageSize; }
    [[nodiscard]] PVOID getImageBase() const { return m_imageBase; }
    [[nodiscard]] PVOID getLocalBase() const { return m_localBase; }
    [[nodiscard]] PVOID getEntryPoint() const { return m_entryPoint; }

    [[nodiscard]] PIMAGE_DOS_HEADER getDosHeader() const { return m_dosHeader; }
    [[nodiscard]] PIMAGE_NT_HEADERS getNtHeaders() const { return m_ntHeaders; }
    [[nodiscard]] PIMAGE_OPTIONAL_HEADER getOptionalHeader() const { return m_optionalHeader; }

    [[nodiscard]] bool isValidPe() const { return m_areValidPeSignatures; };

    [[nodiscard]] SIZE_T rvaToOffset(SIZE_T rva) const;
};