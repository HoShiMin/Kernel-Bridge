#include "PEAnalyzer.h"

constexpr unsigned int RELOCS_OFFSET_MASK = 0b0000111111111111; /* Low 12 bit */

constexpr unsigned short FORCED_FILE_ALIGNMENT = 0x200;
constexpr unsigned short MINIMAL_SECTION_ALIGNMENT = 0x1000;

constexpr unsigned short MZ_SIGNATURE = 0x5A4D; // MZ
constexpr unsigned short PE_SIGNATURE = 0x4550; // PE

constexpr unsigned short PE32_SIGNATURE = 0x010B;
constexpr unsigned short PE64_SIGNATURE = 0x020B;

size_t inline alignDown(size_t value, size_t factor)
{
    return value & ~(factor - 1);
}

size_t inline alignUp(size_t value, size_t factor)
{
    return alignDown(value - 1, factor) + factor;
}

SIZE_T PEAnalyzer::rvaToOffset(SIZE_T rva) const
{
    if (!m_isRawModule) return rva;
/*
    Offset = SectionRAW + (rva - SectionRVA)
    1. Find a section that contains the specified rva
    2. Calculate offset from beginning of section
    3. Add offset to the physical address of section in file
*/
    for (const auto& section : m_sections)
    {
        SIZE_T sectionBase, sectionSize, sectionOffset;
        if (m_needToAlign)
        {
            sectionBase = alignDown(static_cast<SIZE_T>(section.offsetInMemory), m_sectionAlignment);
            SIZE_T alignedFileSize, alignedSectionSize;
            alignedFileSize    = alignUp(section.sizeOnDisk, m_fileAlignment);
            alignedSectionSize = alignUp(section.sizeInMemory, m_sectionAlignment);
            sectionSize        = alignedFileSize > alignedSectionSize ? alignedSectionSize : alignedFileSize;
            sectionOffset      = alignDown(section.offsetInFile, FORCED_FILE_ALIGNMENT);
        }
        else
        {
            sectionBase = static_cast<SIZE_T>(section.offsetInMemory);
            sectionSize = section.sizeOnDisk > section.sizeInMemory ? section.sizeInMemory : section.sizeOnDisk;
            sectionOffset = section.offsetInFile;
        }

        if ((rva >= sectionBase) && (rva < sectionBase + sectionSize))
        {
            return (sectionOffset + (rva - sectionBase));
        }
    }

    return 0;
}

void PEAnalyzer::fillSectionsInfo()
{
    m_sections.clear();
    WORD numberOfSections = m_ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(m_ntHeaders);
    for (unsigned short i = 0; i < numberOfSections; ++i, ++sectionHeader)
    {
        SECTION_INFO sectionInfo = {};
        sectionInfo.offsetInMemory = sectionHeader->VirtualAddress;
        sectionInfo.offsetInFile = sectionHeader->PointerToRawData;
        sectionInfo.sizeInMemory = sectionHeader->Misc.VirtualSize;
        sectionInfo.sizeOnDisk = sectionHeader->SizeOfRawData;
        sectionInfo.characteristics = sectionHeader->Characteristics;
        sectionInfo.numberOfRelocs = sectionHeader->NumberOfRelocations;
        memcpy(&sectionInfo.name, &sectionHeader->Name, SEC_NAME_SIZE);
        sectionInfo.name[SEC_NAME_SIZE] = NULL; // Null-terminator
        m_sections.push_back(sectionInfo);
    }
}

void PEAnalyzer::fillRelocsInfo()
{
    m_relocs.clear();
    auto relocsDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

    if (!relocsDir->Size) return;

    auto relocs = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(relocsDir->VirtualAddress)));
    auto relocsFinalAddress = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(relocs) + relocsDir->Size);
    while (relocs < relocsFinalAddress)
    {
        DWORD relocsRva = relocs->VirtualAddress;

        DWORD relocsCount = (relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto relocEntry = reinterpret_cast<PWORD>((reinterpret_cast<PBYTE>(relocs) + sizeof(IMAGE_BASE_RELOCATION)));
        for (unsigned int i = 0; i < relocsCount; ++i, ++relocEntry)
        {
            WORD reloc = *relocEntry;
            RELOC_INFO relocInfo = {};
            relocInfo.rva = relocsRva + (reloc & RELOCS_OFFSET_MASK);
            relocInfo.relocType = static_cast<BYTE>(reloc >> 12u);
            m_relocs.push_back(relocInfo);
        }

        relocs = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(relocs) + relocs->SizeOfBlock);
    }
}

void PEAnalyzer::fillImportsSet(
    __in PIMAGE_THUNK_DATA thunk,
    __in PIMAGE_THUNK_DATA originalThunk,
    __out IMPORTS_SET& importsSet)
{
    importsSet.clear();
    while (thunk->u1.AddressOfData)
    {
        auto namedImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(originalThunk->u1.AddressOfData));

        constexpr SIZE_T ordinalPresentMask = static_cast<SIZE_T>(0x80) << static_cast<SIZE_T>((sizeof(SIZE_T) - 1) * 8);
        constexpr SIZE_T ordinalMask = ordinalPresentMask - 1;

        IMPORT_INFO importInfo;
        importInfo.ft = reinterpret_cast<PVOID>(thunk->u1.Function);
        importInfo.oft = reinterpret_cast<PVOID>(originalThunk->u1.Function);
        importInfo.isOrdinalImport = (reinterpret_cast<SIZE_T>(importInfo.oft) & ordinalPresentMask) == ordinalPresentMask;
        if (importInfo.isOrdinalImport)
        {
            importInfo.ordinal = reinterpret_cast<SIZE_T>(importInfo.oft) & ordinalMask;
            importInfo.hint = 0;
        }
        else
        {
            importInfo.ordinal = 0;
            importInfo.hint = namedImport->Hint;
            importInfo.name = namedImport->Name;
        }

        importsSet.push_back(importInfo);

        ++thunk;
        ++originalThunk;
    }
}

void PEAnalyzer::fillImportsInfo()
{
    m_imports.clear();
    auto importDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

    if (!importDir->Size) return;

    auto imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(importDir->VirtualAddress)));
    while (imports->FirstThunk)
    {
        auto libraryName = reinterpret_cast<LPCSTR>(m_localBase) + rvaToOffset(imports->Name);

        IMPORTS_SET importsSet;

        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(imports->FirstThunk));
        auto originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(imports->OriginalFirstThunk));
        fillImportsSet(thunk, originalThunk, importsSet);

        m_imports.emplace(libraryName, importsSet);
        ++imports;
    }
}

void PEAnalyzer::fillDelayedImportsInfo()
{
    m_delayedImports.clear();
    auto delayedImportDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);

    if (!delayedImportDir->Size) return;

    auto delayedImports = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(delayedImportDir->VirtualAddress));
    while (delayedImports->DllNameRVA)
    {
        auto libraryName = reinterpret_cast<LPCSTR>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(delayedImports->DllNameRVA));

        DELAYED_IMPORT_INFO delayedImportInfo;
        delayedImportInfo.attributes = delayedImports->Attributes.AllAttributes;
        delayedImportInfo.hModule = *reinterpret_cast<HMODULE*>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(delayedImports->ModuleHandleRVA));
        delayedImportInfo.dllName = libraryName;

        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(delayedImports->ImportAddressTableRVA));
        auto originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(delayedImports->ImportNameTableRVA));
        fillImportsSet(thunk, originalThunk, delayedImportInfo.imports);

        m_delayedImports.push_back(delayedImportInfo);
        ++delayedImports;
    }
}

void PEAnalyzer::fillExportsInfo()
{
    m_exports.timeStamp = 0;
    m_exports.numberOfNames = 0;

    m_exports.name.clear();
    m_exports.exports.clear();
    auto exportDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

    if (!exportDir->Size) return;

    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(exportDir->VirtualAddress)));

    this->m_exports.timeStamp = exports->TimeDateStamp;
    this->m_exports.numberOfNames = exports->NumberOfNames;
    this->m_exports.numberOfFunctions = exports->NumberOfFunctions;
    this->m_exports.name = reinterpret_cast<LPCSTR>(m_localBase) + rvaToOffset(exports->Name);

    auto ordinalsArray = reinterpret_cast<PWORD>((reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(exports->AddressOfNameOrdinals)));

    auto namesArray = reinterpret_cast<PDWORD>((reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(exports->AddressOfNames)));
    auto functionsArray = reinterpret_cast<PDWORD>((reinterpret_cast<PBYTE>(m_localBase) + rvaToOffset(exports->AddressOfFunctions)));

    std::unordered_map<WORD, unsigned int> ordinalsMap; // ordinal -> ordinal index
    ordinalsMap.reserve(exports->NumberOfNames);
    for (unsigned int nameNumber = 0; nameNumber < exports->NumberOfNames; ++nameNumber)
    {
        ordinalsMap.emplace(*(ordinalsArray + nameNumber), nameNumber);
    }

    for (unsigned int functionNumber = 0; functionNumber < exports->NumberOfFunctions; ++functionNumber)
    {
        DWORD functionAddress = *(functionsArray + functionNumber);

        EXPORT_INFO exportInfo;
        exportInfo.va = reinterpret_cast<PBYTE>(m_localBase) + functionAddress;
        exportInfo.rva = functionAddress;
        exportInfo.ordinal = exports->Base + functionNumber;

        auto ordinalEntry = ordinalsMap.find(functionNumber);
        exportInfo.ordinalExport = ordinalEntry == ordinalsMap.end();
        if (!exportInfo.ordinalExport)
        {
            unsigned int nameNumber = ordinalEntry->second;
            auto functionName = reinterpret_cast<LPCSTR>(m_localBase) + rvaToOffset(*(namesArray + nameNumber));
            exportInfo.name = functionName;
        }

        m_exports.exports.push_back(exportInfo);
    }
}

PEAnalyzer::PEAnalyzer()
    : m_isRawModule(false)
    , m_areValidPeSignatures(false)
    , m_dosHeader(nullptr)
    , m_ntHeaders(nullptr)
    , m_optionalHeader(nullptr)
    , m_imageSize(0)
    , m_localBase(nullptr)
    , m_imageBase(nullptr)
    , m_entryPoint(nullptr)
    , m_needToAlign(0)
    , m_fileAlignment(0)
    , m_sectionAlignment(0)
    , m_sections()
    , m_relocs()
    , m_imports()
    , m_delayedImports()
    , m_exports()
{}


PEAnalyzer::PEAnalyzer(HMODULE hModule, bool isRawModule)
    : m_isRawModule(false)
    , m_areValidPeSignatures(false)
    , m_dosHeader(nullptr)
    , m_ntHeaders(nullptr)
    , m_optionalHeader(nullptr)
    , m_imageSize(0)
    , m_localBase(nullptr)
    , m_imageBase(nullptr)
    , m_entryPoint(nullptr)
    , m_needToAlign(0)
    , m_fileAlignment(0)
    , m_sectionAlignment(0)
    , m_sections()
    , m_relocs()
    , m_imports()
    , m_delayedImports()
    , m_exports()
{
    load(hModule, isRawModule);
}

PEAnalyzer::~PEAnalyzer()
{
    clear();
}

bool PEAnalyzer::load(HMODULE hModule, bool isRawModule)
{
    clear();

    if (!hModule) return false;

    m_isRawModule = isRawModule;

    m_dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    m_ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<PBYTE>(hModule) + m_dosHeader->e_lfanew));

    if (!validatePeSignatures())
    {
        clear();
        return false;
    }

    m_optionalHeader = &m_ntHeaders->OptionalHeader;

#ifdef _WIN64
    if (m_optionalHeader->Magic != PE64_SIGNATURE)
        throw std::exception("PE image must be 64-bit!");
#elif _WIN32
    if (m_optionalHeader->Magic != PE32_SIGNATURE)
        throw std::exception("PE image must be 32-bit!");
#endif

    m_imageSize = m_optionalHeader->SizeOfImage;

    m_localBase = hModule;

    m_imageBase = reinterpret_cast<PVOID>(m_optionalHeader->ImageBase);
    m_entryPoint = reinterpret_cast<PBYTE>(m_imageBase) + m_optionalHeader->AddressOfEntryPoint;

    m_fileAlignment = m_optionalHeader->FileAlignment;
    m_sectionAlignment = m_optionalHeader->SectionAlignment;
    m_needToAlign = m_sectionAlignment >= MINIMAL_SECTION_ALIGNMENT;

    fillSectionsInfo();
    fillRelocsInfo();
    fillImportsInfo();
    fillDelayedImportsInfo();
    fillExportsInfo();

    return true;
}

void PEAnalyzer::clear()
{
    m_isRawModule = false;
    m_areValidPeSignatures = false;
    m_dosHeader = nullptr;
    m_ntHeaders = nullptr;
    m_optionalHeader = nullptr;
    m_localBase = nullptr;
    m_imageBase = nullptr;
    m_imageSize = 0;
    m_entryPoint = nullptr;
    m_needToAlign = false;
    m_fileAlignment = 0;
    m_sectionAlignment = 0;
    m_sections.clear();
    m_relocs.clear();
    m_imports.clear();
    m_delayedImports.clear();
    m_exports.timeStamp = 0;
    m_exports.numberOfNames = 0;
    m_exports.numberOfFunctions = 0;
    m_exports.name.clear();
    m_exports.exports.clear();
}

bool PEAnalyzer::validatePeSignatures()
{
    return m_areValidPeSignatures = (m_dosHeader->e_magic == MZ_SIGNATURE) && (m_ntHeaders->Signature == PE_SIGNATURE);
}