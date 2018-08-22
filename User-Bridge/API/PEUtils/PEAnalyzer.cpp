#include "PEAnalyzer.h"

#define RELOCS_OFFSET_MASK 0b0000111111111111 /* Младшие 12 бит */ 

#define FORCED_FILE_ALIGNMENT		0x200
#define MINIMAL_SECTION_ALIGNMENT	0x1000

size_t inline AlignDown(size_t Value, size_t Factor) {
    return Value & ~(Factor - 1);
}

size_t inline AlignUp(size_t Value, size_t Factor) {
    return AlignDown(Value - 1, Factor) + Factor;
}

SIZE_T PEAnalyzer::Rva2Offset(SIZE_T Rva) const {
    if (!IsRawModule) return Rva;
/*
    Offset = SectionRAW + (RVA - SectionRVA)
    1. Находим, какой секции принадлежит RVA
    2. Вычисляем смещение от начала секции
    3. Прибавляем смещение к физическому адресу секции в файле
*/
    for (const auto& Section : Sections) {
        SIZE_T SectionBase, SectionSize, SectionOffset;
        if (NeedToAlign) {
            SectionBase = AlignDown((SIZE_T)Section.OffsetInMemory, SectionAlignment);
            SIZE_T AlignedFileSize, AlignedSectionSize;
            AlignedFileSize		= AlignUp(Section.SizeOnDisk, FileAlignment);
            AlignedSectionSize	= AlignUp(Section.SizeInMemory, SectionAlignment);
            SectionSize			= AlignedFileSize > AlignedSectionSize ? AlignedSectionSize : AlignedFileSize;
            SectionOffset		= AlignDown(Section.OffsetInFile, FORCED_FILE_ALIGNMENT);
        } else {
            SectionBase = (SIZE_T)Section.OffsetInMemory;
            SectionSize = Section.SizeOnDisk > Section.SizeInMemory ? Section.SizeInMemory : Section.SizeOnDisk;
            SectionOffset = Section.OffsetInFile;
        }

        if ((Rva >= SectionBase) && (Rva < SectionBase + SectionSize)) {
            return (SectionOffset + (Rva - SectionBase));
        }
    }

    return 0;
}

void PEAnalyzer::FillSectionsInfo() {
    // Собираем инфу о секциях:
    Sections.clear();
    WORD NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    for (unsigned short i = 0; i < NumberOfSections; i++, SectionHeader++) {
        SECTION_INFO SectionInfo;
        SectionInfo.OffsetInMemory = SectionHeader->VirtualAddress;
        SectionInfo.OffsetInFile = SectionHeader->PointerToRawData;
        SectionInfo.SizeInMemory = SectionHeader->Misc.VirtualSize;
        SectionInfo.SizeOnDisk = SectionHeader->SizeOfRawData;
        SectionInfo.Characteristics = SectionHeader->Characteristics;
        SectionInfo.NumberOfRelocs = SectionHeader->NumberOfRelocations;
        memcpy(&SectionInfo.Name, &SectionHeader->Name, SEC_NAME_SIZE);
        SectionInfo.Name[SEC_NAME_SIZE] = NULL;
        Sections.push_back(SectionInfo);
    }
}

void PEAnalyzer::FillRelocsInfo() {
    // Собираем инфу о релоках:
    Relocs.clear();
    PIMAGE_DATA_DIRECTORY RelocsDir =
        (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (RelocsDir->Size == 0) return;

    PIMAGE_BASE_RELOCATION Relocs = (PIMAGE_BASE_RELOCATION)((PBYTE)LocalBase + Rva2Offset(RelocsDir->VirtualAddress));
    PIMAGE_BASE_RELOCATION RelocsFinalAddress = (PIMAGE_BASE_RELOCATION)((PBYTE)Relocs + RelocsDir->Size);
    while (Relocs < RelocsFinalAddress) {
        DWORD RelocsRva = Relocs->VirtualAddress;

        DWORD RelocsCount = (Relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD RelocEntry = (PWORD)((PBYTE)Relocs + sizeof(IMAGE_BASE_RELOCATION));
        for (unsigned int i = 0; i < RelocsCount; i++, RelocEntry++) {
            WORD Reloc = *RelocEntry;
            RELOC_INFO RelocInfo;
            RelocInfo.Rva = RelocsRva + (Reloc & RELOCS_OFFSET_MASK);
            RelocInfo.Type = (BYTE)(Reloc >> 12);
            this->Relocs.push_back(RelocInfo);
        }

        Relocs = (PIMAGE_BASE_RELOCATION)((PBYTE)Relocs + Relocs->SizeOfBlock);
    }
}

void PEAnalyzer::FillImportsSet(
    PIMAGE_THUNK_DATA Thunk, 
    PIMAGE_THUNK_DATA OriginalThunk, 
    OUT IMPORTS_SET& ImportsSet
) {
    ImportsSet.clear();
    while (Thunk->u1.AddressOfData) {
        PIMAGE_IMPORT_BY_NAME NamedImport = (PIMAGE_IMPORT_BY_NAME)((PBYTE)LocalBase + Rva2Offset(OriginalThunk->u1.AddressOfData));

        static const SIZE_T OrdinalPresentMask = (SIZE_T)0x80 << (SIZE_T)((sizeof(SIZE_T) - 1) * 8);
        static const SIZE_T OrdinalMask = OrdinalPresentMask - 1;

        IMPORT_INFO ImportInfo;
        ImportInfo.FT = (PVOID)Thunk->u1.Function;
        ImportInfo.OFT = (PVOID)OriginalThunk->u1.Function;
        ImportInfo.IsOrdinalImport = ((SIZE_T)ImportInfo.OFT & OrdinalPresentMask) == OrdinalPresentMask;
        if (ImportInfo.IsOrdinalImport) {
            ImportInfo.Ordinal = (SIZE_T)ImportInfo.OFT & OrdinalMask;
            ImportInfo.Hint = 0;
        }
        else {
            ImportInfo.Ordinal = 0;
            ImportInfo.Hint = NamedImport->Hint;
            ImportInfo.Name = NamedImport->Name;
        }
        ImportsSet.push_back(ImportInfo);

        Thunk++;
        OriginalThunk++;
    }
}

void PEAnalyzer::FillImportsInfo() {
    // Парсим таблицу импорта:
    Imports.clear();
    PIMAGE_DATA_DIRECTORY ImportDir =
        (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (ImportDir->Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR Imports = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)LocalBase + Rva2Offset(ImportDir->VirtualAddress));
    while (Imports->FirstThunk != 0) {
        LPCSTR LibraryName = (LPCSTR)((PBYTE)LocalBase + Rva2Offset(Imports->Name));

        IMPORTS_SET ImportsSet;

        PIMAGE_THUNK_DATA Thunk = (PIMAGE_THUNK_DATA)((PBYTE)LocalBase + Rva2Offset(Imports->FirstThunk));
        PIMAGE_THUNK_DATA OriginalThunk = (PIMAGE_THUNK_DATA)((PBYTE)LocalBase + Rva2Offset(Imports->OriginalFirstThunk));
        FillImportsSet(Thunk, OriginalThunk, ImportsSet);

        this->Imports.emplace(LibraryName, ImportsSet);
        Imports++;
    }
}

void PEAnalyzer::FillDelayedImportsInfo() {
    // Парсим таблицу отложенного импорта:
    DelayedImports.clear();
    PIMAGE_DATA_DIRECTORY DelayedImportDir =
        (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

    if (DelayedImportDir->Size == 0) return;

    PIMAGE_DELAYLOAD_DESCRIPTOR DelayedImports =
        (PIMAGE_DELAYLOAD_DESCRIPTOR)((PBYTE)LocalBase + Rva2Offset(DelayedImportDir->VirtualAddress));
    while (DelayedImports->DllNameRVA != 0) {
        LPCSTR LibraryName = (LPCSTR)((PBYTE)LocalBase + Rva2Offset(DelayedImports->DllNameRVA));

        DELAYED_IMPORT_INFO DelayedImportInfo;
        DelayedImportInfo.Attributes = DelayedImports->Attributes.AllAttributes;
        DelayedImportInfo.hModule = *(HMODULE*)((PBYTE)LocalBase + Rva2Offset(DelayedImports->ModuleHandleRVA));
        DelayedImportInfo.DllName = LibraryName;

        PIMAGE_THUNK_DATA Thunk = (PIMAGE_THUNK_DATA)((PBYTE)LocalBase + Rva2Offset(DelayedImports->ImportAddressTableRVA));
        PIMAGE_THUNK_DATA OriginalThunk = (PIMAGE_THUNK_DATA)((PBYTE)LocalBase + Rva2Offset(DelayedImports->ImportNameTableRVA));
        FillImportsSet(Thunk, OriginalThunk, DelayedImportInfo.Imports);

        this->DelayedImports.push_back(DelayedImportInfo);
        DelayedImports++;
    }
}

void PEAnalyzer::FillExportsInfo() {
    // Парсим экспорты:
    Exports.TimeStamp = 0;
    Exports.NumberOfNames = 0;

    Exports.Name.clear();
    Exports.Exports.clear();
    PIMAGE_DATA_DIRECTORY ExportDir =
        (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDir->Size == 0) return;
    
    PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)LocalBase + Rva2Offset(ExportDir->VirtualAddress));

    this->Exports.TimeStamp = Exports->TimeDateStamp;
    this->Exports.NumberOfNames = Exports->NumberOfNames;
    this->Exports.NumberOfFunctions = Exports->NumberOfFunctions;
    this->Exports.Name = (LPCSTR)((PBYTE)LocalBase + Rva2Offset(Exports->Name));

    PWORD OrdinalsArray = (PWORD)((PBYTE)LocalBase + Rva2Offset(Exports->AddressOfNameOrdinals));

    PDWORD NamesArray = (PDWORD)((PBYTE)LocalBase + Rva2Offset(Exports->AddressOfNames));
    PDWORD FunctionsArray = (PDWORD)((PBYTE)LocalBase + Rva2Offset(Exports->AddressOfFunctions));

    DWORD OrdinalBase = Exports->Base;

    std::unordered_map<WORD, unsigned int> OrdinalsMap; // Ordinal -> Ordinal index
    OrdinalsMap.reserve(Exports->NumberOfNames);
    for (unsigned int NameNumber = 0; NameNumber < Exports->NumberOfNames; NameNumber++) {
        OrdinalsMap.emplace(*(OrdinalsArray + NameNumber), NameNumber);
    }

    for (unsigned int FunctionNumber = 0; FunctionNumber < Exports->NumberOfFunctions; FunctionNumber++) {
        DWORD FunctionAddress = *(FunctionsArray + FunctionNumber);

        EXPORT_INFO ExportInfo;
        ExportInfo.VA = (PBYTE)LocalBase + FunctionAddress;
        ExportInfo.RVA = FunctionAddress;
        ExportInfo.Ordinal = Exports->Base + FunctionNumber;

        auto OrdinalEntry = OrdinalsMap.find(FunctionNumber);
        ExportInfo.OrdinalExport = OrdinalEntry == OrdinalsMap.end();
        if (!ExportInfo.OrdinalExport) {
            unsigned int NameNumber = OrdinalEntry->second;
            LPCSTR FunctionName = (LPCSTR)((PBYTE)LocalBase + Rva2Offset(*(NamesArray + NameNumber)));
            ExportInfo.Name = FunctionName;
        }

        this->Exports.Exports.push_back(ExportInfo);
    }
}

PEAnalyzer::PEAnalyzer() {
    Clear();
}

PEAnalyzer::PEAnalyzer(HMODULE hModule, BOOL RawModule) {
    LoadModule(hModule, RawModule);
}

PEAnalyzer::~PEAnalyzer() {
    Clear();
}

BOOL PEAnalyzer::LoadModule(HMODULE hModule, BOOL RawModule) {
    Clear();

    if (hModule == NULL) return FALSE;

    IsRawModule = RawModule;

    DosHeader = (PIMAGE_DOS_HEADER)hModule;
    NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + DosHeader->e_lfanew);

    if (!ValidatePESignatures()) {
        Clear();
        return FALSE;
    }

    OptionalHeader = &NtHeaders->OptionalHeader;

#ifdef _WIN64
    if (OptionalHeader->Magic != PE64_SIGNATURE)
        throw std::exception("PE image must be 64-bit!");
#elif _WIN32
    if (OptionalHeader->Magic != PE32_SIGNATURE)
        throw std::exception("PE image must be 32-bit!");
#endif

    ImageSize = OptionalHeader->SizeOfImage;

    //LocalBase = !RawModule ? hModule : (PVOID)OptionalHeader->ImageBase;
    LocalBase = hModule;

    ImageBase = (PVOID)OptionalHeader->ImageBase;
    EntryPoint = (PBYTE)ImageBase + OptionalHeader->AddressOfEntryPoint;

    FileAlignment = OptionalHeader->FileAlignment;
    SectionAlignment = OptionalHeader->SectionAlignment;
    NeedToAlign = SectionAlignment >= MINIMAL_SECTION_ALIGNMENT;

    FillSectionsInfo();
    FillRelocsInfo();
    FillImportsInfo();
    FillDelayedImportsInfo();
    FillExportsInfo();

    return TRUE;
}

void PEAnalyzer::Clear() {
    IsRawModule = FALSE;
    IsValidPESignatures = FALSE;
    DosHeader = NULL;
    NtHeaders = NULL;
    OptionalHeader = NULL;
    LocalBase = NULL;
    ImageBase = NULL;
    EntryPoint = NULL;
    NeedToAlign = FALSE;
    FileAlignment = 0;
    SectionAlignment = 0;
    Sections.clear();
    Relocs.clear();
    Imports.clear();
    DelayedImports.clear();
    Exports.TimeStamp = 0;
    Exports.NumberOfNames = 0;
    Exports.NumberOfFunctions = 0;
    Exports.Name.clear();
    Exports.Exports.clear();
}

BOOL PEAnalyzer::ValidatePESignatures() {
    return IsValidPESignatures = (DosHeader->e_magic == MZ_SIGNATURE) && (NtHeaders->Signature == PE_SIGNATURE);
}