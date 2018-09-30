#include <windows.h>
#include <vector>
#include <string>
#include "SymParser.h"

// Using Wide-versions of DbgHelp functions:
#define DBGHELP_TRANSLATE_TCHAR

// Expose additional declarations from DbgHelp.h:
#define _NO_CVCONST_H 

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

SymParser::SymParser(OPTIONAL LPCWSTR SymbolsPath) 
    : Initialized(FALSE), hProcess(GetCurrentProcess()), ModuleBase(NULL) 
{
    Initialized = SymInitialize(
        hProcess, 
        SymbolsPath ? SymbolsPath : DefaultSymbolsPath, 
        FALSE
    );
}

SymParser::~SymParser() {
    if (Initialized) SymCleanup(hProcess);
}


BOOL SymParser::LoadModule(LPCWSTR ModulePath, OPTIONAL DWORD64 ImageBase, OPTIONAL DWORD ImageSize) {
    ModuleBase = SymLoadModuleEx(hProcess, NULL, ModulePath, NULL, ImageBase, ImageSize, NULL, 0);
    return ModuleBase != NULL;
}


std::wstring SymParser::GetSymName(ULONG Index, OPTIONAL OUT PBOOL Status) {
    LPCWSTR Name = NULL;
    if (SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_SYMNAME, &Name) && Name) {
        std::wstring SymName = Name;
        VirtualFree(const_cast<LPWSTR>(Name), 0, MEM_RELEASE);
        if (Status) *Status = TRUE;
        return SymName;
    }
    if (Status) *Status = FALSE;
    return L"";
}

std::wstring SymParser::GetSymTypeName(ULONG Index, OPTIONAL OUT PUINT64 BaseTypeSize, OPTIONAL OUT PBOOL Status) {
    if (!Index) return L"";
    
    UINT64 SymSize = GetSymSize(Index, Status);
    if (BaseTypeSize) *BaseTypeSize = SymSize;
    std::wstring TypeName = GetSymName(Index, Status);
    if (!TypeName.empty()) return TypeName;

    enum SymTagEnum Tag = GetSymTag(Index, Status);
    switch (Tag) {
    case SymTagBaseType: {
        enum SymParser::BasicType Type = GetSymBaseType(Index, Status);
        switch (Type) {
        case btNoType: 
            TypeName = L"NO_TYPE";
            break;
        case btVoid:
            TypeName = L"VOID";
            break;
        case btChar:
            TypeName = L"CHAR";
            break;
        case btWChar:
            TypeName = L"WCHAR";
            break;
        case btInt:
            TypeName = SymSize == sizeof(INT64) ? L"INT64" : L"INT";
            break;
        case btUInt:
            TypeName = SymSize == sizeof(UINT64) ? L"UINT64" : L"UINT";
            break;
        case btFloat:
            TypeName = L"float";
            break;
        case btBCD:
            TypeName = L"BCD"; // Binary-coded decimal
            break;
        case btBool:
            TypeName = L"BOOL";
            break;
        case btLong:
            TypeName = SymSize == sizeof(LONGLONG) ? L"LONGLONG" : L"LONG";
            break;
        case btULong:
            TypeName = SymSize == sizeof(ULONGLONG) ? L"ULONGLONG" : L"ULONG";
            break;
        case btCurrency:
            TypeName = L"CurrencyType"; // ???
            break;
        case btDate:
            TypeName = L"DateType"; // ???
            break;
        case btVariant:
            TypeName = L"VariantType"; // ???
            break;
        case btComplex:
            TypeName = L"ComplexType"; // ???
            break;
        case btBit:
            TypeName = L"Bit";
            break;
        case btBSTR:
            TypeName = L"BSTR"; // Binary string
            break;
        case btHresult:
            TypeName = L"HRESULT";
            break;
        }
        break;
    }
    case SymTagPointerType: {
        ULONG Type = GetSymType(Index, Status);
        TypeName = GetSymTypeName(Type, BaseTypeSize, Status) + L"*";
        break;
    }
    case SymTagArrayType: {
        ULONG Type = GetSymArrayTypeId(Index, Status);
        TypeName = GetSymTypeName(Type, BaseTypeSize, Status);
        break;
    }
    default: {
        ULONG Type = GetSymType(Index, Status);
        TypeName = GetSymTypeName(Type, BaseTypeSize, Status);
    }
    }

    return TypeName;
}

UINT64 SymParser::GetSymSize(ULONG Index, OPTIONAL OUT PBOOL Status) {
    UINT64 Size = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_LENGTH, &Size);
    if (Status) *Status = SymStatus;
    return Size;
}

ULONG SymParser::GetSymOffset(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG Offset = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_OFFSET, &Offset);
    if (Status) *Status = SymStatus;
    return Offset;
}

ULONG SymParser::GetSymAddressOffset(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG Offset = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_ADDRESSOFFSET, &Offset);
    if (Status) *Status = SymStatus;
    return Offset;
}

ULONG SymParser::GetSymBitPosition(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG BitPosition = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_BITPOSITION, &BitPosition);
    if (Status) *Status = SymStatus;
    return BitPosition;
}

ULONG SymParser::GetSymTypeId(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG TypeId = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_TYPEID, &TypeId);
    if (Status) *Status = SymStatus;
    return TypeId;
}

ULONG SymParser::GetSymArrayTypeId(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG TypeId = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_ARRAYINDEXTYPEID, &TypeId);
    if (Status) *Status = SymStatus;
    return TypeId;
}

enum SymTagEnum SymParser::GetSymTag(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG Tag = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_SYMTAG, &Tag);
    if (Status) *Status = SymStatus;
    return static_cast<enum SymTagEnum>(Tag);
}

enum SymParser::BasicType SymParser::GetSymType(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG Type = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_TYPE, &Type);
    if (Status) *Status = SymStatus;
    return static_cast<enum BasicType>(Type);
}

enum SymParser::BasicType SymParser::GetSymBaseType(ULONG Index, OPTIONAL OUT PBOOL Status) {
    ULONG BasicType = 0;
    BOOL SymStatus = SymGetTypeInfo(hProcess, ModuleBase, Index, TI_GET_BASETYPE, &BasicType);
    if (Status) *Status = SymStatus;
    return static_cast<enum BasicType>(BasicType);
}


BOOL SymParser::DumpSymbol(LPCWSTR SymbolName, OUT SYM_INFO& SymInfo) {
    SymInfo = {};

    // Obtaining root symbol:
    const ULONG SymNameLength = 128;
    const ULONG SymInfoSize = sizeof(SYMBOL_INFO) + SymNameLength * sizeof(WCHAR);
    std::vector<BYTE> RootSymbolInfoBuffer(SymInfoSize);
    auto RootSymbolInfo = reinterpret_cast<PSYMBOL_INFO>(&RootSymbolInfoBuffer[0]);
    RootSymbolInfo->SizeOfStruct = SymInfoSize;
    BOOL Status = SymGetTypeFromName(hProcess, ModuleBase, SymbolName, RootSymbolInfo);
    if (!Status) return FALSE;

    ULONG RootIndex = RootSymbolInfo->Index;

    SymInfo.Name = GetSymName(RootIndex);
    SymInfo.Size = GetSymSize(RootIndex);
    SymInfo.Offset = GetSymOffset(RootIndex, &Status);
    if (!Status) SymInfo.Offset = GetSymAddressOffset(RootIndex);

    // Obtaining root symbol children count:
    ULONG ChildrenCount = 0;
    Status = SymGetTypeInfo(hProcess, ModuleBase, RootIndex, TI_GET_CHILDRENCOUNT, &ChildrenCount);
    if (!Status) return FALSE;

    SymInfo.Name = SymbolName;
    SymGetTypeInfo(hProcess, ModuleBase, RootIndex, TI_GET_LENGTH, &SymInfo.Size);

    if (ChildrenCount) {
        // Obtaining children indices:
        std::vector<BYTE> FindChildrenParamsBuffer(sizeof(TI_FINDCHILDREN_PARAMS) + ChildrenCount * sizeof(ULONG));
        auto Children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(&FindChildrenParamsBuffer[0]);
        Children->Count = ChildrenCount;
        Status = SymGetTypeInfo(hProcess, ModuleBase, RootIndex, TI_FINDCHILDREN, Children);
        if (!Status) return FALSE;

        for (unsigned int i = 0; i < ChildrenCount; i++) {
            SYM_CHILD_ENTRY Entry = {};
            ULONG ChildIndex = Children->ChildId[i];
            ULONG TypeId = GetSymTypeId(ChildIndex);
            Entry.Name = GetSymName(ChildIndex);
            Entry.Size = GetSymSize(TypeId);
            Entry.Offset = GetSymOffset(ChildIndex);
            Entry.BitPosition = GetSymBitPosition(ChildIndex, &Entry.IsBitField);
            UINT64 BaseTypeSize = 0;
            Entry.TypeName = GetSymTypeName(TypeId, &BaseTypeSize);
            Entry.ElementsCount = BaseTypeSize != 0 ? Entry.Size / BaseTypeSize : 1;

            if (Entry.Name.empty()) Entry.Name = L"UNKNOWN_NAME";
            if (Entry.TypeName.empty()) Entry.TypeName = L"UNKNOWN_TYPE";

            SymInfo.Entries.emplace_back(Entry);
        }
    }

    return TRUE;
}