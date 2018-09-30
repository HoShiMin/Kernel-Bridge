#pragma once

class SymParser {
private:
    // From cvconst.h:
    enum BasicType {   
        btNoType   = 0,  
        btVoid     = 1,  
        btChar     = 2,  
        btWChar    = 3,  
        btInt      = 6,  
        btUInt     = 7,  
        btFloat    = 8,  
        btBCD      = 9,  
        btBool     = 10,  
        btLong     = 13,  
        btULong    = 14,  
        btCurrency = 25,  
        btDate     = 26,  
        btVariant  = 27,  
        btComplex  = 28,  
        btBit      = 29,  
        btBSTR     = 30,  
        btHresult  = 31  
    };

    BOOL Initialized;
    HANDLE hProcess;
    DWORD64 ModuleBase;
    LPCWSTR DefaultSymbolsPath = L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";

    std::wstring GetSymName(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    std::wstring GetSymTypeName(ULONG Index, OPTIONAL OUT PUINT64 BaseTypeSize = NULL, OPTIONAL OUT PBOOL Status = NULL);
    UINT64 GetSymSize(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    ULONG GetSymOffset(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    ULONG GetSymAddressOffset(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    ULONG GetSymBitPosition(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    ULONG GetSymTypeId(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    ULONG GetSymArrayTypeId(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    enum SymTagEnum GetSymTag(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    enum BasicType GetSymType(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
    enum BasicType GetSymBaseType(ULONG Index, OPTIONAL OUT PBOOL Status = NULL);
public:
    using SYM_CHILD_ENTRY = struct {
        std::wstring Name;
        std::wstring TypeName;
        UINT64 ElementsCount;
        UINT64 Size;
        ULONG Offset;
        BOOL IsBitField;
        ULONG BitPosition;
    };
    using SYM_INFO = struct {
        std::wstring Name;
        UINT64 Size;
        ULONG Offset;
        std::vector<SYM_CHILD_ENTRY> Entries;
    };

    SymParser(OPTIONAL LPCWSTR SymbolsPath = NULL);
    ~SymParser();

    BOOL IsInitialized() const { return Initialized; }

    // Load symbols for specified module (*.exe/*.dll/*.sys etc.):
    BOOL LoadModule(LPCWSTR ModulePath, OPTIONAL DWORD64 ImageBase = NULL, OPTIONAL DWORD ImageSize = 0);

    BOOL DumpSymbol(LPCWSTR SymbolName, OUT SYM_INFO& SymInfo);
};