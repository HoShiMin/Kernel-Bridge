#pragma once

/*
    [KM] Dependencies:
     - wdm.h/fltKernel.h
     - ntstrsafe.h
     - stdarg.h
    [UM] Dependencies:
     - Windows.h
     - cstdarg
*/

#ifndef _NTDDK_
#pragma comment(lib, "ntdll.lib")
#endif

extern "C"
{
    int __cdecl _vsnprintf_s(char* dest, size_t size, size_t max_count, const char* format, va_list args);
    int __cdecl _vsnwprintf_s(wchar_t* dest, size_t size, size_t max_count, const wchar_t* format, va_list args);
}

template<typename TChar> class String {
private:
    static const TChar NullChar = 0;

    // Small string optimization (using stack memory for small strings):
    static constexpr unsigned char SSO_SIZE = 32;
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) TChar SsoBuffer[SSO_SIZE];

    static constexpr unsigned short AllocationGranularity = 64;

    using STRING_INFO = struct {
        TChar* Buffer;
        size_t Length; // Symbols count without null-terminator
        size_t BufferSize; // Buffer size in bytes
        BOOLEAN SsoUsing;
    };

    STRING_INFO Data;

    static inline VOID SetupSso(OUT STRING_INFO* StringInfo, const TChar* SsoBuffer) {
        StringInfo->Buffer = const_cast<TChar*>(SsoBuffer);
        StringInfo->Length = 0;
        StringInfo->BufferSize = SSO_SIZE * sizeof(TChar);
        StringInfo->SsoUsing = TRUE;
        StringInfo->Buffer[0] = NullChar;
        StringInfo->Buffer[SSO_SIZE - 1] = NullChar;
    }

    static inline TChar* StrAllocMem(size_t Bytes) {
#ifdef _NTDDK_
#ifdef POOL_NX_OPTIN
        return static_cast<TChar*>(ExAllocatePoolWithTag(ExDefaultNonPagedPoolType, Bytes, StrPoolTag));
#else
        return static_cast<TChar*>(ExAllocatePoolWithTag(NonPagedPool, Bytes, StrPoolTag));
#endif
#else
        return reinterpret_cast<TChar*>(new BYTE[Bytes]);
#endif
    }

    static inline VOID StrFreeMem(TChar* Memory) {
#ifdef _NTDDK_
        ExFreePoolWithTag(Memory, StrPoolTag);
#else
        delete[] Memory;
#endif
    }

    static bool Alloc(OUT STRING_INFO* StringInfo, size_t Characters) {
        if (!StringInfo || !Characters) return false;
        *StringInfo = {};
        size_t Size = (Characters + 1) * sizeof(TChar); // Null-terminated buffer
        Size = ((Size / AllocationGranularity) + 1) * AllocationGranularity;
        TChar* Buffer = StrAllocMem(Size);
        if (!Buffer) return false;
        Buffer[0] = NullChar;
        Buffer[Characters] = NullChar;
        StringInfo->Buffer = Buffer;
        StringInfo->Length = Characters;
        StringInfo->BufferSize = Size;
        StringInfo->SsoUsing = FALSE;
        return true;
    }

    static VOID Free(IN OUT STRING_INFO* StringInfo) {
        if (StringInfo && StringInfo->Buffer && !StringInfo->SsoUsing) {
            StrFreeMem(StringInfo->Buffer);
        }
    }

    static VOID Copy(OUT TChar* Dest, const IN TChar* Src, size_t Characters, bool Terminate = true) {
        if (!Dest || !Src || !Characters) return;
        RtlCopyMemory(Dest, Src, Characters * sizeof(TChar));
        if (Terminate) Dest[Characters] = NullChar;
    }

    static VOID CopyCat(OUT TChar* Dest, const IN TChar* First, size_t FirstLength, const IN TChar* Second, size_t SecondLength) {
        if (!Dest) return;
        if (First && FirstLength) {
            RtlCopyMemory(Dest, First, FirstLength * sizeof(TChar));
            Dest += FirstLength;
        }
        if (Second && SecondLength) {
            RtlCopyMemory(Dest, Second, SecondLength * sizeof(TChar));
            Dest += SecondLength;
        }
        *Dest = NullChar;
    }

    bool Concat(const IN TChar* Str) {
        return Concat(Str, Length(Str));
    }

    bool Concat(const IN TChar* Str, size_t StrLength) {
        if (!StrLength) return true;
        Resize(Data.Length + StrLength);
        Copy(&Data.Buffer[Data.Length - StrLength], Str, StrLength);
        return true;
    }

    bool Concat(const IN STRING_INFO* StringInfo) {
        return Concat(StringInfo->Buffer, StringInfo->Length);
    }

    String(const IN STRING_INFO* StringInfo) : String() {
        if (StringInfo->SsoUsing) {
            Copy(SsoBuffer, StringInfo->Buffer, StringInfo->Length);
            SetupSso(&Data, SsoBuffer);
            Data.Length = StringInfo->Length;
        } else {
            Data = *StringInfo;
            // Check whether we can use SSO:
            if (Data.Length < SSO_SIZE) {
                SetupSso(&Data, SsoBuffer);
                Data.Length = StringInfo->Length;
                Copy(SsoBuffer, StringInfo->Buffer, Data.Length);
            }
        }
        
    }

public:

#ifdef _NTDDK_
    static constexpr ULONG StrPoolTag = 'RTS_';
#endif

    String() {
        SetupSso(&Data, SsoBuffer);
    };
    ~String() {
        Free(&Data);
    }
    String(const TChar* Str) : String(Str, Length(Str)) {
    }
    String(const TChar* Str, size_t StrLength) : String() {
        if (StrLength < SSO_SIZE || Alloc(&Data, StrLength))
            Copy(Data.Buffer, Str, StrLength);

        Data.Length = StrLength;
    }
    String(const String& Str) : String() {
        if (Str.Data.Length < SSO_SIZE || Alloc(&Data, Str.Data.Length))
            Copy(Data.Buffer, Str.Data.Buffer, Str.Data.Length);

        Data.Length = Str.Data.Length;
    }
    String(String&& Str) noexcept : String() {
        if (Str.Data.SsoUsing || Str.Data.Length < SSO_SIZE) {
            Copy(Data.Buffer, Str.Data.Buffer, Str.Data.Length);
        } else {
            Data = Str.Data;    
        }
        Data.Length = Str.Data.Length;
        Str.Data = {};
    }

    String operator + (const TChar* Str) {
        if (!Str) return *this;

        size_t StrLength = Length(Str);
        if (!StrLength) return *this;

        size_t SummaryLength = Data.Length + StrLength;

        STRING_INFO StringInfo = {};
        if (!Alloc(&StringInfo, SummaryLength)) 
            return *this;

        CopyCat(StringInfo.Buffer, Data.Buffer, Data.Length, Str, StrLength);
        StringInfo.Length = SummaryLength;

        return String(&StringInfo);
    }
    String operator + (String&& Str) {
        size_t StrLength = Str.GetLength();
        if (!StrLength) return *this;

        size_t SummaryLength = Data.Length + Str.Data.Length;

        STRING_INFO StringInfo = {};
        if (!Alloc(&StringInfo, SummaryLength)) 
            return *this;

        CopyCat(StringInfo.Buffer, Data.Buffer, Data.Length, Str.GetConstData(), StrLength);
        StringInfo.Length = SummaryLength;

        return String(&StringInfo);         
    }
    String operator + (const String& Str) {
        if (!Str.Data.Length) return *this;

        size_t SummaryLength = Data.Length + Str.Data.Length;

        STRING_INFO StringInfo = {};
        if (!Alloc(&StringInfo, SummaryLength)) 
            return *this;

        CopyCat(StringInfo.Buffer, Data.Buffer, Data.Length, Str.Data.Buffer, Str.Data.Length);
        StringInfo.Length = SummaryLength;

        return String(&StringInfo);        
    }
    friend String operator + (const TChar* Left, const String& Right) {
        if (!Left) return Right;

        size_t LeftLength = Length(Left);
        if (!LeftLength) return Right;

        size_t SummaryLength = Right.GetLength() + LeftLength;

        STRING_INFO StringInfo = {};
        if (!Alloc(&StringInfo, SummaryLength)) 
            return String(Left);

        CopyCat(StringInfo.Buffer, Left, LeftLength, Right.GetConstData(), Right.GetLength());
        StringInfo.Length = SummaryLength;

        return String(&StringInfo);  
    }

    String& operator += (const TChar* Str) {
        Concat(Str);
        return *this;
    }

    String& operator += (String&& Str) {
        Concat(&Str.Data);
        return *this;
    }

    String& operator += (const String& Str) {
        Concat(&Str.Data);
        return *this;
    }

    String& operator = (const TChar* Str) {
        size_t StrLength = Length(Str);
        Resize(StrLength);
        Copy(Data.Buffer, Str, StrLength);
        return *this;
    }
    String& operator = (const String& Str) {
        Resize(Str.Data.Length);
        Copy(Data.Buffer, Str.Data.Buffer, Str.Data.Length);
        return *this;
    }
    String& operator = (String&& Str) {
        Free(&Data);
        SetupSso(&Data, SsoBuffer);
        if (Str.Data.SsoUsing || Str.Data.Length < SSO_SIZE) {
            Copy(Data.Buffer, Str.Data.Buffer, Str.Data.Length);
        } else {
            Data = Str.Data;
        }
        Data.Length = Str.Data.Length;
        Str.Data = {};
        return *this;
    }

    bool operator == (const TChar* Str) {
        if (Data.Buffer == Str) return true;
        size_t StrLength = Length(Str);
        if (Data.Length != StrLength) return false;
        return RtlCompareMemory(Data.Buffer, Str, StrLength) == StrLength;
    }
    bool operator == (const String& String) {
        if (Data.Buffer == String.Data.Buffer) return true;
        if (Data.Length != String.Data.Length) return false;
        return RtlCompareMemory(Data.Buffer, String.Data.Buffer, Data.Length) == Data.Length;
    }

    bool operator != (const TChar* Str) {
        if (Data.Buffer == Str) return false;
        size_t StrLength = Length(Str);
        if (Data.Length != StrLength) return true;
        return RtlCompareMemory(Data.Buffer, Str, StrLength) != StrLength;
    }
    bool operator != (const String& String) {
        if (Data.Buffer == String.Data.Buffer) return false;
        if (Data.Length != String.Data.Length) return true;
        return RtlCompareMemory(Data.Buffer, String.Data.Buffer, Data.Length) != Data.Length;
    }

    inline operator const TChar* () const {
        return Data.Buffer;
    }

    inline operator TChar* () {
        return Data.Buffer;
    }

    inline TChar& operator [] (int Index) {
        return Data.Buffer[Index];
    }

    inline TChar operator [] (int Index) const {
        return Data.Buffer[Index];
    }

    static inline size_t Length(const TChar* String);

    inline size_t GetLength() const { return Data.Length; };
    inline size_t GetSize() const { return Data.BufferSize; }
    inline const TChar* GetConstData() const { return Data.Buffer ? Data.Buffer : &NullChar; }
    inline TChar* GetData() { return Data.Buffer ? Data.Buffer : NULL; };

    VOID Clear() {
        Free(&Data);
        SetupSso(&Data, SsoBuffer);
    }

    inline String<CHAR> GetAnsi() const;
    inline String<WCHAR> GetWide() const;

    inline String& ToLowerCase();
    inline String& ToUpperCase();

    inline String GetLowerCase() const {
        String Str(*this);
        Str.ToLowerCase();
        return Str;
    }
    inline String GetUpperCase() const {
        String Str(*this);
        Str.ToUpperCase();
        return Str;
    }

    static bool Matches(const TChar* Str, const TChar* Mask) {
        /* 
            Dr.Dobb's Algorithm:
            http://www.drdobbs.com/architecture-and-design/matching-wildcards-an-empirical-way-to-t/240169123?queryText=path%2Bmatches
        */

        const TChar* TameText = Str;
        const TChar* WildText = Mask;
        const TChar* TameBookmark = static_cast<TChar*>(0x00);
        const TChar* WildBookmark = static_cast<TChar*>(0x00);

        while (true) {
            if (*WildText == static_cast<TChar>('*')) {
                while (*(++WildText) == static_cast<TChar>('*')); // "xy" matches "x**y"
                if (!*WildText) return true; // "x" matches "*"
            
                if (*WildText != static_cast<TChar>('?')) {
                    while (*TameText != *WildText) {
                        if (!(*(++TameText)))
                            return false;  // "x" doesn't match "*y*"
                    }
                }

                WildBookmark = WildText;
                TameBookmark = TameText;
            }
            else if (*TameText != *WildText && *WildText != static_cast<TChar>('?')) {
                if (WildBookmark) {
                    if (WildText != WildBookmark) {
                        WildText = WildBookmark;

                        if (*TameText != *WildText) {
                            TameText = ++TameBookmark;
                            continue; // "xy" matches "*y"
                        }
                        else {
                            WildText++;
                        }
                    }

                    if (*TameText) {
                        TameText++;
                        continue; // "mississippi" matches "*sip*"
                    }
                }

                return false; // "xy" doesn't match "x"
            }

            TameText++;
            WildText++;

            if (!*TameText) {
                while (*WildText == static_cast<TChar>('*')) WildText++; // "x" matches "x*"

                if (!*WildText) return true; // "x" matches "x"
                return false; // "x" doesn't match "xy"
            }
        }
    }

    bool Matches(const TChar* Mask) {
        return Matches(Data.Buffer, Mask);
    }

    static inline const TChar* Find(const TChar* Str, const TChar* Substr, size_t Offset = 0);
    inline const TChar* Find(const TChar* Substring, size_t Offset = 0) const {
        if (Offset > Data.Length) return nullptr;
        return Find(Data.Buffer, Substring, Offset);
    }
    inline bool Contains(const TChar* Substring, size_t Offset = 0) const {
        return Find(Substring, Offset) != nullptr;
    }

#ifdef _AMD64_
    static constexpr size_t NoPos = ~0ULL;
#else
    static constexpr size_t NoPos = ~0UL;
#endif

    inline size_t Pos(const TChar* Substring, size_t Offset = 0, bool GetRelativePos = false) const {
        const TChar* SubstrAddr = Find(Substring, Offset);
        if (!SubstrAddr) return NoPos;
        size_t AbsPos = (reinterpret_cast<size_t>(SubstrAddr) - reinterpret_cast<size_t>(Data.Buffer)) / sizeof(TChar);
        return GetRelativePos ? AbsPos - Offset : AbsPos;
    }

    String& Delete(size_t Position, size_t Count, bool AutoShrink = false) {
        if (Position >= Data.Length) return *this;
        if (Position + Count >= Data.Length) {
            Data.Buffer[Position] = NullChar;
            Data.Length = Position;
        } else {
            Copy(&Data.Buffer[Position], &Data.Buffer[Position + Count], Data.Length - (Position + Count));
            Data.Length -= Count;
            Data.Buffer[Data.Length] = NullChar;
        }

        if (AutoShrink) Shrink();

        return *this;
    }

    String& Insert(size_t Position, const TChar* Insertion) {
        return Insert(Position, Insertion, Length(Insertion));
    }

    String& Insert(size_t Position, const String& Insertion) {
        return Insert(Position, Insertion.Data.Buffer, Insertion.Data.Length);
    }

    String& Insert(size_t Position, const String&& Insertion) {
        return Insert(Position, Insertion.Data.Buffer, Insertion.Data.Length);
    }

    String& Insert(size_t Position, const TChar* Insertion, size_t CharactersCount) {
        if (!CharactersCount) return *this;
        size_t SummaryLength = Data.Length + CharactersCount;
        size_t RequiredSize = (SummaryLength + 1) * sizeof(TChar);
        if (RequiredSize > Data.BufferSize) {
            STRING_INFO StringInfo = {};
            if (Alloc(&StringInfo, SummaryLength)) {
                Copy(StringInfo.Buffer, Data.Buffer, Position);
                Copy(&StringInfo.Buffer[Position], Insertion, CharactersCount);
                Copy(&StringInfo.Buffer[Position + CharactersCount], &Data.Buffer[Position], Data.Length - Position);
                Free(&Data);
                Data = StringInfo;
            }
        } else {
            Copy(&Data.Buffer[Position + CharactersCount], &Data.Buffer[Position], Data.Length - Position);
            Copy(&Data.Buffer[Position], Insertion, CharactersCount, false);
        }
        Data.Length += CharactersCount;
        return *this;
    } 

    String Substr(size_t Position, size_t CharactersCount = 0) const {
        if (!Data.Length || Position > Data.Length) return String();
        if (CharactersCount) {
            if (Position + CharactersCount > Data.Length) CharactersCount = Data.Length - Position;
            return String(&Data.Buffer[Position], CharactersCount);
        } else {
            return String(&Data.Buffer[Position]);
        }
    }

    String& TrimLeft(bool AutoShrink = false) {
        if (!Data.Length) return *this;
        size_t Symbol;
        for (Symbol = 0; Symbol < Data.Length; ++Symbol) {
            if (
                Data.Buffer[Symbol] != static_cast<TChar>(' ') &&
                Data.Buffer[Symbol] != static_cast<TChar>('\t')
            ) break;
        }

        if (Symbol == 0) return *this;
        
        size_t TrimmedLength = Data.Length - Symbol;

        if (!Data.SsoUsing && TrimmedLength < SSO_SIZE) {
            STRING_INFO StringInfo = {};
            SetupSso(&StringInfo, SsoBuffer);
            Copy(StringInfo.Buffer, &Data.Buffer[Symbol], TrimmedLength);
            StringInfo.Length = TrimmedLength;
            Free(&Data);
            Data = StringInfo;
            return *this;
        }

        Copy(Data.Buffer, &Data.Buffer[Symbol], TrimmedLength);
        Data.Length = TrimmedLength;

        if (AutoShrink) Shrink();
        return *this;
    }

    String& TrimRight(bool AutoShrink = false) {
        if (!Data.Length) return *this;
        size_t Symbol;
        for (Symbol = Data.Length - 1; Symbol >= 0; --Symbol) {
            if (
                Data.Buffer[Symbol] != static_cast<TChar>(' ') &&
                Data.Buffer[Symbol] != static_cast<TChar>('\t')
            ) break;
        }

        ++Symbol; // Set it to points to null-terminator
        Data.Buffer[Symbol] = NullChar;
        Data.Length = Symbol;

        if (!Data.SsoUsing && Data.Length < SSO_SIZE) {
            STRING_INFO StringInfo = {};
            SetupSso(&StringInfo, SsoBuffer);
            Copy(StringInfo.Buffer, Data.Buffer, Data.Length);
            StringInfo.Length = Data.Length;
            Free(&Data);
            Data = StringInfo;
            return *this;
        }

        if (AutoShrink) Shrink();
        return *this;
    }

    String& Trim(bool AutoShrink = false) {
        TrimLeft(false);
        TrimRight(false);
        if (AutoShrink) Shrink();
        return *this;
    }

    void Shrink() {
        if (Data.SsoUsing) return;
        size_t RequiredSize = ((((Data.Length + 1) * sizeof(TChar)) / AllocationGranularity) + 1) * AllocationGranularity;
        if (RequiredSize < Data.BufferSize) {
            STRING_INFO StringInfo = {};
            if (Data.Length < SSO_SIZE) {
                SetupSso(&StringInfo, SsoBuffer);
                Copy(StringInfo.Buffer, Data.Buffer, Data.Length);
                StringInfo.Length = Data.Length;
                Free(&Data);
                Data = StringInfo;
            } else {
                if (Alloc(&StringInfo, Data.Length)) {
                    Copy(StringInfo.Buffer, Data.Buffer, Data.Length);
                    Free(&Data);
                    Data = StringInfo;
                }
            }
        }
    }

    void Resize(size_t Characters, TChar Filler = 0, bool AutoShrink = false) {
        if (Characters == Data.Length) {
            if (AutoShrink) Shrink();
            return;
        }
        
        if (!Characters) {
            if (AutoShrink) {
                Clear();
            } else {
                Data.Buffer[0] = NullChar;
                Data.Length = 0;
            }
            return;
        }

        if (Characters > Data.Length) {
            size_t RequiredSize = (Characters + 1) * sizeof(TChar);
            if (RequiredSize <= Data.BufferSize) {
                if (Filler == 0)
                    RtlZeroMemory(&Data.Buffer[Data.Length], (Characters - Data.Length) * sizeof(TChar));
                else {
                    for (size_t Index = Data.Length; Index < Characters; ++Index)
                        Data.Buffer[Index] = Filler;
                }
                Data.Buffer[Characters] = NullChar;
                Data.Length = Characters;
                return;
            } 

            STRING_INFO StringInfo = {};            
            if (Alloc(&StringInfo, Characters)) {
                Copy(StringInfo.Buffer, Data.Buffer, Data.Length);
                if (Filler == 0)
                    RtlZeroMemory(&StringInfo.Buffer[Data.Length], (Characters - Data.Length) * sizeof(TChar));
                else {
                    for (size_t Index = Data.Length; Index < Characters; ++Index)
                        StringInfo.Buffer[Index] = Filler;
                }
                StringInfo.Buffer[Characters] = NullChar;
                StringInfo.Length = Characters;
                Free(&Data);
                Data = StringInfo;
            }
        } else {
            Data.Buffer[Characters] = NullChar;
            Data.Length = Characters;
        }
        if (AutoShrink) Shrink();
    }

    void Reserve(size_t Characters) {
        if (Characters == Data.Length) return;
        if (Characters < Data.Length) {
            Resize(Characters);
            return;
        }
        STRING_INFO StringInfo = {};
        if (Characters < SSO_SIZE) {
            if (Data.SsoUsing) return;
            SetupSso(&StringInfo, SsoBuffer);
            Copy(StringInfo.Buffer, Data.Buffer, Data.Length);
            Free(&Data);
            Data = StringInfo;
        } else {
            if (Alloc(&StringInfo, Characters)) {
                Copy(StringInfo.Buffer, Data.Buffer, Data.Length);
                Free(&Data);
                Data = StringInfo;
            }
        }
    }

    String& Replace(
        const TChar* Substr,
        const TChar* Replacer,
        bool SelectiveReplacement = false, // aXXabXXabc.Replace("a", "abc", true) == abcXXabcbXXabc
        unsigned int* ReplacementsCount = nullptr
    ) {
        unsigned int Replaced = 0;
        size_t SubstrLength = Length(Substr);
        size_t ReplacerLength = Length(Replacer);
        
        size_t Position = Pos(Substr);
        if (Position == NoPos) return *this;
        do {
            if (SelectiveReplacement)
                if (Pos(Replacer, Position) == Position) continue;
            Delete(Position, SubstrLength);
            Insert(Position, Replacer);
            Replaced++;
        } while ((Position = Pos(Substr, Position + ReplacerLength)) != NoPos);
    
        if (ReplacementsCount) *ReplacementsCount = Replaced;
        return *this;
    }

    VOID CopyTo(TChar* Buffer, size_t Characters) {
        if (Data.Length < Characters)
            Characters = Data.Length;
        RtlCopyMemory(Buffer, Data.Buffer, Characters * sizeof(TChar));
        Buffer[Characters] = 0x0000;
    }
};

class AnsiString : public String<CHAR> {
public:
    using String::String;
    AnsiString(PCANSI_STRING Ansi) : String(Ansi->Buffer, Ansi->Length / sizeof(CHAR)) {}
    AnsiString(const String& Str) : String(Str) {}
    AnsiString(String&& Str) : String(Str) {}
    AnsiString() : String() {}
};

class WideString : public String<WCHAR> {
public:
    using String::String;
    WideString(PCUNICODE_STRING Wide) : String(Wide->Buffer, Wide->Length / sizeof(WCHAR)) {}
    WideString(const String& Str) : String(Str) {}
    WideString(String&& Str) : String(Str) {}
    WideString() : String() {}
};

template<>
static inline size_t String<CHAR>::Length(const CHAR* String) {
    if (!String) return 0;
    return strlen(String);
}

template<>
static inline size_t String<WCHAR>::Length(const WCHAR* String) {
    if (!String) return 0;
    return wcslen(String);
}

template<>
inline String<CHAR> String<CHAR>::GetAnsi() const {
    return *this;
}

template<>
inline String<WCHAR> String<CHAR>::GetWide() const {
    ANSI_STRING AnsiString = {};
    RtlInitAnsiString(&AnsiString, Data.Buffer);
    UNICODE_STRING UnicodeString = {};
    RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
    String<WCHAR> Wide(UnicodeString.Buffer, UnicodeString.Length / sizeof(WCHAR));
    RtlFreeUnicodeString(&UnicodeString);
    return Wide;
}

template<>
inline String<CHAR> String<WCHAR>::GetAnsi() const {
    UNICODE_STRING UnicodeString = {};
    RtlInitUnicodeString(&UnicodeString, Data.Buffer);
    ANSI_STRING AnsiString = {};
    RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, TRUE);
    String<CHAR> Ansi(AnsiString.Buffer, AnsiString.Length / sizeof(CHAR));
    RtlFreeAnsiString(&AnsiString);
    return Ansi;
}

template<>
inline String<WCHAR> String<WCHAR>::GetWide() const {
    return *this;
}

template<>
inline String<CHAR>& String<CHAR>::ToLowerCase() {
    UNICODE_STRING UnicodeString;
    ANSI_STRING AnsiString;
    RtlInitAnsiString(&AnsiString, Data.Buffer);
    RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
    RtlDowncaseUnicodeString(&UnicodeString, &UnicodeString, FALSE);
    RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, FALSE);
    RtlFreeUnicodeString(&UnicodeString);
    return *this;
}

template<>
inline String<CHAR>& String<CHAR>::ToUpperCase() {
    UNICODE_STRING UnicodeString;
    ANSI_STRING AnsiString;
    RtlInitAnsiString(&AnsiString, Data.Buffer);
    RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
    RtlUpcaseUnicodeString(&UnicodeString, &UnicodeString, FALSE);
    RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, FALSE);
    RtlFreeUnicodeString(&UnicodeString);
    return *this;
}

template<>
inline String<WCHAR>& String<WCHAR>::ToLowerCase() {
    UNICODE_STRING UnicodeString;
    RtlInitUnicodeString(&UnicodeString, Data.Buffer);
    RtlDowncaseUnicodeString(&UnicodeString, &UnicodeString, FALSE);
    return *this;
}

template<>
inline String<WCHAR>& String<WCHAR>::ToUpperCase() {
    UNICODE_STRING UnicodeString;
    RtlInitUnicodeString(&UnicodeString, Data.Buffer);
    RtlUpcaseUnicodeString(&UnicodeString, &UnicodeString, FALSE);
    return *this;
}

template<>
inline const CHAR* String<CHAR>::Find(const CHAR* Str, const CHAR* Substr, size_t Offset) {
    return strstr(Str + Offset, Substr);
}

template<>
inline const WCHAR* String<WCHAR>::Find(const WCHAR* Str, const WCHAR* Substr, size_t Offset) {
    return wcsstr(Str + Offset, Substr);
}


inline String<CHAR> FormatAnsi(LPCSTR Format, ...) {
    va_list args;
    va_start(args, Format);
    constexpr int BufferSize = 64;
    CHAR Buffer[BufferSize];
    int characters = _vsnprintf_s(Buffer, BufferSize, BufferSize - 1, Format, args);
    if (characters != -1) return String<CHAR>(Buffer);
    String<CHAR> Result;
    Result.Resize(BufferSize * 2);
    while ((characters = _vsnprintf_s(
        Result.GetData(), 
        Result.GetLength() + 1, 
        Result.GetLength(), 
        Format, 
        args
    )) == -1) {
        Result.Resize(Result.GetLength() + BufferSize);
    }
    Result.Resize(characters);
    return Result;
}

inline String<WCHAR> FormatWide(LPCWSTR Format, ...) {
    va_list args;
    va_start(args, Format);
    constexpr int BufferSize = 64;
    WCHAR Buffer[BufferSize];
    int characters = _vsnwprintf_s(Buffer, BufferSize, BufferSize - 1, Format, args);
    if (characters != -1) return String<WCHAR>(Buffer);
    String<WCHAR> Result;
    Result.Resize(BufferSize * 2);
    while ((characters = _vsnwprintf_s(
        Result.GetData(), 
        Result.GetLength() + 1, 
        Result.GetLength(), 
        Format, 
        args
    )) == -1) {
        Result.Resize(Result.GetLength() + BufferSize);
    }
    Result.Resize(characters);
    return Result;
}