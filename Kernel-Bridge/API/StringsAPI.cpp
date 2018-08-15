#include "StringsAPI.h"

template<>
String<CHAR>::String(POOL_TYPE PoolType) : Data({ 0 }) {
	_PoolType = PoolType;
	AllocateString("", &Data);
}

template<>
String<WCHAR>::String(POOL_TYPE PoolType) : Data({ 0 }) {
	_PoolType = PoolType;
	AllocateString(L"", &Data);
}


template<>
static inline SIZE_T String<CHAR>::Length(const CHAR* String) {
	return strlen(String);
}

template<>
static inline SIZE_T String<WCHAR>::Length(const WCHAR* String) {
	return wcslen(String);
}



template<>
VOID String<CHAR>::AllocateString(const CHAR* String, OUT PSTRING_INFO StringInfo) {
	AllocateString(strlen(String), StringInfo, _PoolType);
}

template<>
VOID String<WCHAR>::AllocateString(const WCHAR* String, OUT PSTRING_INFO StringInfo) {
	AllocateString(wcslen(String), StringInfo, _PoolType);
}

template<>
VOID String<CHAR>::CopyString(CHAR* Dest, const CHAR* Src) {
	strcpy(Dest, Src);
}

template<>
VOID String<WCHAR>::CopyString(WCHAR* Dest, const WCHAR* Src) {
	wcscpy(Dest, Src);
}

template<>
VOID String<CHAR>::CopyString(CHAR* Dest, const CHAR* Src, SIZE_T SymbolsCount, BOOLEAN NullTerminate) {
	strncpy(Dest, Src, SymbolsCount);
	if (NullTerminate) *(Dest + SymbolsCount) = (CHAR)0x00;
}

template<>
VOID String<WCHAR>::CopyString(WCHAR* Dest, const WCHAR* Src, SIZE_T SymbolsCount, BOOLEAN NullTerminate) {
	wcsncpy(Dest, Src, SymbolsCount);
	if (NullTerminate) *(Dest + SymbolsCount) = (WCHAR)0x0000;
}

template<>
VOID String<CHAR>::ConcatString(CHAR* Left, const CHAR* Right) {
	strcat(Left, Right);
}

template<>
VOID String<WCHAR>::ConcatString(WCHAR* Left, const WCHAR* Right) {
	wcscat(Left, Right);
}

template<>
BOOLEAN String<CHAR>::CompareStrings(const CHAR* Left, const CHAR* Right) {
	return strcmp(Left, Right) == 0;
}

template<>
BOOLEAN String<WCHAR>::CompareStrings(const WCHAR* Left, const WCHAR* Right) {
	return wcscmp(Left, Right) == 0;
}



template<>
String<CHAR>::String(IN PCANSI_STRING AnsiString, POOL_TYPE PoolType) {
	if (!AnsiString || !AnsiString->Buffer || !AnsiString->Length || !AnsiString->MaximumLength) {
		String::String(PoolType);
	}
	else {
		_PoolType = PoolType;
		unsigned int SymbolsCount = AnsiString->Length / sizeof(CHAR);
		AllocateString(SymbolsCount, &Data, PoolType);
		CopyString(Data.Buffer, AnsiString->Buffer, SymbolsCount);
	}
}

template<>
String<CHAR>::String(IN PCUNICODE_STRING UnicodeString, POOL_TYPE PoolType) {
	String::String(String<WCHAR>(UnicodeString, PoolType).GetAnsi());
}

template<>
String<WCHAR>::String(IN PCANSI_STRING AnsiString, POOL_TYPE PoolType) {
	String::String(String<CHAR>(AnsiString, PoolType).GetWide());
}

template<>
String<WCHAR>::String(IN PCUNICODE_STRING UnicodeString, POOL_TYPE PoolType) {
	if (!UnicodeString || !UnicodeString->Buffer || !UnicodeString->Length || !UnicodeString->MaximumLength) {
		String::String(PoolType);
	}
	else {
		_PoolType = PoolType;
		unsigned int SymbolsCount = UnicodeString->Length / sizeof(WCHAR);
		AllocateString(SymbolsCount, &Data, PoolType);
		CopyString(Data.Buffer, UnicodeString->Buffer, SymbolsCount);
	}
}

template<>
String<CHAR> String<CHAR>::GetAnsi() const {
	return String::String(*this);
}

template<>
String<WCHAR> String<CHAR>::GetWide() const {
	ANSI_STRING Ansi;
	UNICODE_STRING Unicode;
	RtlInitAnsiString(&Ansi, Data.Buffer);
	RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
	String<WCHAR> Result(Unicode.Buffer);
	RtlFreeUnicodeString(&Unicode);
	return Result;
}

template<>
String<CHAR> String<WCHAR>::GetAnsi() const {
	ANSI_STRING Ansi;
	UNICODE_STRING Unicode;
	RtlInitUnicodeString(&Unicode, Data.Buffer);
	RtlUnicodeStringToAnsiString(&Ansi, &Unicode, TRUE);
	String<CHAR> Result(Ansi.Buffer);
	RtlFreeUnicodeString(&Unicode);
	return Result;
}

template<>
String<WCHAR> String<WCHAR>::GetWide() const {
	return String::String(*this);
}

template<>
String<CHAR>& String<CHAR>::ToLowerCase() {
	_strlwr(Data.Buffer);
	return *this;
}

template<>
String<WCHAR>& String<WCHAR>::ToLowerCase() {
	_wcslwr(Data.Buffer);
	return *this;
}

template<>
String<CHAR> String<CHAR>::GetLowerCase() const {
	String<CHAR> Result(*this);
	Result.ToLowerCase();
	return Result;
}

template<>
String<WCHAR> String<WCHAR>::GetLowerCase() const {
	String<WCHAR> Result(*this);
	Result.ToLowerCase();
	return Result;
}

template<>
String<CHAR>& String<CHAR>::ToUpperCase() {
	_strupr(Data.Buffer);
	return *this;
}

template<>
String<WCHAR>& String<WCHAR>::ToUpperCase() {
	_wcsupr(Data.Buffer);
	return *this;
}

template<>
String<CHAR> String<CHAR>::GetUpperCase() const {
	String<CHAR> Result(*this);
	Result.ToUpperCase();
	return Result;
}

template<>
String<WCHAR> String<WCHAR>::GetUpperCase() const {
	String<WCHAR> Result(*this);
	Result.ToUpperCase();
	return Result;
}

template<>
SIZE_T String<CHAR>::Find(const CHAR* Substr, SIZE_T Position) const {
	if (Position > Data.Length) return SUBSTR_NOT_FOUND;
	CHAR* Pos = strstr(Data.Buffer + Position, Substr);
	return Pos != 0 ? (SIZE_T)(Data.Buffer - Pos) : SUBSTR_NOT_FOUND;
}

template<>
SIZE_T String<WCHAR>::Find(const WCHAR* Substr, SIZE_T Position) const {
	if (Position > Data.Length) return SUBSTR_NOT_FOUND;
	WCHAR* Pos = wcsstr(Data.Buffer + Position, Substr);
	return Pos != 0 ? (SIZE_T)(Data.Buffer - Pos) : SUBSTR_NOT_FOUND;
}




String<CHAR> FormatAnsi(POOL_TYPE PoolType, LPCSTR Format, ...) {
	va_list args;
	va_start(args, Format);
	const int size = _vsnprintf(NULL, 0, Format, args) + sizeof(CHAR);
	if (size <= 64) {
		CHAR Buffer[64];
		_vsnprintf(Buffer, size, Format, args);
		return String<CHAR>(Buffer);
	}
	else {
		LPSTR Buffer = (LPSTR)ExAllocatePoolWithTag(PoolType, size, String<CHAR>::GetPoolTag());
		_vsnprintf(Buffer, size, Format, args);
		String<CHAR> Result(Buffer);
		ExFreePoolWithTag(Buffer, String<CHAR>::GetPoolTag());
		return Result;
	}
}

String<WCHAR> FormatWide(POOL_TYPE PoolType, LPCWSTR Format, ...) {
	va_list args;
	va_start(args, Format);
	const int size = _vsnwprintf(NULL, 0, Format, args) + sizeof(WCHAR);
	if (size <= 64) {
		WCHAR Buffer[64];
		_vsnwprintf(Buffer, size, Format, args);
		return String<WCHAR>(Buffer);
	}
	else {
		LPWSTR Buffer = (LPWSTR)ExAllocatePoolWithTag(PoolType, size, String<WCHAR>::GetPoolTag());
		_vsnwprintf(Buffer, size, Format, args);
		String<WCHAR> Result(Buffer);
		ExFreePoolWithTag(Buffer, String<WCHAR>::GetPoolTag());
		return Result;
	}
}