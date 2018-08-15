#pragma once

#include <wdm.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "MemoryUtils.h"

#define STRING_TEMPLATE template<class TChar>

#define SUBSTR_NOT_FOUND ((SIZE_T)-1)

STRING_TEMPLATE
class String {
private:
	static const ULONG PoolTag = 0x1EE7C0DE;
	POOL_TYPE _PoolType;

	typedef struct _STRING_INFO {
		TChar* Buffer;
		SIZE_T Length;
		SIZE_T Size;
	} STRING_INFO, *PSTRING_INFO;

	STRING_INFO Data;
	VOID AllocateString(SIZE_T Length, OUT PSTRING_INFO StringInfo, POOL_TYPE PoolType);
	VOID AllocateString(const TChar* String, OUT PSTRING_INFO StringInfo);
	VOID CopyString(TChar* Dest, const TChar* Src);
	VOID CopyString(TChar* Dest, const TChar* Src, SIZE_T SymbolsCount, BOOLEAN NullTerminate = TRUE);
	VOID ConcatString(TChar* Left, const TChar* Right);
	BOOLEAN CompareStrings(const TChar* Left, const TChar* Right);
	VOID FreeString(IN PSTRING_INFO Data);
	VOID AllocAndConcatString(
		const IN PSTRING_INFO Left,
		const IN PSTRING_INFO Right,
		OUT PSTRING_INFO Data
	);
	String(POOL_TYPE PoolType, IN PSTRING_INFO StringInfo);
	String(const String& String, POOL_TYPE PoolType = VirtualMemory::GetPoolType());
public:
	typedef enum _REPLACING_METHOD {
		METHOD_SIMPLE,
		METHOD_SELECTIVE
	} REPLACING_METHOD;

	typedef enum _TRIM_TYPE {
		TRIM_SPACES,
		TRIM_TABS,
		TRIM_ALL
	} TRIM_TYPE;

	static inline SIZE_T Length(const TChar* String);

	String(POOL_TYPE PoolType = VirtualMemory::GetPoolType());
	String(const TChar* String, POOL_TYPE PoolType = VirtualMemory::GetPoolType());
	String(String&& String);
	String(IN PCANSI_STRING AnsiString, POOL_TYPE PoolType = VirtualMemory::GetPoolType());
	String(IN PCUNICODE_STRING UnicodeString, POOL_TYPE PoolType = VirtualMemory::GetPoolType());

    ~String();

	static inline ULONG GetPoolTag() { return PoolTag; }
	inline POOL_TYPE GetPoolType() const { return _PoolType; }

	inline const TChar* GetPtr() const { return Data.Buffer; }
	inline SIZE_T GetLength() const { return Data.Length; }
	inline SIZE_T GetSize() const { return Data.Size; }

	String<CHAR> GetAnsi() const;
	String<WCHAR> GetWide() const;
	String& ToLowerCase();
	String& ToUpperCase();
	String GetLowerCase() const;
	String GetUpperCase() const;

	SIZE_T Find(const TChar* Substr, SIZE_T Position = 0) const;
	bool Contains(const TChar* Substr) const;
	bool Substr(SIZE_T StartPos, SIZE_T Length = 0) const;

	String& Trim(TRIM_TYPE TrimType = TRIM_ALL);
	String& TrimLeft(TRIM_TYPE TrimType = TRIM_ALL);
	String& TrimRight(TRIM_TYPE TrimType = TRIM_ALL);
	String& Delete(SIZE_T Position, SIZE_T Count);
	String& Insert(SIZE_T Position, const TChar* Insertion);
	String& Replace(
		const TChar* Substr, 
		const TChar* Replacer, 
		REPLACING_METHOD Method = METHOD_SIMPLE, 
		unsigned int* Replaced = NULL
	);

	bool IsMatches(const TChar* WildString) const;

	String operator + (String&& String);
	String operator + (const String& String);
	friend String operator + (const TChar* Left, const String& Right) {
		return String(Left, Right.GetPoolType()) + Right;
	}

	String& operator += (const String&& String);

	String& operator = (const String& String);
	String& operator = (String&& String);

	bool operator == (const TChar* String);
	bool operator == (const String& String);
};

typedef String<CHAR> AnsiString;
typedef String<WCHAR> UnicodeString, WideString;

STRING_TEMPLATE
String<TChar>::String(POOL_TYPE PoolType, IN PSTRING_INFO StringInfo) {
	_PoolType = PoolType;
	Data = *StringInfo;
}

STRING_TEMPLATE
VOID String<TChar>::AllocAndConcatString(
	const IN PSTRING_INFO Left,
	const IN PSTRING_INFO Right,
	OUT PSTRING_INFO StringInfo
) {
	AllocateString(Left->Length + Right->Length, StringInfo, _PoolType);
	CopyString(StringInfo->Buffer, Left->Buffer);
	ConcatString(StringInfo->Buffer, Right->Buffer);
}

STRING_TEMPLATE
VOID String<TChar>::AllocateString(SIZE_T Length, OUT PSTRING_INFO StringInfo, POOL_TYPE PoolType) {
	StringInfo->Length = Length;
	StringInfo->Size = (StringInfo->Length + 1) * sizeof(TChar); // +1 null-terminator
	StringInfo->Buffer = (TChar*)ExAllocatePoolWithTag(PoolType, StringInfo->Size, PoolTag);
}


STRING_TEMPLATE
VOID String<TChar>::FreeString(IN PSTRING_INFO StringInfo) {
	if (StringInfo->Buffer) ExFreePoolWithTag(StringInfo->Buffer, PoolTag);
	*StringInfo = { 0 };
}

STRING_TEMPLATE
String<TChar>::String(const TChar* String, POOL_TYPE PoolType) {
	_PoolType = PoolType;
	AllocateString(String, &Data);
	CopyString(Data.Buffer, String);
}

STRING_TEMPLATE
String<TChar>::String(const String& String, POOL_TYPE PoolType) {
	_PoolType = PoolType;
	AllocateString(String.Data.Length, &Data, PoolType);
	CopyString(Data.Buffer, String.Data.Buffer, String.Data.Length);
}

STRING_TEMPLATE
String<TChar>::String(String&& String) {
	_PoolType = String._PoolType;
	Data = String.Data;
	String.Data = { 0 };
}

STRING_TEMPLATE
String<TChar>::~String() {
    FreeString(&Data);
}

STRING_TEMPLATE
bool String<TChar>::Contains(const TChar* Substr) const {
	return Find(Substr) != SUBSTR_NOT_FOUND;
}

STRING_TEMPLATE
bool String<TChar>::Substr(SIZE_T StartPos, SIZE_T Length) const {
	if (StartPos > Data.Length || Length == 0) return String::String();
	SIZE_T Count = (StartPos + Length + 1) <= Data.Length ? Length : (Data.Length - StartPos + 1);

	TChar* Begin = Data.Buffer + StartPos;
	TChar* NullTerminator = Begin + Count;
	TChar Symbol = *NullTerminator;
	*NullTerminator = (TChar)0x00;
	String Result(Begin);
	*NullTerminator = Symbol;
	return Result;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::Trim(TRIM_TYPE TrimType) {
	TrimLeft();
	TrimRight();
	return *this;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::TrimLeft(TRIM_TYPE TrimType) {

	return *this;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::TrimRight(TRIM_TYPE TrimType) {

	return *this;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::Delete(SIZE_T Position, SIZE_T Count) {
	if (Count == 0 || Position > Data.Length)
		return *this;

	SIZE_T RemainderPosition = Position + Count;
	if (RemainderPosition > Data.Length) {
		Position++;
		*(Data.Buffer + Position) = (TChar)0x00;
		Data.Length = Position;
		return *this;
	}

	CopyString(Data.Buffer + Position, Data.Buffer + RemainderPosition, Count);
	Data.Length -= Count;
	return *this;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::Insert(SIZE_T Position, const TChar* Insertion) {
	if (Position > Data.Length || Insertion == NULL) return *this;
	SIZE_T InsertionLength = Length(Insertion);
	SIZE_T TargetLength = Data.Length + InsertionLength;
	BOOL NeedToRealloc = TargetLength > ((Data.Size / sizeof(TChar)) - 1);
	SIZE_T RemainderPos = Position + InsertionLength;
	SIZE_T RemainderLength = Length(Data.Buffer + RemainderPos);
	if (NeedToRealloc) {
		STRING_INFO Temp;
		AllocateString(TargetLength, &Temp, _PoolType);
		CopyString(Temp.Buffer, Data.Buffer, Position, FALSE);
		CopyString(Temp.Buffer + Position, Insertion, InsertionLength, FALSE);
		CopyString(Temp.Buffer + Position + InsertionLength, Data.Buffer + Position, RemainderLength, TRUE);
		FreeString(&Data);
		Data = Temp;
	}
	else {
		CopyString(Data.Buffer + RemainderPos, Data.Buffer + Position, RemainderLength, TRUE);
		CopyString(Data.Buffer + Position, Insertion, InsertionLength, FALSE);
	}
	return *this;
}

/*
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

* Simple - простой метод :
	Text = aFFabFFabc
		Source = ab
		Destination = abc

	Result = aFFabcFFabcc

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

* Selective - избирательный метод :
	Text = aFFabFFabc
		Source = ab
		Destination = abc

	Result = aFFabcFFabc - крайн€€ последовательность така€ же, как
	замен€юща€ строка(abc), поэтому еЄ не трогаем

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
*/

STRING_TEMPLATE
String<TChar>& String<TChar>::Replace(
	const TChar* Substr,
	const TChar* Replacer,
	REPLACING_METHOD Method,
	unsigned int* Replaced
) {
	unsigned int ReplacesCount = 0;
	SIZE_T SubstrLength = Length(Substr);
	SIZE_T ReplacerLength = Length(Replacer);
		
	SIZE_T Position = Find(Substr);
	if (Position == SUBSTR_NOT_FOUND) return *this;
	do {
		if (Method == METHOD_SELECTIVE)
			if (Find(Replacer, Position) == Position) continue;
		Delete(Position, SubstrLength);
		Insert(Position, Replacer);
		ReplacesCount++;
	} while ((Position = Find(Substr, Position + ReplacerLength)) != SUBSTR_NOT_FOUND);
	
	if (Replaced) *Replaced = ReplacesCount;
	return *this;
}

STRING_TEMPLATE
bool String<TChar>::IsMatches(const TChar* WildString) const {
	/* 
		Dr.Dobb's Algorithm:
		http://www.drdobbs.com/architecture-and-design/matching-wildcards-an-empirical-way-to-t/240169123?queryText=path%2Bmatches
	*/
	TChar* TameText = Data.Buffer;
	TChar* WildText = (TChar*)WildString;
	TChar* TameBookmark = (TChar*)0x00;
	TChar* WildBookmark = (TChar*)0x00;

	while (true) {
		if (*WildText == (TChar)'*') {
			while (*(++WildText) == (TChar)'*'); // "xy" matches "x**y"
			if (!*WildText) return true; // "x" matches "*"
			
			if (*WildText != (TChar)'?') {
				while (*TameText != *WildText) {
					if (!(*(++TameText)))
						return false;  // "x" doesn't match "*y*"
				}
			}

			WildBookmark = WildText;
			TameBookmark = TameText;
		}
		else if (*TameText != *WildText && *WildText != (TChar)'?') {
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
			while (*WildText == (TChar)'*') WildText++; // "x" matches "x*"

			if (!*WildText) return true; // "x" matches "x"
			return false; // "x" doesn't match "xy"
		}
	}
}




STRING_TEMPLATE
String<TChar> String<TChar>::operator + (String&& String) {
	STRING_INFO StringInfo;
	AllocAndConcatString(&Data, (const PSTRING_INFO)&String.Data, &StringInfo);
	return String::String(_PoolType, (const PSTRING_INFO)&StringInfo);
}

STRING_TEMPLATE
String<TChar> String<TChar>::operator + (const String& String) {
	STRING_INFO StringInfo;
	AllocAndConcatString(&Data, (const PSTRING_INFO)&String.Data, &StringInfo);
	return String::String(_PoolType, (const PSTRING_INFO)&StringInfo);
}

STRING_TEMPLATE
String<TChar>& String<TChar>::operator += (const String&& String) {
	STRING_INFO Temp;
	AllocAndConcatString(&Data, (const PSTRING_INFO)&String.Data, &Temp);
	FreeString(&Data);
	Data = Temp;
	return *this;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::operator = (const String& String) {
	_PoolType = String._PoolType;
	FreeString(&Data);
	AllocateString(String.Data.Length, &Data);
	CopyString(Data.Buffer, String.Data.Buffer, String.Data.Length);
	return *this;
}

STRING_TEMPLATE
String<TChar>& String<TChar>::operator = (String&& String) {
	_PoolType = String._PoolType;
	FreeString(&Data);
	Data = String.Data;
	String.Data = { 0 };
	return *this;
}

STRING_TEMPLATE
bool String<TChar>::operator == (const String& String) {
	return Data.Length == String.Data.Length
		? CompareStrings(Data.Buffer, String.Data.Buffer)
		: FALSE;
}

STRING_TEMPLATE
bool String<TChar>::operator == (const TChar* String) {
	return Data.Buffer != String
		? CompareStrings(Data.Buffer, String)
		: TRUE;
}