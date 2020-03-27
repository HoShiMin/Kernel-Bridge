#pragma once

#pragma pack(push, 1)
// Value of CS, DS, GS, FS, ES, SS, TR registers:
union SEGMENT_SELECTOR {
    unsigned short Value;
    struct {
        unsigned short Rpl : 2; // Requestor privilege level
        unsigned short TableIndicator : 1; // 0 = GDT using, 1 = LDT using
        unsigned short SelectorIndex : 13; // Entry base = Table base + SelectorIndex * sizeof(Table entry)
    } Bitmap;
};

// Value of the IDTR/GDTR/LDTR registers in the legacy mode:
struct DESCRIPTOR_TABLE_REGISTER_LEGACY {
    unsigned short Limit; // Size of descriptor table in bytes
    unsigned int BaseAddress; // Points to the first entry in a descriptor table
};

// Value of the IDTR/GDTR/LDTR registers in the long mode:
struct DESCRIPTOR_TABLE_REGISTER_LONG {
    unsigned short Limit; // Size of descriptor table in bytes
    unsigned long long BaseAddress; // Points to the first entry in a descriptor table
};

enum SYSTEM_SEGMENT_DESCRIPTOR_TYPE_LEGACY {
    ssdtReserved0,
    ssdtAvailable16BitTss,
    ssdtLdt,
    ssdtBusy16BitTss,
    ssdt16BitCallGate,
    ssdtTaskGate,
    ssdt16BitInterruptGate,
    ssdt16BitTrapGate,
    ssdtReserved1,
    ssdtAvailable32BitTss,
    ssdtReserved2,
    ssdtBusy32BitTss,
    ssdt32BitCallGate,
    ssdtReserved3,
    ssdt32BitInterruptGate,
    ssdt32BitTrapGate
};

// Legacy:
union SEGMENT_DESCRIPTOR_LEGACY {
    unsigned long long Value;
    struct {
        unsigned long long SegmentLimitLow : 16;
        unsigned long long BaseAddressLow : 24;
        unsigned long long Type : 4; // SEGMENT_DESCRIPTOR_TYPE_LEGACY
        unsigned long long System : 1; // 0 = System (LDT, TSS, Gate), 1 = User (Code, Data)
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long SegmentLimitHigh : 4;
        unsigned long long Available : 1;
        unsigned long long Reserved : 1;
        unsigned long long DefaultOperandSize : 1; // 1 = 32-bit, 0 = 16-bit
        unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        unsigned long long BaseAddressHigh : 8;
    } Generic;
    struct {
        unsigned long long SegmentLimitLow : 16;
        unsigned long long BaseAddressLow : 24;
        unsigned long long Accessed : 1;
        unsigned long long Readable : 1;
        unsigned long long Conforming : 1;
        unsigned long long Type : 1; // Must be 1 (1 = Code, 0 = Data)
        unsigned long long System : 1; // Must be 1 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long SegmentLimitHigh : 4;
        unsigned long long Available : 1;
        unsigned long long Reserved : 1;
        unsigned long long DefaultOperandSize : 1; // 1 = 32-bit, 0 = 16-bit
        unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        unsigned long long BaseAddressHigh : 8;
    } Code;
    struct {
        unsigned long long SegmentLimitLow : 16;
        unsigned long long BaseAddressLow : 24;
        unsigned long long Accessed : 1;
        unsigned long long Writeable : 1;
        unsigned long long ExpandDown : 1;
        unsigned long long Type : 1; // Must be 0 (1 = Code, 0 = Data)
        unsigned long long System : 1; // Must be 1 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long SegmentLimitHigh : 4;
        unsigned long long Available : 1;
        unsigned long long Reserved : 1;
        unsigned long long DefaultOperandSize : 1; // 1 = 32-bit, 0 = 16-bit
        unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        unsigned long long BaseAddressHigh : 8;
    } Data;
    struct {
        unsigned long long SegmentLimitLow : 16;
        unsigned long long BaseAddressLow : 24;
        unsigned long long Type : 4;
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long SegmentLimitHigh : 4;
        unsigned long long Available : 1;
        unsigned long long Reserved : 2;
        unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        unsigned long long BaseAddressHigh : 8;
    } Ldt, Tss;
};

union GATE_DESCRIPTOR_LEGACY {
    unsigned long long Value;
    struct {
        unsigned long long TargetCodeSegmentOffsetLow : 16;
        unsigned long long TargetCodeSegmentSelector : 16;
        unsigned long long ParameterCount : 5;
        unsigned long long Reserved : 3;
        unsigned long long Type : 4;
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long TargetCodeSegmentOffsetHigh : 16;
    } CallGate;
    struct {
        unsigned long long TargetCodeSegmentOffsetLow : 16;
        unsigned long long TargetCodeSegmentSelector : 16;
        unsigned long long Reserved : 8;
        unsigned long long Type : 4;
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long TargetCodeSegmentOffsetHigh : 16;
    } InterruptGate, TrapGate;
    struct {
        unsigned long long Reserved0 : 16;
        unsigned long long TssSelector : 16;
        unsigned long long Reserved1 : 8;
        unsigned long long Type : 4;
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long Reserved2 : 16;
    } TaskGate;
};

enum SYSTEM_SEGMENT_DESCRIPTOR_TYPE_LONG {
    ssdt64BitLdt = 0x02,
    ssdtAvailable64BitTss = 0x09,
    ssdtBusy64BitTss = 0x0B,
    ssdt64BitCallGate = 0x0C,
    ssdt64BitInterruptGate = 0x0E,
    ssdt64BitTrapGate = 0x0F,
};

union USER_SEGMENT_DESCRIPTOR_LONG {
    unsigned long long Value;
    struct {
        unsigned long long SegmentLimitLow : 16;
        unsigned long long BaseAddressLow : 24;
        unsigned long long Type : 4; // 1 = Code, 0 = Data
        unsigned long long System : 1; // Must be 1 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long SegmentLimitHigh : 4;
        unsigned long long Available : 1;
        unsigned long long LongMode : 1;
        unsigned long long DefaultOperandSize : 1; // Must be 0 (0 = 64-bit, 1 = Reserved)
        unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        unsigned long long BaseAddressHigh : 8;
    } Generic;
    struct {
        /* COMPAT MODE ONLY */ unsigned long long SegmentLimitLow : 16;
        /* COMPAT MODE ONLY */ unsigned long long BaseAddressLow : 24;
        /* COMPAT MODE ONLY */ unsigned long long Accessed : 1;
        /* COMPAT MODE ONLY */ unsigned long long Readable : 1;
        unsigned long long Conforming : 1;
        unsigned long long Type : 1; // Must be 1 (1 = Code, 0 = Data)
        unsigned long long System : 1; // Must be 1 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        /* COMPAT MODE ONLY */ unsigned long long SegmentLimitHigh : 4;
        /* COMPAT MODE ONLY */ unsigned long long Available : 1;
        unsigned long long LongMode : 1;
        unsigned long long DefaultOperandSize : 1; // Must be 0 (0 = 64-bit, 1 = Reserved)
        /* COMPAT MODE ONLY */ unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        /* COMPAT MODE ONLY */ unsigned long long BaseAddressHigh : 8;
    } Code;
    struct {
        /* COMPAT MODE ONLY */ unsigned long long SegmentLimitLow : 16;
        /* COMPAT MODE ONLY */ unsigned long long BaseAddressLow : 24;
        /* COMPAT MODE ONLY */ unsigned long long Accessed : 1;
        /* COMPAT MODE ONLY */ unsigned long long Writeable : 1;
        /* COMPAT MODE ONLY */ unsigned long long ExpandDown : 1;
        /* COMPAT MODE ONLY */ unsigned long long Type : 1; // Must be 0 (1 = Code, 0 = Data)
        /* COMPAT MODE ONLY */ unsigned long long System : 1; // Must be 1 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        /* COMPAT MODE ONLY */ unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        /* COMPAT MODE ONLY */ unsigned long long SegmentLimitHigh : 4;
        /* COMPAT MODE ONLY */ unsigned long long Available : 1;
        /* COMPAT MODE ONLY */ unsigned long long Reserved : 1;
        /* COMPAT MODE ONLY */ unsigned long long DefaultOperandSize : 1; // 1 = 32-bit, 0 = 16-bit
        /* COMPAT MODE ONLY */ unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        /* COMPAT MODE ONLY */ unsigned long long BaseAddressHigh : 8;
    } Data;
};

union SYSTEM_SEGMENT_DESCRIPTOR_LONG {
    struct {
        unsigned long long Low;
        unsigned long long High;
    } Value;
    struct {
        unsigned long long SegmentLimitLow : 16;
        unsigned long long BaseAddressLow : 24;
        unsigned long long Type : 4; // SEGMENT_DESCRIPTOR_TYPE_LONG
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long SegmentLimitHigh : 4;
        unsigned long long Available : 1;
        unsigned long long Reserved0 : 2;
        unsigned long long Granularity : 1; // 1 = Segment size is SegmentLimit * 4096 bytes, 0 = Segment size is SegmentLimit bytes
        unsigned long long BaseAddressHigh : 40;
        unsigned long long Reserved1 : 8;
        unsigned long long MustBeZero : 5;
        unsigned long long Reserved2 : 19;
    } Bitmap;
};

union GATE_DESCRIPTOR_LONG {
    struct {
        unsigned long long Low;
        unsigned long long High;
    } Value;
    struct {
        unsigned long long TargetOffsetLow : 16;
        unsigned long long TargetSelector : 16;
        unsigned long long Reserved0 : 8;
        unsigned long long Type : 4; // SEGMENT_DESCRIPTOR_TYPE_LONG
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long TargetOffsetHigh : 48;
        unsigned long long Reserved1 : 8;
        unsigned long long MustBeZero : 5;
        unsigned long long Reserved2 : 19;
    } CallGate;
    struct {
        unsigned long long TargetOffsetLow : 16;
        unsigned long long TargetSelector : 16;
        unsigned long long InterruptStackTable : 3;
        unsigned long long Reserved0 : 5;
        unsigned long long Type : 4; // SEGMENT_DESCRIPTOR_TYPE_LONG
        unsigned long long System : 1; // Must be 0 (0 = System (LDT, TSS, Gate), 1 = User (Code, Data))
        unsigned long long Dpl : 2;
        unsigned long long Present : 1;
        unsigned long long TargetOffsetHigh : 48;
        unsigned long long Reserved1 : 32;
    } InterruptGate, TrapGate;
};

union TSS {
    struct {
        unsigned short Link; // Prior TSS selector
        unsigned short Reserved0;
        unsigned int Esp0;
        unsigned short Ss0;
        unsigned short Reserved1;
        unsigned int Esp1;
        unsigned short Ss1;
        unsigned short Reserved2;
        unsigned int Esp2;
        unsigned short Ss2;
        unsigned short Reserved3;
        unsigned int Cr3;
        unsigned int Eip;
        unsigned int EFlags;
        unsigned int Eax;
        unsigned int Ecx;
        unsigned int Edx;
        unsigned int Ebx;
        unsigned int Esp;
        unsigned int Ebp;
        unsigned int Esi;
        unsigned int Edi;
        unsigned short Es;
        unsigned short Reserved4;
        unsigned short Cs;
        unsigned short Reserved5;
        unsigned short Ss;
        unsigned short Reserved6;
        unsigned short Ds;
        unsigned short Reserved7;
        unsigned short Fs;
        unsigned short Reserved8;
        unsigned short Gs;
        unsigned short Reserved9;
        unsigned short LdtSelector;
        unsigned short Reserved10;
        unsigned short Trap : 1;
        unsigned short Reserved11 : 15;
        unsigned short IopbBaseAddress;
        unsigned int ShadowStackPointer; // Intel platforms only
        // ... Operating system data structure ...
        // Interrupt-redirection bitmap (eight 32-bit locations)
        // IOPB (up to 8 Kbytes)
        // ^ TSS Limit in the SEGMENT_DESCRIPTOR_LEGACY::Tss::SegmentLimit
    } Legacy;
    struct {
        unsigned int Reserved0;
        unsigned int Rsp0Lower;
        unsigned int Rsp0Upper;
        unsigned int Rsp1Lower;
        unsigned int Rsp1Upper;
        unsigned int Rsp2Lower;
        unsigned int Rsp2Upper;
        unsigned long long Reserved1;
        unsigned int Ist1Lower; // Interrupt stack table (lower part)
        unsigned int Ist1Upper; // Interrupt stack table (higher part)
        unsigned int Ist2Lower;
        unsigned int Ist2Upper;
        unsigned int Ist3Lower;
        unsigned int Ist3Upper;
        unsigned int Ist4Lower;
        unsigned int Ist4Upper;
        unsigned int Ist5Lower;
        unsigned int Ist5Upper;
        unsigned int Ist6Lower;
        unsigned int Ist6Upper;
        unsigned int Ist7Lower;
        unsigned int Ist7Upper;
        unsigned long long Reserved2;
        unsigned short Reserved3;
        unsigned short IopbBaseAddress;
        // IOPB (up to 8 Kbytes)
        // ^ TSS Limit in the SEGMENT_DESCRIPTOR_LONG::Tss::SegmentLimit
    } Long;
};
#pragma pack(pop)