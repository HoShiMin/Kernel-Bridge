#pragma once

/*
    Registers CR1, CR5..CR7, CR9..CR15, DR8..DR15 aren't implemented.
    Any attempt to access unimplemented registers results in an invalid-opcode exception (#UD).
*/

#pragma pack(push, 1)
union CR0 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int PE : 1; // Protection enabled
            unsigned int MP : 1; // Monitor coprocessor
            unsigned int EM : 1; // Emulation of 8087
            unsigned int TS : 1; // Task switched
            unsigned int ET : 1; // Extension type (readonly)
            unsigned int NE : 1; // Numeric error
            unsigned int Reserved0 : 10;
            unsigned int WP : 1; // Write protect
            unsigned int Reserved1 : 1;
            unsigned int AM : 1; // Alignment mask
            unsigned int Reserved3 : 10;
            unsigned int NW : 1; // Not writethrough
            unsigned int CD : 1; // Cache disable
            unsigned int PG : 1; // Paging
        } Bitmap;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long PE : 1; // Protection enabled
            unsigned long long MP : 1; // Monitor coprocessor
            unsigned long long EM : 1; // Emulation of 8087
            unsigned long long TS : 1; // Task switched
            unsigned long long ET : 1; // Extension type (readonly)
            unsigned long long NE : 1; // Numeric error
            unsigned long long Reserved0 : 10;
            unsigned long long WP : 1; // Write protect
            unsigned long long Reserved1 : 1;
            unsigned long long AM : 1; // Alignment mask
            unsigned long long Reserved3 : 10;
            unsigned long long NW : 1; // Not writethrough
            unsigned long long CD : 1; // Cache disable
            unsigned long long PG : 1; // Paging
            unsigned long long Reserved4 : 32;
        } Bitmap;
    } x64;
};

union CR2 {
    unsigned long long Value;
    struct {
        unsigned int PageFaultLinearAddress;
    } x32;
    struct {
        unsigned long long PageFaultLinearAddress;
    } x64;
};

union CR3 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int Reserved0 : 3;
            unsigned int PWT : 1; // Write through
            unsigned int PCD : 1; // Cache disable
            unsigned int Reserved1 : 7;
            unsigned int PD : 20; // Page Directory table base address
        } NonPae;
        struct {
            unsigned int Reserved0 : 3;
            unsigned int PWT : 1; // Write through
            unsigned int PCD : 1; // Cache disable
            unsigned int PDP : 27; // Page Directory Pointer table base address
        } Pae;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long Reserved0 : 3;
            unsigned long long PWT : 1; // Write through
            unsigned long long PCD : 1; // Cache disable
            unsigned long long Reserved1 : 7;
            unsigned long long PML4 : 40; // PML4 table base address
            unsigned long long Reserved2 : 12;
        } Bitmap;
    } x64;
};

union CR4 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int VME : 1; // Virtual 8086-mode extensions
            unsigned int PVI : 1; // Protected-mode virtual interrupts
            unsigned int TSD : 1; // Timestamp disable
            unsigned int DE : 1; // Debugging extensions
            unsigned int PSE : 1; // Page size extensions
            unsigned int PAE : 1; // Physical address extension
            unsigned int MCE : 1; // Machine check enable
            unsigned int PGE : 1; // Page global enable
            unsigned int PCE : 1; // Performance-monitoring counter enable
            unsigned int OSFXSR : 1; // Operating system FXSAVE/FXSTOR support
            unsigned int OSXMMEXCPT : 1; // Operating system unmasked exception support
            unsigned int UMIP : 1; // Usermode instruction prevention
            unsigned int Reserved0 : 1;
            unsigned int VMXE : 1; // VMX-enable bit (Intel only)
            unsigned int SMXE : 1; // SMX-enable bit (Safer Mode Extensions, Intel only)
            unsigned int Reserved1 : 1;
            unsigned int FSGSBASE : 1; // Enable RDFSBASE, RDGSBASE, WRFSBASE and WRGSBASE instructions
            unsigned int PCIDE : 1; // PCID-enable bit (Process-Context Identifiers, Intel only)
            unsigned int OSXSAVE : 1; // XSAVE and Processor Extended States Enable bit
            unsigned int Reserved2 : 1;
            unsigned int SMEP : 1; // Supervisor mode execution prevention
            unsigned int SMAP : 1; // Supervisor mode access prevention
            unsigned int PKE : 1; // Protection key enable (Intel only)
            unsigned int Reserved3 : 9;
        } Bitmap;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long VME : 1; // Virtual 8086-mode extensions
            unsigned long long PVI : 1; // Protected-mode virtual interrupts
            unsigned long long TSD : 1; // Timestamp disable
            unsigned long long DE : 1; // Debugging extensions
            unsigned long long PSE : 1; // Page size extensions
            unsigned long long PAE : 1; // Physical address extension
            unsigned long long MCE : 1; // Machine check enable
            unsigned long long PGE : 1; // Page global enable
            unsigned long long PCE : 1; // Performance-monitoring counter enable
            unsigned long long OSFXSR : 1; // Operating system FXSAVE/FXSTOR support
            unsigned long long OSXMMEXCPT : 1; // Operating system unmasked exception support
            unsigned long long UMIP : 1; // Usermode instruction prevention
            unsigned long long Reserved0 : 1;
            unsigned long long VMXE : 1; // VMX-enable bit (Intel only)
            unsigned long long SMXE : 1; // SMX-enable bit (Safer Mode Extensions, Intel only)
            unsigned long long Reserved1 : 1;
            unsigned long long FSGSBASE : 1; // Enable RDFSBASE, RDGSBASE, WRFSBASE and WRGSBASE instructions
            unsigned long long PCIDE : 1; // PCID-enable bit (Process-Context Identifiers, Intel only)
            unsigned long long OSXSAVE : 1; // XSAVE and Processor Extended States Enable bit
            unsigned long long Reserved2 : 1;
            unsigned long long SMEP : 1; // Supervisor mode execution prevention
            unsigned long long SMAP : 1; // Supervisor mode access prevention
            unsigned long long PKE : 1; // Protection key enable (Intel only)
            unsigned long long Reserved3 : 41;
        } Bitmap;
    } x64;
};

union CR8 { // Task priority register:
    unsigned long long Reserved;
    struct {
        unsigned long long TPR : 4; // Priority
        unsigned long long Reserved : 60;
    } x64;
};



union DR0 {
    unsigned long long Breakpoint0LinearAddress;
    struct {
        unsigned int Breakpoint0LinearAddress;
    } x32;
    struct {
        unsigned long long Breakpoint0LinearAddress;
    } x64;
};

union DR1 {
    unsigned long long Breakpoint1LinearAddress;
    struct {
        unsigned int Breakpoint1LinearAddress;
    } x32;
    struct {
        unsigned long long Breakpoint1LinearAddress;
    } x64;
};

union DR2 {
    unsigned long long Breakpoint2LinearAddress;
    struct {
        unsigned int Breakpoint2LinearAddress;
    } x32;
    struct {
        unsigned long long Breakpoint2LinearAddress;
    } x64;
};

union DR3 {
    unsigned long long Breakpoint3LinearAddress;
    struct {
        unsigned int Breakpoint3LinearAddress;
    } x32;
    struct {
        unsigned long long Breakpoint3LinearAddress;
    } x64;
};

union DR4 { // Aliased to the DR6
    unsigned long long Reserved;
};

union DR5 { // Aliased to the DR7
    unsigned long long Reserved;
};

union DR6 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int B0 : 1; // Breakpoint #0 condition detected
            unsigned int B1 : 1; // Breakpoint #1 condition detected
            unsigned int B2 : 1; // Breakpoint #2 condition detected
            unsigned int B3 : 1; // Breakpoint #3 condition detected
            unsigned int FilledByOnes0 : 8; // Must be 0xFF (8 bits of ones: 0b1111_1111)
            unsigned int ReservedByZero : 1;
            unsigned int BD : 1; // Debug register access detected
            unsigned int BS : 1; // Single step
            unsigned int BT : 1; // Task switch
            unsigned int RTM : 1; // Intel only, must be 1 on AMD platforms
            unsigned int FilledByOnes1 : 15; // Must be 0x7FFF (15 bits of ones: 0b111_1111_1111_1111)
        } Bitmap;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long B0 : 1; // Breakpoint #0 condition detected
            unsigned long long B1 : 1; // Breakpoint #1 condition detected
            unsigned long long B2 : 1; // Breakpoint #2 condition detected
            unsigned long long B3 : 1; // Breakpoint #3 condition detected
            unsigned long long FilledByOnes0 : 8; // Must be 0xFF (8 bits of ones: 0b1111_1111)
            unsigned long long ReservedByZero : 1;
            unsigned long long BD : 1; // Debug register access detected
            unsigned long long BS : 1; // Single step
            unsigned long long BT : 1; // Task switch
            unsigned long long RTM : 1; // Intel only, must be 1 on AMD platforms
            unsigned long long FilledByOnes1 : 15; // Must be 0x7FFF (15 bits of ones: 0b111_1111_1111_1111)
            unsigned long long MustBeZero : 32;
        } Bitmap;
    } x64;
};

union DR7 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int L0 : 1; // Local  exact breakpoint #0 enabled
            unsigned int G0 : 1; // Global exact breakpoint #0 enabled
            unsigned int L1 : 1; // Local  exact breakpoint #1 enabled
            unsigned int G1 : 1; // Global exact breakpoint #1 enabled
            unsigned int L2 : 1; // Local  exact breakpoint #2 enabled
            unsigned int G2 : 1; // Global exact breakpoint #2 enabled
            unsigned int L3 : 1; // Local  exact breakpoint #3 enabled
            unsigned int G3 : 1; // Global exact breakpoint #3 enabled
            unsigned int LE : 1; // Local  exact breakpoint enabled
            unsigned int GE : 1; // Global exact breakpoint enabled
            unsigned int ReservedAsOne : 1;
            unsigned int RTM : 1; // Intel only, must be zero on AMD platforms
            unsigned int ReservedAsZero0 : 1;
            unsigned int GD : 1; // General detect enabled
            unsigned int ReservedAsZero1 : 2;
            unsigned int RW0 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned int LEN0 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned int RW1 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned int LEN1 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned int RW2 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned int LEN2 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned int RW3 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned int LEN3 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
        } Bitmap;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long L0 : 1; // Local  exact breakpoint #0 enabled
            unsigned long long G0 : 1; // Global exact breakpoint #0 enabled
            unsigned long long L1 : 1; // Local  exact breakpoint #1 enabled
            unsigned long long G1 : 1; // Global exact breakpoint #1 enabled
            unsigned long long L2 : 1; // Local  exact breakpoint #2 enabled
            unsigned long long G2 : 1; // Global exact breakpoint #2 enabled
            unsigned long long L3 : 1; // Local  exact breakpoint #3 enabled
            unsigned long long G3 : 1; // Global exact breakpoint #3 enabled
            unsigned long long LE : 1; // Local  exact breakpoint enabled
            unsigned long long GE : 1; // Global exact breakpoint enabled
            unsigned long long ReservedAsOne : 1;
            unsigned long long RTM : 1; // Intel only, must be zero on AMD platforms
            unsigned long long ReservedAsZero0 : 1;
            unsigned long long GD : 1; // General detect enabled
            unsigned long long ReservedAsZero1 : 2;
            unsigned long long RW0 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned long long LEN0 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned long long RW1 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned long long LEN1 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned long long RW2 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned long long LEN2 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned long long RW3 : 2; // 0b00 - Execute, 0b01 - Write, 0b10 - CR4.DE(0 - Undefined, 1 - I/O Reads & Writes), 0b11 - Read/Write only
            unsigned long long LEN3 : 2; // 0b00 = 1 byte, 0b01 = 2 bytes, 0b10 = 8 bytes (long mode only, otherwise undefined), 0b11 = 4 bytes
            unsigned long long ReservedAsZero2 : 32;
        } Bitmap;
    } x64;
};
#pragma pack(pop)