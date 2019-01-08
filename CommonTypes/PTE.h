#pragma once

/*
    Page size (max VA = 64 bit, max PA = 52 bit):
     * Long Mode (CR4.PAE always = 1, CR4.PSE ignored): 
         // Maximum VA = 64 bit
         // Maximum PA = 52 bit
         if (PDPE.PS) {
             PageSize = 1 Gbyte;
         }
         else {
             if (PDE.PS) {
                 PageSize = 2 Mbyte;
             } else {
                 PageSize = 4 Kbyte;
             }
         }

     * Legacy Mode:
         // PDPE.PS always = 0
         // Maximum VA = 32 bit
         if (CR4.PAE) {
             // CR4.PSE ignored
             // Maximum PA = 52 bit
             if (PDE.PS) {
                 PageSize = 2 Mbyte;
             } else {
                 PageSize = 4 Kbyte;
             }
         }
         else {
             if (CR4.PSE) {
                 if (PDE.PS) {
                     // Maximum PA = 40 bit
                     PageSize = 4 Mbyte;
                 } else {
                     // Maximum PA = 32 bit
                     PageSize = 4 Kbyte;
                 }
             }
             else {
                 // PDE.PS ignored
                 // Maximum PA = 32 bit
                 PageSize = 4 Kbyte;
             }
         }
*/

#define PFN_TO_PAGE(pfn) (pfn << 12)

#pragma pack(push, 1)
union VIRTUAL_ADDRESS {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int PageOffset : 12; // Offset into the physical page
            unsigned int PageTableOffset : 10; // Index into the 1024-entry page-table
            unsigned int PageDirectoryOffset : 10; // Index into the 1024-entry page-directory table
        } NonPae4Kb;
        struct {
            unsigned int PageOffset : 22; // Offset into the physical page
            unsigned int PageDirectoryOffset : 10;
        } NonPae4Mb;
        struct {
            unsigned int PageOffset : 12; // Byte offset into the physical page
            unsigned int PageTableOffset : 9; // Index into the 512-entry page table
            unsigned int PageDirectoryOffset : 9; // Index into the 512-entry page-directory table
            unsigned int PageDirectoryPointerOffset : 2; // Index into a 4-entry page-directory-pointer table
        } Pae4Kb;
        struct {
            unsigned int PageOffset : 21; // Byte offset into the physical page
            unsigned int PageDirectoryOffset : 9; // Index into the 512-entry page-directory table
            unsigned int PageDirectoryPointerOffset : 2; // Index into a 4-entry page-directory-pointer table
        } Pae2Mb;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long PageOffset : 12;
            unsigned long long PageTableOffset : 9;
            unsigned long long PageDirectoryOffset : 9;
            unsigned long long PageDirectoryPointerOffset : 9;
            unsigned long long PageMapLevel4Offset : 9;
            unsigned long long SignExtend : 16;
        } Page4Kb;
        struct {
            unsigned long long PageOffset : 21;
            unsigned long long PageDirectoryOffset : 9;
            unsigned long long PageDirectoryPointerOffset : 9;
            unsigned long long PageMapLevel4Offset : 9;
            unsigned long long SignExtend : 16;
        } Page2Mb;
        struct {
            unsigned long long PageOffset : 30;
            unsigned long long PageDirectoryPointerOffset : 9;
            unsigned long long PageMapLevel4Offset : 9;
            unsigned long long SignExtend : 16;
        } Page1Gb;
    } x64;
};

union PML4E {
    union {
        unsigned long long Value;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Reserved1 : 2;
            unsigned long long AVL : 3;
            unsigned long long PDP : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page4Kb;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Reserved1 : 2;
            unsigned long long AVL : 3;
            unsigned long long PDP : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page2Mb;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Zero : 1;
            unsigned long long Ignored1 : 1;
            unsigned long long AVL : 3;
            unsigned long long PDP : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page1Gb;
    } x64;
};

union PDPE {
    union {
        union {
            unsigned long long Value;
            struct {
                unsigned long long P : 1;
                unsigned long long Reserved0 : 2;
                unsigned long long PWT : 1;
                unsigned long long PCD : 1;
                unsigned long long Reserved1 : 4;
                unsigned long long AVL : 3;
                unsigned long long PT : 40;
                unsigned long long Reserved : 12;
            } Pae4Kb;
            struct {
                unsigned long long P : 1;
                unsigned long long Reserved0 : 2;
                unsigned long long PWT : 1;
                unsigned long long PCD : 1;
                unsigned long long Reserved1 : 4;
                unsigned long long AVL : 3;
                unsigned long long PT : 40;
                unsigned long long Reserved : 12;
            } Pae2Mb;
        } Pae;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Zero : 1;
            unsigned long long Reserved0 : 1;
            unsigned long long AVL : 3;
            unsigned long long PD : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page4Kb;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Zero : 1;
            unsigned long long Reserved0 : 1;
            unsigned long long AVL : 3;
            unsigned long long PD : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page2Mb;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long D : 1;
            unsigned long long One : 1;
            unsigned long long G : 1;
            unsigned long long AVL : 3;
            unsigned long long PAT : 1;
            unsigned long long Reserved0 : 17;
            unsigned long long PhysicalPageBase : 22;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page1Gb;
    } x64;
};

union PDE {
    union {
        union {
            unsigned int Value;
            struct {
                unsigned int P : 1;
                unsigned int RW : 1;
                unsigned int US : 1;
                unsigned int PWT : 1;
                unsigned int PCD : 1;
                unsigned int A : 1;
                unsigned int Ignored0 : 1;
                unsigned int Zero : 1;
                unsigned int Ignored1 : 1;
                unsigned int AVL : 3;
                unsigned int PT : 20;
            } Page4Kb;
            struct {
                unsigned int P : 1;
                unsigned int RW : 1;
                unsigned int US : 1;
                unsigned int PWT : 1;
                unsigned int PCD : 1;
                unsigned int A : 1;
                unsigned int D : 1;
                unsigned int One : 1;
                unsigned int G : 1;
                unsigned int AVL : 3;
                unsigned int PAT : 1;
                unsigned int PhysicalPageBaseHigh : 8;
                unsigned int Zero : 1;
                unsigned int PhysicalPageBaseLow : 10;
            } Page4Mb;
        } NonPae;
        union {
            unsigned long long Value;
            struct {
                unsigned long long P : 1;
                unsigned long long RW : 1;
                unsigned long long US : 1;
                unsigned long long PWT : 1;
                unsigned long long PCD : 1;
                unsigned long long A : 1;
                unsigned long long Ignored0 : 1;
                unsigned long long Zero : 1;
                unsigned long long Ignored1 : 1;
                unsigned long long AVL : 3;
                unsigned long long PT : 40;
                unsigned long long Reserved : 11;
                unsigned long long NX : 1;
            } Page4Kb;
            struct {
                unsigned long long P : 1;
                unsigned long long RW : 1;
                unsigned long long US : 1;
                unsigned long long PWT : 1;
                unsigned long long PCD : 1;
                unsigned long long A : 1;
                unsigned long long D : 1;
                unsigned long long One : 1;
                unsigned long long G : 1;
                unsigned long long AVL : 3;
                unsigned long long PAT : 1;
                unsigned long long Reserved0 : 8;
                unsigned long long PhysicalPageBase : 31;
                unsigned long long Reserved1 : 11;
                unsigned long long NX : 1;
            } Page2Mb;
        } Pae;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long Ignored0 : 1;
            unsigned long long Zero : 1;
            unsigned long long Ignored1 : 1;
            unsigned long long AVL : 3;
            unsigned long long PT : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page4Kb;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long D : 1;
            unsigned long long One : 1;
            unsigned long long G : 1;
            unsigned long long AVL : 3;
            unsigned long long PAT : 1;
            unsigned long long Reserved0 : 8;
            unsigned long long PhysicalPageBase : 31;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page2Mb;
    } x64;
};

union PTE {
    union {
        union {
            unsigned int Value;
            struct {
                unsigned int P : 1;
                unsigned int RW : 1;
                unsigned int US : 1;
                unsigned int PWT : 1;
                unsigned int PCD : 1;
                unsigned int A : 1;
                unsigned int D : 1;
                unsigned int Zero : 1;
                unsigned int G : 1;
                unsigned int AVL : 3;
                unsigned int PT : 20;
            } Page4Kb;
        } NonPae;
        union {
            unsigned long long Value;
            struct {
                unsigned long long P : 1;
                unsigned long long RW : 1;
                unsigned long long US : 1;
                unsigned long long PWT : 1;
                unsigned long long PCD : 1;
                unsigned long long A : 1;
                unsigned long long D : 1;
                unsigned long long Zero : 1;
                unsigned long long G : 1;
                unsigned long long AVL : 3;
                unsigned long long PT : 40;
                unsigned long long Reserved : 11;
                unsigned long long NX : 1;
            } Page4Kb;
        } Pae;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long P : 1;
            unsigned long long RW : 1;
            unsigned long long US : 1;
            unsigned long long PWT : 1;
            unsigned long long PCD : 1;
            unsigned long long A : 1;
            unsigned long long D : 1;
            unsigned long long PAT : 1;
            unsigned long long G : 1;
            unsigned long long AVL : 3;
            unsigned long long PhysicalPageBase : 40;
            unsigned long long Available : 11;
            unsigned long long NX : 1;
        } Page4Kb;
    } x64;
};

union CR3 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int Reserved0 : 3;
            unsigned int PWT : 1; // Page-Level Writethrough
            unsigned int PCD : 1; // Page-Level Cache Disable
            unsigned int Reserved1 : 7;
            unsigned int PD : 20; // Page-Directory-Table Base Address
        } NonPae;
        struct {
            unsigned int Reserved0 : 3;
            unsigned int PWT : 1; // Page-Level Writethrough
            unsigned int PCD : 1; // Page-Level Cache Disable
            unsigned int PDP : 27; // Page-Directory-Pointer-Table Base Address
        } Pae;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long Reserved0 : 3;
            unsigned long long PWT : 1; // Page-Level Writethrough
            unsigned long long PCD : 1; // Page-Level Cache Disable
            unsigned long long Reserved1 : 7;
            unsigned long long PML4 : 40; // Page-Map Level-4 Table Base Address
            unsigned long long Reserved2 : 12;
        } Bitmap;
    } x64;
};

union CR4 {
    unsigned long long Value;
    union {
        unsigned int Value;
        struct {
            unsigned int VME : 1; // Virtual 8086-Mode Extensions
            unsigned int PVI : 1; // Protected-Mode Virtual Interrupts
            unsigned int TSD : 1; // Time-Stamp Disable
            unsigned int DE : 1; // Debugging Extensions
            unsigned int PSE : 1; // Page Size Extensions
            unsigned int PAE : 1; // Physical Address Extension
            unsigned int MCE : 1; // Machine Check Enable
            unsigned int PGE : 1; // Page Global Enable
            unsigned int PCE : 1; // Performance-Monitoring Counter Enable
            unsigned int OSFXSR : 1; // Operating-System FXSAVE/FXRSTOR Support
            unsigned int OSXMMEXCPT : 1; // Operating System Unmasked Exception Support
            unsigned int Reserved0 : 5;
            unsigned int FSGSBASE : 1; // Enable RDFSBASE, RDGSBASE, WRFSBASE, WRGSBASE instructions
            unsigned int Reserved1 : 1;
            unsigned int OSXSAVE : 1; // XSAVE and Processor Extended States Enable Bit
            unsigned int Reserved2 : 13;
        } Bitmap;
    } x32;
    union {
        unsigned long long Value;
        struct {
            unsigned long long VME : 1; // Virtual 8086-Mode Extensions
            unsigned long long PVI : 1; // Protected-Mode Virtual Interrupts
            unsigned long long TSD : 1; // Time-Stamp Disable
            unsigned long long DE : 1; // Debugging Extensions
            unsigned long long PSE : 1; // Page Size Extensions
            unsigned long long PAE : 1; // Physical Address Extension
            unsigned long long MCE : 1; // Machine Check Enable
            unsigned long long PGE : 1; // Page Global Enable
            unsigned long long PCE : 1; // Performance-Monitoring Counter Enable
            unsigned long long OSFXSR : 1; // Operating-System FXSAVE/FXRSTOR Support
            unsigned long long OSXMMEXCPT : 1; // Operating System Unmasked Exception Support
            unsigned long long Reserved0 : 5;
            unsigned long long FSGSBASE : 1; // Enable RDFSBASE, RDGSBASE, WRFSBASE, WRGSBASE instructions
            unsigned long long Reserved1 : 1;
            unsigned long long OSXSAVE : 1; // XSAVE and Processor Extended States Enable Bit
            unsigned long long Reserved2 : 45;
        } Bitmap;
    } x64;
};
#pragma pack(pop)