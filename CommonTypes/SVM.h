#pragma once

namespace SVM {
    struct VMCB_CONTROL_AREA {
        union {
            unsigned int Value;
            struct {
                union {
                    unsigned short Value; // Interception of CR0..CR15 reads
                    struct {
                        unsigned short ReadCr0 : 1;
                        unsigned short ReadCr1 : 1;
                        unsigned short ReadCr2 : 1;
                        unsigned short ReadCr3 : 1;
                        unsigned short ReadCr4 : 1;
                        unsigned short ReadCr5 : 1;
                        unsigned short ReadCr6 : 1;
                        unsigned short ReadCr7 : 1;
                        unsigned short ReadCr8 : 1;
                        unsigned short ReadCr9 : 1;
                        unsigned short ReadCr10 : 1;
                        unsigned short ReadCr11 : 1;
                        unsigned short ReadCr12 : 1;
                        unsigned short ReadCr13 : 1;
                        unsigned short ReadCr14 : 1;
                        unsigned short ReadCr15 : 1;
                    } Bitmap;
                } Read;
                union {
                    unsigned short Value; // Interception of CR0..CR15 writes
                    struct {
                        unsigned short WriteCr0 : 1;
                        unsigned short WriteCr1 : 1;
                        unsigned short WriteCr2 : 1;
                        unsigned short WriteCr3 : 1;
                        unsigned short WriteCr4 : 1;
                        unsigned short WriteCr5 : 1;
                        unsigned short WriteCr6 : 1;
                        unsigned short WriteCr7 : 1;
                        unsigned short WriteCr8 : 1;
                        unsigned short WriteCr9 : 1;
                        unsigned short WriteCr10 : 1;
                        unsigned short WriteCr11 : 1;
                        unsigned short WriteCr12 : 1;
                        unsigned short WriteCr13 : 1;
                        unsigned short WriteCr14 : 1;
                        unsigned short WriteCr15 : 1;
                    } Bitmap;
                } Write;
            } RW;
        } InterceptCr;
        union {
            unsigned int Value;
            struct {
                union {
                    unsigned short Value; // Interception of CR0..CR15 reads
                    struct {
                        unsigned short ReadDr0 : 1;
                        unsigned short ReadDr1 : 1;
                        unsigned short ReadDr2 : 1;
                        unsigned short ReadDr3 : 1;
                        unsigned short ReadDr4 : 1;
                        unsigned short ReadDr5 : 1;
                        unsigned short ReadDr6 : 1;
                        unsigned short ReadDr7 : 1;
                        unsigned short ReadDr8 : 1;
                        unsigned short ReadDr9 : 1;
                        unsigned short ReadDr10 : 1;
                        unsigned short ReadDr11 : 1;
                        unsigned short ReadDr12 : 1;
                        unsigned short ReadDr13 : 1;
                        unsigned short ReadDr14 : 1;
                        unsigned short ReadDr15 : 1;
                    } Bitmap;
                } Read;
                union {
                    unsigned short Value; // Interception of CR0..CR15 writes
                    struct {
                        unsigned short WriteDr0 : 1;
                        unsigned short WriteDr1 : 1;
                        unsigned short WriteDr2 : 1;
                        unsigned short WriteDr3 : 1;
                        unsigned short WriteDr4 : 1;
                        unsigned short WriteDr5 : 1;
                        unsigned short WriteDr6 : 1;
                        unsigned short WriteDr7 : 1;
                        unsigned short WriteDr8 : 1;
                        unsigned short WriteDr9 : 1;
                        unsigned short WriteDr10 : 1;
                        unsigned short WriteDr11 : 1;
                        unsigned short WriteDr12 : 1;
                        unsigned short WriteDr13 : 1;
                        unsigned short WriteDr14 : 1;
                        unsigned short WriteDr15 : 1;
                    } Bitmap;
                } Write;
            } RW;
        } InterceptDr;
        union {
            unsigned int Value;
            struct {
                unsigned int InterceptionVector0 : 1;
                unsigned int InterceptionVector1 : 1;
                unsigned int InterceptionVector2 : 1;
                unsigned int InterceptionVector3 : 1;
                unsigned int InterceptionVector4 : 1;
                unsigned int InterceptionVector5 : 1;
                unsigned int InterceptionVector6 : 1;
                unsigned int InterceptionVector7 : 1;
                unsigned int InterceptionVector8 : 1;
                unsigned int InterceptionVector9 : 1;
                unsigned int InterceptionVector10 : 1;
                unsigned int InterceptionVector11 : 1;
                unsigned int InterceptionVector12 : 1;
                unsigned int InterceptionVector13 : 1;
                unsigned int InterceptionVector14 : 1;
                unsigned int InterceptionVector15 : 1;
                unsigned int InterceptionVector16 : 1;
                unsigned int InterceptionVector17 : 1;
                unsigned int InterceptionVector18 : 1;
                unsigned int InterceptionVector19 : 1;
                unsigned int InterceptionVector20 : 1;
                unsigned int InterceptionVector21 : 1;
                unsigned int InterceptionVector22 : 1;
                unsigned int InterceptionVector23 : 1;
                unsigned int InterceptionVector24 : 1;
                unsigned int InterceptionVector25 : 1;
                unsigned int InterceptionVector26 : 1;
                unsigned int InterceptionVector27 : 1;
                unsigned int InterceptionVector28 : 1;
                unsigned int InterceptionVector29 : 1;
                unsigned int InterceptionVector30 : 1;
                unsigned int InterceptionVector31 : 1;
            } Bitmap;
        } InterceptExceptions;
        unsigned int InterceptIntr : 1; // Physical maskable interrupt
        unsigned int InterceptNmi : 1;
        unsigned int InterceptSmi : 1;
        unsigned int InterceptInit : 1;
        unsigned int InterceptVirtualIntr : 1; // Virtual maskable interrupt
        unsigned int InterceptCr0WritesOther : 1; // Intercept CR0 writes that change bits other than CR0.TS or CR0.MP
        unsigned int InterceptIdtrRead : 1;
        unsigned int InterceptGdtrRead : 1;
        unsigned int InterceptLdtrRead : 1;
        unsigned int InterceptTrRead : 1;
        unsigned int InterceptIdtrWrite : 1;
        unsigned int InterceptGdtrWrite : 1;
        unsigned int InterceptLdtrWrite : 1;
        unsigned int InterceptTrWrite : 1;
        unsigned int InterceptRdtsc : 1;
        unsigned int InterceptRdpmc : 1;
        unsigned int InterceptPushf : 1;
        unsigned int InterceptPopf : 1;
        unsigned int InterceptCpuid : 1;
        unsigned int InterceptRsm : 1;
        unsigned int InterceptIret : 1;
        unsigned int InterceptInt : 1; // Intercept Int N instruction
        unsigned int InterceptInvd : 1;
        unsigned int InterceptPause : 1;
        unsigned int InterceptHlt : 1;
        unsigned int InterceptInvlpg : 1;
        unsigned int InterceptInvlpga : 1;
        unsigned int InterceptIoIo : 1; // Intercept IN and OUT accesses to selected ports
        unsigned int InterceptMsr : 1; // Intercept RDMSR and WRMSR accesses to selected MSRs
        unsigned int InterceptTaskSwitched : 1;
        unsigned int InterceptFerrFreeze : 1; // Intercept processor "freezing" during legacy FERR handling
        unsigned int InterceptShutdown : 1; // Intercept shutdown events
        unsigned short InterceptVmrun : 1;
        unsigned short InterceptVmcall : 1;
        unsigned short InterceptVmload : 1;
        unsigned short InterceptVmsave : 1;
        unsigned short InterceptStgi : 1;
        unsigned short InterceptClgi : 1;
        unsigned short InterceptSkinit : 1;
        unsigned short InterceptRdtscp : 1;
        unsigned short InterceptIcebp : 1;
        unsigned short InterceptWbinvd : 1;
        unsigned short InterceptMonitor : 1;
        unsigned short InterceptMwaitUnconditionally : 1; // Intercept MWAIT instruction unconditionally
        unsigned short InterceptMwaitIfMonitorHwIsArmed : 1; // Intercept MWAIT instruction if monitor hardware is armed
        unsigned short InterceptXsetbv : 1;
        unsigned short Reserved0 : 1; // Should be zero
        unsigned short InterceptEferWrite : 1; // Occures after guest instruction finishes
        union {
            unsigned short Value;
            struct {
                unsigned short InterceptCr0WriteAfter : 1;
                unsigned short InterceptCr1WriteAfter : 1;
                unsigned short InterceptCr2WriteAfter : 1;
                unsigned short InterceptCr3WriteAfter : 1;
                unsigned short InterceptCr4WriteAfter : 1;
                unsigned short InterceptCr5WriteAfter : 1;
                unsigned short InterceptCr6WriteAfter : 1;
                unsigned short InterceptCr7WriteAfter : 1;
                unsigned short InterceptCr8WriteAfter : 1;
                unsigned short InterceptCr9WriteAfter : 1;
                unsigned short InterceptCr10WriteAfter : 1;
                unsigned short InterceptCr11WriteAfter : 1;
                unsigned short InterceptCr12WriteAfter : 1;
                unsigned short InterceptCr13WriteAfter : 1;
                unsigned short InterceptCr14WriteAfter : 1;
                unsigned short InterceptCr15WriteAfter : 1;
            } Bitmap;
        } InterceptCrWritesAfter; // Occures after guest instruction finishes
        unsigned char Reserved1[40]; // Should be zero
        unsigned short PauseFilterThreshold;
        unsigned short PauseFilterCount;
        unsigned long long IopmBasePa; // Physical base address of IOPM,  bits 11:0 are ignored
        unsigned long long MsrpmBasePa; // Physical base address of MSRPM, bits 11:0 are ignored
        unsigned long long TscOffset; // To be added in RDTSC and RDTSCP
        unsigned int GuestAsid;
        union {
            unsigned int Value;
            struct {
                unsigned int TlbControl : 8; // 0x00 - Do nothing
                                             // 0x01 - Flush entire TLB (all entries, all ASIDs) on VMRUN (for legacy hypervisors)
                                             // 0x03 - Flush the guest's TLB entries
                                             // 0x07 - Flush the guest's non-global TLB entries
                                             // All other encodings are reserved
                unsigned int Reserved2 : 24;
            } Bitmap;
        } TlbControl;
        union {
            unsigned long long Value;
            struct {
                unsigned long long VirtualTpr : 8; // Virtual TPR for the guest (3:0 = 4-bit virtual TPR value, 7:4 should be zero), written back to the VMCB at #VMEXIT
                unsigned long long VirtualIrq : 1; // If nonzero, virtual INTR is pending, ignored on VMRUN if AVIC is enabled, written back to the VMCB at #VMEXIT
                unsigned long long VirtualGif : 1; // 0 - virtual interrupts are masked, 1 - unmasked
                unsigned long long Reserved0 : 6;
                unsigned long long VirtualIntrPriority : 4; // Priority for virtual interrupt, ignored on VMRUN if AVIC is enabled
                unsigned long long VirtualIgnoreTpr : 1; // If nonzero, the current virtual interrupt ignores (virtual) TPR, ignored on VMRUN if AVIC is enabled
                unsigned long long Reserved1 : 3;
                unsigned long long VirtualIntrMasking : 1; // Virtualize masking of INTR interrupts
                unsigned long long VirtualGifEnabled : 1; // 0 - Disabled, 1 - Enabled for this guest
                unsigned long long Reserved2 : 5;
                unsigned long long AvicEnable : 1;
                unsigned long long VirtualIntrVector : 8; // Vector to use for this interrupt, ignored on VMRUN if AVIC is enabled
                unsigned long long Reserved3 : 24;
            } Bitmap;
        } VirtualIntr;
        union {
            unsigned long long Value;
            struct {
                unsigned long long InterruptShadow : 1; // Guest is in an interrupt shadow
                unsigned long long GuestInterruptMask : 1; // Value of the RFLAGS.IF for the guest, written back to the VMCB at #VMEXIT, not used on VMRUN
                unsigned long long Reserved : 62;
            } Bitmap;
        } InterruptShadow;
        unsigned long long ExitCode;
        unsigned long long ExitInfo1;
        unsigned long long ExitInfo2;
        unsigned long long ExitIntInfo;
        unsigned long long NpEnable : 1; // Nested paging
        unsigned long long EnableSev : 1; // Secure Encrypted Virtualization
        unsigned long long EnabledEncryptedState : 1; // Enable encrypted state for SEV
        unsigned long long Reserved2 : 61; // Should be zero
        unsigned long long AvicApicBar : 52; // Address must be 4-Kbyte aligned
        unsigned long long Reserved3 : 12;
        unsigned long long GuestGhcbPa; // Guest physical address of GHCB
        unsigned long long EventInjection;
        unsigned long long NestedPageTableCr3; // Nested page table CR3 to use for nested paging
        unsigned long long LbrVirtualizationEnable : 1; // 0 - Do nothing, 1 - Enable LBR virtualization hardware acceleration
        unsigned long long VirtualizedVmsaveVmload : 1;
        unsigned long long Reserved4 : 62;
        unsigned long long VmcbCleanBits : 32;
        unsigned long long Reserved5 : 32;
        unsigned long long NextRip; // Next sequential instruction pointer
        unsigned char NumberOfBytesFetched;
        unsigned char GuestInstructionBytes[15];
        unsigned long long AvicApicBackingPageAddr : 52; // Must be 4-Kbyte aligned
        unsigned long long Reserved6 : 12;
        unsigned long long Reserved7;
        union {
            unsigned long long Value;
            struct {
                unsigned long long AvicLogicalMaxIndex : 8;
                unsigned long long Reserved0 : 4;
                unsigned long long AvicLogicalTableAddr : 40; // Must be 4-Kbyte aligned
                unsigned long long Reserved1 : 12;
            } Bitmap;
        } AvicLogicalTable;
        union {
            unsigned long long Value;
            struct {
                unsigned long long AvicPhysicalMaxIndex : 8;
                unsigned long long Reserved0 : 4;
                unsigned long long AvicPhysicalTableAddr : 40; // Must be 4-Kbyte aligned
                unsigned long long Reserved1 : 12;
            } Bitmap;
        } AvicPhysicalTable;
        unsigned long long Reserved8;
        unsigned long long Reserved9 : 12;
        unsigned long long VmcbSaveStatePointer : 40;
        unsigned long long Reserved10 : 12;
        unsigned char Reserved11[752]; // Final padding to 0x400 size
    };

    struct VMCB_STATE_SAVE_AREA {
        union VMCB_SEGMENT_ATTRIBUTE {
            unsigned short Value;
            struct {
                unsigned short Type : 4;
                unsigned short System : 1;
                unsigned short Dpl : 2;
                unsigned short Present : 1;
                unsigned short Available : 1;
                unsigned short LongMode : 1;
                unsigned short DefaultOperandSize : 1;
                unsigned short Granularity : 1;
                unsigned short Reserved : 4;
            } Bitmap;
        };
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base; // Only lower 32 bits are implemented
        } Es;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base; // Only lower 32 bits are implemented
        } Cs;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base; // Only lower 32 bits are implemented
        } Ss;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base; // Only lower 32 bits are implemented
        } Ds;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base;
        } Fs;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base;
        } Gs;
        struct {
            unsigned short Selector; // Reserved
            VMCB_SEGMENT_ATTRIBUTE Attrib; // Reserved
            unsigned int Limit; // Only lower 16 bits are implemented
            unsigned long long Base;
        } Gdtr;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base;
        } Ldtr;
        struct {
            unsigned short Selector; // Reserved
            VMCB_SEGMENT_ATTRIBUTE Attrib; // Reserved
            unsigned int Limit; // Only lower 16 bits are implemented
            unsigned long long Base;
        } Idtr;
        struct {
            unsigned short Selector;
            VMCB_SEGMENT_ATTRIBUTE Attrib;
            unsigned int Limit;
            unsigned long long Base;
        } Tr;
        unsigned char Reserved0[43];
        unsigned char Cpl; // If the guest is in real-mode, CPL forced to 0, if the guest in virtual-mode, CPL forced to 3
        unsigned int Reserved1;
        unsigned long long Efer;
        unsigned char Reserved2[112];
        unsigned long long Cr4;
        unsigned long long Cr3;
        unsigned long long Cr0;
        unsigned long long Dr7;
        unsigned long long Dr6;
        unsigned long long Rflags;
        unsigned long long Rip;
        unsigned char Reserved3[88];
        unsigned long long Rsp;
        unsigned char Reserved4[24];
        unsigned long long Rax;
        unsigned long long Star;
        unsigned long long Lstar;
        unsigned long long Cstar;
        unsigned long long Sfmask;
        unsigned long long KernelGsBase;
        unsigned long long SysenterCs;
        unsigned long long SysenterEsp;
        unsigned long long SysenterEip;
        unsigned long long Cr2;
        unsigned char Reserved5[32];
        unsigned long long GuestPat;     // Guest PAT - only used if nested paging enabled
        unsigned long long DbgCtl;       // Guest debug ctl MSR - only used if HW acceleration is enabled by VMCB.LBR_VIRTUALIZATION_ENABLE
        unsigned long long BrFrom;       // Guest LastBranchFromIP MSR - only used if HW acceleration of LBR virtualization is supported and enabled
        unsigned long long BrTo;         // Guest LastBranchToIP MSR - only used if HW acceleration of LBR virtualization is supported and enabled
        unsigned long long LastExcpFrom; // Guest LastIntFromIP MSR - only used if HW acceleration of LBR virtualization is supported and enabled
        unsigned long long LastExcpTo;   // Guest LastIntToIP MSR - only used if HW acceleration of LBR virtualization is supported and enabled
    };

    struct VMCB {
        VMCB_CONTROL_AREA ControlArea;
        VMCB_STATE_SAVE_AREA StateSaveArea;
        unsigned char Reserved[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
    };
    static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400, "Size of VMCB Control Area != 0x400 bytes");
    static_assert(sizeof(VMCB_STATE_SAVE_AREA) == 0x298, "Size of VMCB State Save Area != 0x298 bytes");
    static_assert(sizeof(VMCB) == 0x1000, "Size of VMCB != 0x1000 bytes");

    union EVENTINJ {
        unsigned long long Value;
        struct {
            unsigned long long Vector : 8; // IDT vector of the interrupt/exception (ignored if Type == 2)
            unsigned long long Type : 2; // 0 = External/virtual interrupt (INTR), 2 = NMI, 3 = Exception (fault/trap), 4 = Software interrupt (INTn instruction)
            unsigned long long ErrorCodeValid : 1; // 1 - Exception should push an error code onto the stack
            unsigned long long Reserved : 19;
            unsigned long long Valid : 1; // 1 - Event is to be injected into the guest
            unsigned long long ErrorCode : 32; // This error code will be pushed onto the stack if the ErrorCodeValid == 1
        } Bitmap;
    };
    static_assert(sizeof(EVENTINJ) == sizeof(unsigned long long), "Size of EVEINTINJ != sizeof(unsigned long long)");

    // 2 bits per MSR:
    union MSRPM {
        unsigned char Msrpm[2048 * 4];
        struct {
            unsigned char Msrpm0[2048]; // 0000_0000 to 0000_1FFF
            unsigned char Msrpm1[2048]; // C000_0000 to C000_1FFF
            unsigned char Msrpm2[2048]; // C001_0000 to C001_1FFF
            unsigned char Msrpm3[2048]; // Reserved
        } Vectors;
    };
    static_assert(sizeof(MSRPM) == 8192, "Size of MSRPM != 8192 bytes");

    enum SVM_EXIT_CODE {
        VMEXIT_INVALID = -1,
        VMEXIT_CR0_READ,
        VMEXIT_CR1_READ,
        VMEXIT_CR2_READ,
        VMEXIT_CR3_READ,
        VMEXIT_CR4_READ,
        VMEXIT_CR5_READ,
        VMEXIT_CR6_READ,
        VMEXIT_CR7_READ,
        VMEXIT_CR8_READ,
        VMEXIT_CR9_READ,
        VMEXIT_CR10_READ,
        VMEXIT_CR11_READ,
        VMEXIT_CR12_READ,
        VMEXIT_CR13_READ,
        VMEXIT_CR14_READ,
        VMEXIT_CR15_READ,
        VMEXIT_CR0_WRITE,
        VMEXIT_CR1_WRITE,
        VMEXIT_CR2_WRITE,
        VMEXIT_CR3_WRITE,
        VMEXIT_CR4_WRITE,
        VMEXIT_CR5_WRITE,
        VMEXIT_CR6_WRITE,
        VMEXIT_CR7_WRITE,
        VMEXIT_CR8_WRITE,
        VMEXIT_CR9_WRITE,
        VMEXIT_CR10_WRITE,
        VMEXIT_CR11_WRITE,
        VMEXIT_CR12_WRITE,
        VMEXIT_CR13_WRITE,
        VMEXIT_CR14_WRITE,
        VMEXIT_CR15_WRITE,
        VMEXIT_DR0_READ,
        VMEXIT_DR1_READ,
        VMEXIT_DR2_READ,
        VMEXIT_DR3_READ,
        VMEXIT_DR4_READ,
        VMEXIT_DR5_READ,
        VMEXIT_DR6_READ,
        VMEXIT_DR7_READ,
        VMEXIT_DR8_READ,
        VMEXIT_DR9_READ,
        VMEXIT_DR10_READ,
        VMEXIT_DR11_READ,
        VMEXIT_DR12_READ,
        VMEXIT_DR13_READ,
        VMEXIT_DR14_READ,
        VMEXIT_DR15_READ,
        VMEXIT_DR0_WRITE,
        VMEXIT_DR1_WRITE,
        VMEXIT_DR2_WRITE,
        VMEXIT_DR3_WRITE,
        VMEXIT_DR4_WRITE,
        VMEXIT_DR5_WRITE,
        VMEXIT_DR6_WRITE,
        VMEXIT_DR7_WRITE,
        VMEXIT_DR8_WRITE,
        VMEXIT_DR9_WRITE,
        VMEXIT_DR10_WRITE,
        VMEXIT_DR11_WRITE,
        VMEXIT_DR12_WRITE,
        VMEXIT_DR13_WRITE,
        VMEXIT_DR14_WRITE,
        VMEXIT_DR15_WRITE,
        VMEXIT_EXCP0,
        VMEXIT_EXCP1,
        VMEXIT_EXCP2,
        VMEXIT_EXCP3,
        VMEXIT_EXCP4,
        VMEXIT_EXCP5,
        VMEXIT_EXCP6,
        VMEXIT_EXCP7,
        VMEXIT_EXCP8,
        VMEXIT_EXCP9,
        VMEXIT_EXCP10,
        VMEXIT_EXCP11,
        VMEXIT_EXCP12,
        VMEXIT_EXCP13,
        VMEXIT_EXCP14,
        VMEXIT_EXCP15,
        VMEXIT_EXCP16,
        VMEXIT_EXCP17,
        VMEXIT_EXCP18,
        VMEXIT_EXCP19,
        VMEXIT_EXCP20,
        VMEXIT_EXCP21,
        VMEXIT_EXCP22,
        VMEXIT_EXCP23,
        VMEXIT_EXCP24,
        VMEXIT_EXCP25,
        VMEXIT_EXCP26,
        VMEXIT_EXCP27,
        VMEXIT_EXCP28,
        VMEXIT_EXCP29,
        VMEXIT_EXCP30,
        VMEXIT_EXCP31,
        VMEXIT_INTR,
        VMEXIT_NMI,
        VMEXIT_SMI,
        VMEXIT_INIT,
        VMEXIT_VINTR,
        VMEXIT_CR0_SEL_WRITE,
        VMEXIT_IDTR_READ,
        VMEXIT_GDTR_READ,
        VMEXIT_LDTR_READ,
        VMEXIT_TR_READ,
        VMEXIT_IDTR_WRITE,
        VMEXIT_GDTR_WRITE,
        VMEXIT_LDTR_WRITE,
        VMEXIT_TR_WRITE,
        VMEXIT_RDTSC,
        VMEXIT_RDPMC,
        VMEXIT_PUSHF,
        VMEXIT_POPF,
        VMEXIT_CPUID,
        VMEXIT_RSM,
        VMEXIT_IRET,
        VMEXIT_SWINT,
        VMEXIT_INVD,
        VMEXIT_PAUSE,
        VMEXIT_HLT,
        VMEXIT_INVLPG,
        VMEXIT_INVLPGA,
        VMEXIT_IOIO,
        VMEXIT_MSR,
        VMEXIT_TASK_SWITCH,
        VMEXIT_FERR_FREEZE,
        VMEXIT_SHUTDOWN,
        VMEXIT_VMRUN,
        VMEXIT_VMMCALL,
        VMEXIT_VMLOAD,
        VMEXIT_VMSAVE,
        VMEXIT_STGI,
        VMEXIT_CLGI,
        VMEXIT_SKINIT,
        VMEXIT_RDTSCP,
        VMEXIT_ICEBP,
        VMEXIT_WBINVD,
        VMEXIT_MONITOR,
        VMEXIT_MWAIT,
        VMEXIT_MWAIT_CONDITIONAL,
        VMEXIT_XSETBV,
        VMEXIT_EFER_WRITE_TRAP,
        VMEXIT_CR0_WRITE_TRAP,
        VMEXIT_CR1_WRITE_TRAP,
        VMEXIT_CR2_WRITE_TRAP,
        VMEXIT_CR3_WRITE_TRAP,
        VMEXIT_CR4_WRITE_TRAP,
        VMEXIT_CR5_WRITE_TRAP,
        VMEXIT_CR6_WRITE_TRAP,
        VMEXIT_CR7_WRITE_TRAP,
        VMEXIT_CR8_WRITE_TRAP,
        VMEXIT_CR9_WRITE_TRAP,
        VMEXIT_CR10_WRITE_TRAP,
        VMEXIT_CR11_WRITE_TRAP,
        VMEXIT_CR12_WRITE_TRAP,
        VMEXIT_CR13_WRITE_TRAP,
        VMEXIT_CR14_WRITE_TRAP,
        VMEXIT_CR15_WRITE_TRAP,
        VMEXIT_NPF = 0x400,
        AVIC_INCOMPLETE_IPI,
        AVIC_NOACCEL,
        VMEXIT_VMGEXIT
    };
}