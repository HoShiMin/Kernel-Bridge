#pragma once

enum class INTERRUPT_VECTOR
{
    DivideError = 0,                 // #DE, DIV and IDIV instructions
    Debug = 1,                       // #DB, any code or data reference
    NmiInterrupt = 2,                //      Non-maskable interrupt
    Breakpoint = 3,                  // #BP, INT3 instruction
    Overflow = 4,                    // #OF, INT0 instruction
    BoundRangeExceeded = 5,          // #BR, BOUND instruction
    InvalidOpcode = 6,               // #UD, UD instruction or reserved opcode
    DeviceNotAvailable = 7,          // #NM, No math coprocoessor (floating point or WAIT/FWAIT instruction)
    DoubleFault = 8,                 // #DF, Any instruction that can generate an exception, an NMI or an INTR
    CoProcessorSegmentOverrun = 9,   // #MF, Floating-point instruction
    InvalidTss = 10,                 // #TS, Task switch or TSS access
    SegmentNotPresent = 11,          // #NP, Loading segment register or accessing system segments
    StackSegmentFault = 12,          // #SS, Stack operations and SS register loads
    GeneralProtection = 13,          // #GP, Any memory reference and other protection checks
    PageFault = 14,                  // #PF, Any memory reference
    Reserved = 15,
    FloatingPointError = 16,         // #MF, Floating-point or WAIT/FWAIT instruction
    AlignmentCheck = 17,             // #AC, Any data reference in memory
    MachineCheck = 18,               // #MC, Error codes (if any) and source are model-dependent
    SimdFloatingPointException = 19, // #XM, SIMD floating-point instruction
    VirtualizationException = 20,    // #VE, EPT violations
    ControlProtectionException = 21, // #CP, The RET, IRET, RSTORSSP, SETSSBSY, and ENDBRANCH (whet CET is enabled) instructions
    // 22..31 are reserved
    // 32..255 are maskable interrupts (external interrupt from INTR pin or INTn instruction
};