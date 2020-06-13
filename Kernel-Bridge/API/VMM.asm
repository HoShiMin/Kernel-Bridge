.CODE

EXTERN SvmVmexitHandler: PROC
EXTERN VmxVmexitHandler: PROC

; Store LDTR:
_sldt PROC PUBLIC
    sldt WORD PTR [rcx]
    ret
_sldt ENDP

; Store TR:
_str PROC PUBLIC
    str WORD PTR [rcx]
    ret
_str ENDP

__invd PROC PUBLIC
    invd
    ret
__invd ENDP

; VMX-only:
__hyperv_vmcall PROC PUBLIC
    ; RCX - HYPERCALL_INPUT_VALUE
    ; RDX - Input parameters GPA when the Fast flag is 0, otherwise input parameter
    ; R8  - Output parameters GPA when the Fast flag is 0, otherwise output parameter
    ; XMM0..XMM5 can be used in hypervisors with XMM Fast input support
    vmcall

    ; RAX - HYPERCALL_RESULT_VALUE
    ret
__hyperv_vmcall ENDP

; VMX-only:
__kb_vmcall PROC PUBLIC
    ; RCX, RDX, R8, R9 - args
    ; RAX - result
    push r10
    mov r10, 01EE7C0DEh
    vmcall
    pop r10
    ret
__kb_vmcall ENDP

GPR_CONTEXT_ENTRIES equ 15 ; rax, rbx, rcx, rdx, rsi, rdi, rbp, r8..r15
GPR_CONTEXT_SIZE    equ GPR_CONTEXT_ENTRIES * sizeof(QWORD)
XMM_CONTEXT_ENTRIES equ 6 ; xmm0..xmm5
XMM_CONTEXT_SIZE    equ XMM_CONTEXT_ENTRIES * sizeof(OWORD)

CPUID_VMM_SHUTDOWN equ 01EE7C0DEh

; Without RSP saving:
PUSHAQ MACRO
    sub rsp, GPR_CONTEXT_SIZE
    mov [rsp + 0  * sizeof(QWORD)], rax
    mov [rsp + 1  * sizeof(QWORD)], rbx
    mov [rsp + 2  * sizeof(QWORD)], rcx
    mov [rsp + 3  * sizeof(QWORD)], rdx
    mov [rsp + 4  * sizeof(QWORD)], rsi
    mov [rsp + 5  * sizeof(QWORD)], rdi
    mov [rsp + 6  * sizeof(QWORD)], rbp
    mov [rsp + 7  * sizeof(QWORD)], r8
    mov [rsp + 8  * sizeof(QWORD)], r9
    mov [rsp + 9  * sizeof(QWORD)], r10
    mov [rsp + 10 * sizeof(QWORD)], r11
    mov [rsp + 11 * sizeof(QWORD)], r12
    mov [rsp + 12 * sizeof(QWORD)], r13
    mov [rsp + 13 * sizeof(QWORD)], r14
    mov [rsp + 14 * sizeof(QWORD)], r15
ENDM

; Without RSP restoring:
POPAQ MACRO
    mov rax, [rsp + 0  * sizeof(QWORD)]
    mov rbx, [rsp + 1  * sizeof(QWORD)]
    mov rcx, [rsp + 2  * sizeof(QWORD)]
    mov rdx, [rsp + 3  * sizeof(QWORD)]
    mov rsi, [rsp + 4  * sizeof(QWORD)]
    mov rdi, [rsp + 5  * sizeof(QWORD)]
    mov rbp, [rsp + 6  * sizeof(QWORD)]
    mov r8 , [rsp + 7  * sizeof(QWORD)]
    mov r9 , [rsp + 8  * sizeof(QWORD)]
    mov r10, [rsp + 9  * sizeof(QWORD)]
    mov r11, [rsp + 10 * sizeof(QWORD)]
    mov r12, [rsp + 11 * sizeof(QWORD)]
    mov r13, [rsp + 12 * sizeof(QWORD)]
    mov r14, [rsp + 13 * sizeof(QWORD)]
    mov r15, [rsp + 14 * sizeof(QWORD)]
    add rsp, GPR_CONTEXT_SIZE
ENDM

PUSHAXMM MACRO
    sub rsp, XMM_CONTEXT_SIZE
    movaps [rsp + 0 * sizeof(OWORD)], xmm0
    movaps [rsp + 1 * sizeof(OWORD)], xmm1
    movaps [rsp + 2 * sizeof(OWORD)], xmm2
    movaps [rsp + 3 * sizeof(OWORD)], xmm3
    movaps [rsp + 4 * sizeof(OWORD)], xmm4
    movaps [rsp + 5 * sizeof(OWORD)], xmm5
ENDM

POPAXMM MACRO
    movaps xmm0, [rsp + 0 * sizeof(OWORD)]
    movaps xmm1, [rsp + 1 * sizeof(OWORD)]
    movaps xmm2, [rsp + 2 * sizeof(OWORD)]
    movaps xmm3, [rsp + 3 * sizeof(OWORD)]
    movaps xmm4, [rsp + 4 * sizeof(OWORD)]
    movaps xmm5, [rsp + 5 * sizeof(OWORD)]
    add rsp, XMM_CONTEXT_SIZE
ENDM

PROLOGUE MACRO
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov [rsp + 0 * sizeof(QWORD)], rcx
    mov [rsp + 1 * sizeof(QWORD)], rdx
    mov [rsp + 2 * sizeof(QWORD)], r8
    mov [rsp + 3 * sizeof(QWORD)], r9
ENDM

EPILOGUE MACRO
    mov rcx, [rsp + 0 * sizeof(QWORD)]
    mov rdx, [rsp + 1 * sizeof(QWORD)]
    mov r8 , [rsp + 2 * sizeof(QWORD)]
    mov r9 , [rsp + 3 * sizeof(QWORD)]
    add rsp, 32
    pop rbp
    ret
ENDM

; SvmVmmRun(INITIAL_VMM_STACK_LAYOUT* VmmStack):
SvmVmmRun PROC PUBLIC
    ; RCX - VmmStack pointer
    mov rsp, rcx ; Switch to the VMM stack

    ; RSP -> INITIAL_VMM_STACK_LAYOUT:
    ; RSP + 0  -> PVOID GuestVmcbPa
    ; RSP + 8  -> PVOID HostVmcbPa
    ; RSP + 16 -> PRIVATE_VM_DATA* Private

VmmLoop:
    mov rax, [rsp] ; RAX -> GuestVmcbPa

    vmload rax ; Load previously saved guest state
    vmrun rax

    ; Registers restored by the host's values:
    ;  RAX, RSP, RIP
    ;  GDTR, IDTR
    ;  EFER
    ;  CR0, CR3, CR4, DR7, CPL = 0
    ;  ES.sel, CS.sel, SS.sel, DS.sel

    ; #VMEXIT occured, save the guest state to the guest VMCB:
    vmsave rax ; RAX was restored to host's state (RAX -> GuestVmcbPa)

    ; On #VMEXIT we have the guest context, so save it to the stack:
    PUSHAQ
    mov rcx, [rsp + GPR_CONTEXT_SIZE + 16] ; RCX -> PRIVATE_VM_DATA* Private
    mov rdx, rsp ; RDX -> Guest context

    PUSHAXMM
    sub rsp, 32 ; Homing space for the x64 call convention
    call SvmVmexitHandler ; VMM_STATUS SvmVmexitHandler(PRIVATE_VM_DATA* Private, GUEST_CONTEXT* Context)
    add rsp, 32
    POPAXMM

    test al, al ; if (!SvmVmexitHandler(...)) break;
    jz VmmExit

    POPAQ
    jmp VmmLoop

VmmExit:
    POPAQ

    ; Exiting the virtual state:
    ; This context is setted up in the SvmVmexitHandler:
    ;  RBX -> Guest's RIP
    ;  RCX -> Guest's RSP
    ;  EDX:EAX -> Address of the PRIVATE_VM_DATA to free

    mov rsp, rcx
    mov ecx, CPUID_VMM_SHUTDOWN ; Signature that says about the VM shutdown
    jmp rbx
SvmVmmRun ENDP


__invept PROC PUBLIC
    ; RCX - INVEPT_TYPE
    ; RDX - INVEPT_DESCRIPTOR
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

__invvpid PROC PUBLIC
    ; RCX - INVVPID_TYPE
    ; RDX - INVVPID_DESCRIPTOR
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

VmxVmmRun PROC PUBLIC
    PUSHAQ
    mov rcx, [rsp + GPR_CONTEXT_SIZE + 16]
    mov rdx, rsp

    PUSHAXMM
    sub rsp, 32 ; Homing space for the x64 call convention
    call VmxVmexitHandler ; VMM_STATUS VmxVmexitHandler(PRIVATE_VM_DATA* Private, GUEST_CONTEXT* Context)
    add rsp, 32
    POPAXMM

    test al, al ; if (!SvmVmexitHandler(...)) break;
    jz VmmExit

    POPAQ
    vmresume

VmmExit:
    POPAQ

    ; Exiting the virtual state:
    ; This context is setted up in the SvmVmexitHandler:
    ;  RBX -> Guest's RIP
    ;  RCX -> Guest's RSP
    ;  EDX:EAX -> Address of the PRIVATE_VM_DATA to free

    mov rsp, rcx
    mov ecx, CPUID_VMM_SHUTDOWN ; Signature that says about the VM shutdown
    jmp rbx
VmxVmmRun ENDP

END