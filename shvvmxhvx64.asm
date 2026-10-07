;++
;
; Copyright (c) Alex Ionescu.  All rights reserved.
;
; Module:
;
;    shvvmxhvx64.asm
;
; Abstract:
;
;    This module implements the AMD64-specific SimpleVisor VMENTRY routine.
;
; Author:
;
;    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version
;
; Environment:
;
;    Kernel mode only.
;
;--

    .code

    extern ShvVmxEntryHandler:proc
    extern ShvOsCaptureContext:proc

    ShvVmxEntry PROC
    push    rcx                 ; save the RCX register, which we spill below
    lea     rcx, [rsp+8h]       ; store the context in the stack, bias for
                                ; the return address and the push we just did.
    call    ShvOsCaptureContext ; save the current register state.
                                ; note that this is a specially written function
                                ; which has the following key characteristics:
                                ;   1) it does not taint the value of RCX
                                ;   2) it does not spill any registers, nor
                                ;      expect home space to be allocated for it
    jmp     ShvVmxEntryHandler  ; jump to the C code handler. we assume that it
                                ; compiled with optimizations and does not use
                                ; home space, which is true of release builds.
    ShvVmxEntry ENDP

    ShvVmxCall PROC
    mov     rax, rcx            ; first argument is the magic value
    xor     rcx, rcx            ; clear RCX before VMCALL
    vmcall                      ; causes VM-exit to our handler
    mov     rax, rcx            ; return whatever handler put in RCX
    ret
    ShvVmxCall ENDP

    ;
    ; ShvVmxInvept(Type: UINT64 rcx, Descriptor: VOID* rdx)
    ;
    ; Invalida as traducoes cacheadas do EPT TLB.
    ;   rcx = tipo: 1 = single context (invalida o EPTP atual)
    ;               2 = all contexts  (invalida todos os EPTPs)
    ;   rdx = ponteiro para o descritor de 16 bytes { EPTP (8), Reserved (8) }
    ;
    ShvVmxInvept PROC
    invept  rcx, oword ptr [rdx]
    ret
    ShvVmxInvept ENDP

    ;
    ; === HOOK REAL DE SYSCALL (ShvSyscallTrampoline) =========================
    ;
    ; REQUER: KPTI (KVA Shadow) desativado na maquina de teste.
    ;
    ; Quando o SYSCALL dispara, o hardware salta aqui com:
    ;   - CR3  = shadow CR3 do processo (nao mapeia paginas de kernel comuns)
    ;   - RSP  = pilha de usermode (nao tocada ainda)
    ;   - GS   = GS de usermode (aponta para TEB, nao KPCR)
    ;   - RAX  = numero da syscall
    ;
    ; Com KPTI ativo, qualquer escrita em memoria de kernel (ShvSyscallCount,
    ; ShvLastSyscallNumber, ShvOriginalLstar) causa #PF, pois essas paginas
    ; nao estao no shadow CR3. O #PF tenta rodar com RSP de usermode + GS
    ; errado, gera outro fault → double fault → BSOD 0x7F.
    ;
    ; Para habilitar: desative o KPTI (veja shvvmxhv.c), descomente o bloco
    ; #if 0 em shvvmxhv.c, reative a chamada ShvVmxInstallSyscallHook em
    ; shvvmx.c, e descomente o codigo abaixo.
    ;
    ; extern ShvSyscallCount:qword
    ; extern ShvLastSyscallNumber:qword
    ; extern ShvOriginalLstar:qword
    ;
    ; ShvSyscallTrampoline PROC
    ;     mov  qword ptr [ShvLastSyscallNumber], rax
    ;     lock inc qword ptr [ShvSyscallCount]
    ;     jmp  qword ptr [ShvOriginalLstar]
    ; ShvSyscallTrampoline ENDP
    ;
    ; =========================================================================

    end
