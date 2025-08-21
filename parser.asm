; parser.asm - final
; Minimal DNS Response Parser (x86_64 Linux, NASM)
; Reads response.bin and prints: "<qname> <ipv4>\n" for every A record.
;
; Build:
;   nasm -felf64 parser.asm -o parser.o
;   ld parser.o -o parser
; Run:
;   ./parser

BITS 64

%define SYS_READ   0
%define SYS_WRITE  1
%define SYS_OPEN   2
%define SYS_CLOSE  3
%define SYS_EXIT   60

section .data
filename db "response.bin",0
space    db " ",0
dot      db ".",0
nl       db 10

section .bss
buffer   resb 8192
qname    resb 512
numbuf   resb 64

section .text
global _start

; -------------------------------------------------------
; strlen: RSI -> c-string
; returns: RAX = length
; -------------------------------------------------------
strlen:
    xor rax, rax
.s_len:
    mov al, [rsi + rax]
    test al, al
    je .s_done
    inc rax
    jmp .s_len
.s_done:
    ret

; -------------------------------------------------------
; write_stdout: write(1, RSI, RDX)
; uses RSI, RDX
; -------------------------------------------------------
write_stdout:
    mov rax, SYS_WRITE
    mov rdi, 1
    syscall
    ret

; -------------------------------------------------------
; print_u8:
;   Input: ESI = unsigned value (0..255)
;          RDI = pointer to buffer (where to write digits)
;   Return: RAX = number of bytes written (length)
; -------------------------------------------------------
print_u8:
    push rbx
    push rcx
    push rdx

    mov eax, esi
    cmp eax, 0
    jne .pu_nonzero
    mov byte [rdi], '0'
    mov rax, 1
    jmp .pu_done

.pu_nonzero:
    xor rcx, rcx
.pu_loop:
    xor edx, edx
    mov ebx, 10
    div ebx
    push rdx
    inc rcx
    test eax, eax
    jnz .pu_loop

    mov rbx, rdi
.pu_pop:
    pop rdx
    add dl, '0'
    mov [rbx], dl
    inc rbx
    dec rcx
    jnz .pu_pop

    mov rax, rbx
    sub rax, rdi

.pu_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; -------------------------------------------------------
; entry
; -------------------------------------------------------
_start:
    ; open response.bin
    mov rax, SYS_OPEN
    lea rdi, [rel filename]
    xor rsi, rsi
    syscall
    cmp rax, 0
    js .exit_fail
    mov r12, rax          ; fd

    ; read file
    mov rax, SYS_READ
    mov rdi, r12
    lea rsi, [rel buffer]
    mov rdx, 8192
    syscall
    cmp rax, 0
    jle .close_and_exit
    mov r13, rax          ; bytes read

    ; close fd
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

    ; base pointer to buffer
    lea rbx, [rel buffer]

    ; parse QNAME at offset 12 into qname
    mov r10, 12           ; r10 = offset
    lea rdi, [rel qname]  ; dest pointer for labels

.q_parse_loop:
    ; safety: if offset beyond file, abort
    cmp r10, r13
    jae .no_qname
    mov al, [rbx + r10]
    inc r10
    test al, al
    je .q_parse_done
    movzx rcx, al
.copy_label_q:
    ; safety: ensure we don't read past file
    cmp r10, r13
    jae .no_qname
    mov al, [rbx + r10]
    mov [rdi], al
    inc rdi
    inc r10
    dec rcx
    jnz .copy_label_q
    mov byte [rdi], '.'
    inc rdi
    jmp .q_parse_loop

.q_parse_done:
    ; if nothing written, set empty string
    cmp rdi, qname
    jne .terminate_q
.no_qname:
    mov byte [qname], 0
    jmp .after_qname
.terminate_q:
    ; replace last dot with NUL
    dec rdi
    mov byte [rdi], 0

.after_qname:
    ; skip QTYPE(2) + QCLASS(2)
    add r10, 4

    ; read ANCOUNT from header [6..7]
    movzx rax, byte [rbx + 6]
    shl rax, 8
    movzx rdx, byte [rbx + 7]
    or rax, rdx
    mov r11, rax           ; r11 = ancount

    ; if no answers -> exit cleanly
    test r11, r11
    jz .done

    xor r14, r14           ; answer index

.answer_loop:
    ; stop if processed all answers
    cmp r14, r11
    jge .done
    ; safety: if offset beyond file, stop
    cmp r10, r13
    jae .done

    ; NAME: assume pointer (2 bytes) -> skip 2
    ; (if it's not a pointer and is labels, skipping 2 may be wrong,
    ;  but for typical compressed DNS answers pointer is used)
    add r10, 2
    ; check safety again
    cmp r10, r13
    jae .done

    ; TYPE (2)
    movzx rax, byte [rbx + r10]
    shl rax, 8
    movzx rdx, byte [rbx + r10 + 1]
    or rax, rdx
    mov r15, rax
    add r10, 2

    ; CLASS (2) skip
    add r10, 2
    ; TTL (4) skip
    add r10, 4

    ; RDLENGTH (2)
    movzx rax, byte [rbx + r10]
    shl rax, 8
    movzx rdx, byte [rbx + r10 + 1]
    or rax, rdx
    mov r9, rax
    add r10, 2

    ; safety: ensure rdata inside file
    mov rax, r10
    add rax, r9
    cmp rax, r13
    ja  .skip_rr_safe

    ; if A record and rdlen==4 -> print
    cmp r15, 1
    jne .skip_rr_safe
    cmp r9, 4
    jne .skip_rr_safe

    ; print qname
    lea rsi, [rel qname]
    call strlen
    mov rdx, rax
    lea rsi, [rel qname]
    call write_stdout

    ; print space
    lea rsi, [rel space]
    mov rdx, 1
    call write_stdout

    ; print 4 octets at buffer + r10
    ; octet1
    movzx esi, byte [rbx + r10]
    lea rdi, [rel numbuf]
    call print_u8
    mov rdx, rax
    lea rsi, [rel numbuf]
    call write_stdout
    ; dot
    lea rsi, [rel dot]
    mov rdx, 1
    call write_stdout

    ; octet2
    movzx esi, byte [rbx + r10 + 1]
    lea rdi, [rel numbuf]
    call print_u8
    mov rdx, rax
    lea rsi, [rel numbuf]
    call write_stdout
    ; dot
    lea rsi, [rel dot]
    mov rdx, 1
    call write_stdout

    ; octet3
    movzx esi, byte [rbx + r10 + 2]
    lea rdi, [rel numbuf]
    call print_u8
    mov rdx, rax
    lea rsi, [rel numbuf]
    call write_stdout
    ; dot
    lea rsi, [rel dot]
    mov rdx, 1
    call write_stdout

    ; octet4
    movzx esi, byte [rbx + r10 + 3]
    lea rdi, [rel numbuf]
    call print_u8
    mov rdx, rax
    lea rsi, [rel numbuf]
    call write_stdout

    ; newline
    lea rsi, [rel nl]
    mov rdx, 1
    call write_stdout

.skip_rr_safe:
    ; skip rdata
    add r10, r9
    inc r14
    jmp .answer_loop

.done:
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

.close_and_exit:
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall
    jmp .done

.exit_fail:
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall
