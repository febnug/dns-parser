; Parser tolerant to NAME pointer or full label
;
;
; Build :
; nasm -f elf64 dns.asm -o dns.o
; ld -o dns dns.o
;
; Run :
; ./dns | hexdump -C
  
BITS 64

section .data
    dns_server_ip    dd 0x08080808      ; 8.8.8.8
    dns_server_port  dw 53

    query_bytes:     db 0x00,0x00, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00
                     db 5,'f','e','b','r','i', 5,'c','l','i','c','k',0
                     db 0x00,0x01, 0x00,0x01
    query_len        equ $-query_bytes

    outbuf           times 512 db 0
    ipstr            db "0.0.0.0",10
    noans_msg        db "no answer",10
    noans_len        equ $-noans_msg

section .bss
    sockfd resq 1

section .text
global _start
_start:
    ; create socket: socket(AF_INET, SOCK_DGRAM, 0)
    mov rax, 41
    mov rdi, 2
    mov rsi, 2
    xor rdx, rdx
    syscall
    test rax, rax
    js .exit_err
    mov [sockfd], rax

    ; build sockaddr_in on stack
    sub rsp, 32
    mov word [rsp], 2                 ; AF_INET
    mov ax, word [dns_server_port]
    xchg al, ah
    mov [rsp+2], ax
    mov eax, dword [dns_server_ip]
    mov [rsp+4], eax
    mov qword [rsp+8], 0

    ; patch transaction ID
    mov word [query_bytes], 0xABCD

    ; sendto
    mov rax, 44
    mov rdi, [sockfd]
    lea rsi, [rel query_bytes]
    mov rdx, query_len
    xor r10, r10
    mov r8, rsp
    mov r9, 16
    syscall
    cmp rax, 0
    jle .cleanup_and_exit

    ; recvfrom
    mov rax, 45
    mov rdi, [sockfd]
    lea rsi, [rel outbuf]
    mov rdx, 512
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    cmp rax, 0
    jle .cleanup_and_exit
    mov r12, rax

    ; print raw response for debug
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel outbuf]
    mov rdx, r12
    syscall

    ; parse header
    lea rbx, [rel outbuf]
    movzx rax, word [rbx+6]
    test rax, rax
    jz .no_answer

    ; skip question section
    mov rcx, 12
.loop_qname:
    mov al, [rbx+rcx]
    inc rcx
    test al, al
    jz .qname_done
    add rcx, rax
    jmp .loop_qname
.qname_done:
    add rcx, 4

    ; parse answer, handle NAME as pointer or full label
    mov al, [rbx+rcx]
    cmp al, 0xc0
    jae .skip_pointer
    ; not pointer, skip label(s) until 0
.label_loop:
    mov al, [rbx+rcx]
    inc rcx
    test al, al
    jz .after_label
    add rcx, rax
    jmp .label_loop
.after_label:
    jmp .after_name
.skip_pointer:
    add rcx, 2
.after_name:
    ; TYPE
    movzx rdx, byte [rbx+rcx]
    shl rdx, 8
    movzx rsi, byte [rbx+rcx+1]
    or rdx, rsi
    cmp rdx, 1
    jne .skip_answer
    ; RDLENGTH
    movzx rax, word [rbx+rcx+8]
    cmp rax, 4
    jne .skip_answer

    ; RDATA
    mov eax, dword [rbx+rcx+10]
    mov r13d, eax
    mov r14d, r13d
    and r13d, 0xff

    shr r14d, 8
    mov r15d, r14d
    and r14d, 0xff

    shr r15d, 8
    mov r11d, r15d
    and r15d, 0xff

    lea rdi, [rel ipstr]
    mov esi, r13d
    call .int_to_str_write
    mov byte [rdi], '.'
    inc rdi
    mov esi, r14d
    call .int_to_str_write
    mov byte [rdi], '.'
    inc rdi
    mov esi, r15d
    call .int_to_str_write
    mov byte [rdi], '.'
    inc rdi
    mov esi, r11d
    call .int_to_str_write
    mov byte [rdi], 10
    inc rdi

    mov rdx, rdi
    sub rdx, ipstr
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel ipstr]
    syscall
    jmp .cleanup_and_exit

.skip_answer:
    jmp .no_answer

.no_answer:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel noans_msg]
    mov rdx, noans_len
    syscall
    jmp .cleanup_and_exit

.int_to_str_write:
    push rbx
    push rcx
    push rdx
    mov eax, esi
    mov ecx, 0
    cmp eax, 0
    jne .conv_loop
    mov byte [rdi], '0'
    inc rdi
    pop rdx
    pop rcx
    pop rbx
    ret
.conv_loop:
    xor edx, edx
    mov ebx, 10
    div ebx
    push rdx
    inc ecx
    cmp eax, 0
    jne .conv_loop
.pop_digits:
    pop rdx
    add dl, '0'
    mov [rdi], dl
    inc rdi
    loop .pop_digits
    pop rdx
    pop rcx
    pop rbx
    ret

.cleanup_and_exit:
    mov rax, 3
    mov rdi, [sockfd]
    syscall
.exit_err:
    mov rax, 60
    xor rdi, rdi
    syscall
