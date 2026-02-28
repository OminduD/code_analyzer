; test.asm
section .text
global _start

_start:
    ; VULNERABILITY ASM001
    int 0x80

    ; VULNERABILITY ASM002
    syscall
