; junkCode.asm
_TEXT segment

JunkCode1 proc
    nop
    nop
    mov rax, rax
    nop
    ret
JunkCode1 endp

JunkCode2 proc
    add rax, 4
    sub rax, 4
    nop
    ret
JunkCode2 endp

JunkCode3 proc
    push rbp
    pop rbp
    jne short $+2
    nop
    nop
    ret
JunkCode3 endp

_TEXT ends
end