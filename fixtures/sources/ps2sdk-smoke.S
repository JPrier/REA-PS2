    .set noreorder
    .text
    .globl __start
    .ent __start
__start:
    addiu $v0, $zero, 42
1:
    b 1b
    nop
    .end __start
