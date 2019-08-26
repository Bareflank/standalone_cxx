/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

    .code64
    .intel_syntax noprefix

/*
 * void __store_registers_intel_x64(registers_intel_x64_t *state)
 *
 * This function saves the current register state. Since this function is
 * "naked", the state of the registers is identical to the state of the
 * registers prior to the call to this function, except for rsp, which has
 * been moved down by 8 bytes to accomidate the return address. For this reason
 * we adjust rsp prior to storing it so that we have an accurate rsp
 *
 * Also note that we use the return address as rip. The DWARF code is going to
 * give us a set of instructions on how to roll back the stack, and those
 * instructions are relative to rip. So, we could have used rip just prior to
 * the call to this function, but since this function is "naked" we can also use
 * rip just after the call to this function (which is the return address) as
 * the register state has not changed.
 */
    .globl  __store_registers_intel_x64
    .type   __store_registers_intel_x64, @function
__store_registers_intel_x64:
    mov [rdi +   0], rax
    mov [rdi +   8], rbx
    mov [rdi +  16], rcx
    mov [rdi +  24], rdx
    mov [rdi +  32], rdi
    mov [rdi +  40], rsi
    mov [rdi +  48], rbp
    add rsp, 8
    mov [rdi +  56], rsp
    sub rsp, 8
    mov [rdi +  64], r8
    mov [rdi +  72], r9
    mov [rdi +  80], r10
    mov [rdi +  88], r11
    mov [rdi +  96], r12
    mov [rdi + 104], r13
    mov [rdi + 112], r14
    mov [rdi + 120], r15

    mov rax, [rsp]
    mov [rdi + 128], rax

    ret
/*
 * void __load_registers_intel_x64(registers_intel_x64_t *state)
 *
 * The goal of this function is to "resume" by setting the current state of the
 * CPU to the state that was saved. This function is a little complicated
 * because the order of each instruction needs to be just right.
 *
 * First we start by restoring all of the registers minus rsp, rip, rax and rdi.
 * rdi is currently storing the location of the state fields, so attempting to
 * change that would result in the rest of the state being corrupt, so that is
 * the very last thing to change. rax is used to help restore rip, so that needs
 * to be restored once we are done with it. rsp needs to be restored prior to
 * restoring rip, and rip is restored by pushing it to the stack so that the
 * ret instruction can call it.
 */
    .globl  __load_registers_intel_x64
    .type   __load_registers_intel_x64, @function
__load_registers_intel_x64:
    mov rdx, [rdi +   8]
    mov rcx, [rdi +  16]
    mov rbx, [rdi +  24]
    mov rsi, [rdi +  40]
    mov rbp, [rdi +  48]
    mov r8,  [rdi +  64]
    mov r9,  [rdi +  72]
    mov r10, [rdi +  80]
    mov r11, [rdi +  88]
    mov r12, [rdi +  96]
    mov r13, [rdi + 104]
    mov r14, [rdi + 112]
    mov r15, [rdi + 120]

    mov rsp, [rdi +  56]

    mov rax, [rdi + 128]
    push rax

    mov rax, [rdi +   0]
    mov rdi, [rdi +  32]

    ret
