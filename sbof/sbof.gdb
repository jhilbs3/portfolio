# load the uncompressed kernel
file /home/user/Development/linux/vmlinux

# source the gdb helper python scripts
source /home/user/Development/linux/vmlinux-gdb.py

# connect to the qemu gdb stub
target remote localhost:1234

lx-symbols

break *(device_write+127)
