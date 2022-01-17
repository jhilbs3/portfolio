#!/bin/sh
qemu-system-x86_64 -kernel ~/Development/linux/arch/x86_64/boot/bzImage \
                   -nographic \
                   -monitor /dev/null \
                   -initrd initramfs.cpio.gz \
                   -s \
                   -cpu kvm64,+smep,+smap \
                   -append "console=ttyS0 quiet kpti=1 kaslr" $@
