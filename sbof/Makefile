# also taken from https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234

BUILD_PATH = /home/user/Development/linux/

obj-m += sbof.o
ccflags-y := -g

all: exploit
	$(MAKE) -C $(BUILD_PATH) M=`pwd` modules

exploit:
	$(CC) -o exploit exploit.c -static -g

clean_exploit:
	rm exploit

clean: clean_exploit
	$(MAKE) -C $(BUILD_PATH) M=`pwd` clean

test:
	-sudo rmmod sbof
	sudo dmesg -C
	sudo insmod sbof.ko
	dmesg
