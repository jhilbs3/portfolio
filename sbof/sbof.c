/* This is my first attempt at creating a vulnerable kernel module. It is a
simple stack buffer overflow. */

// Following this guide
// https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>


#define CLASS_NAME "sbof"
#define DEVICE_NAME "sbofchar"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Hilbert");
MODULE_DESCRIPTION("A simple stack buffer overflow in kernel space. How fun.");
MODULE_VERSION("0.01");

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int device_open_count = 0;

static int major_num = -1;
static dev_t dev_num = -1;
static struct class *sbof_class = NULL;
static struct device *sbof_dev = NULL;

static struct file_operations file_ops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
    char msg[] = "hello from sbof module\n";
    int not_copied = 0;

    // BUG: No length checking and use of unsafe __copy_to_user method
    not_copied = __copy_to_user(buffer, msg, len);
    if(0 != not_copied)
    {
        printk(KERN_ALERT "[-] Failed copying %d bytes to userspace\n", not_copied);
    }

    return not_copied;
}

/* Called when a process tries to write to our device */
static ssize_t device_write(struct file *flip, 
                            const char *buffer, 
                            size_t len, 
                            loff_t *offset) {

    // create temp buffer
    int not_copied = 0;
    char msg[16] = {0};

    printk(KERN_INFO "[*] Copying %ld bytes from user to kernel space\n", len);
   
    // BUG: unchecked len field and use of unsafe __copy_from_user method
    not_copied = __copy_from_user(msg, buffer, len);
    if(0 != not_copied)
    {
        printk(KERN_ALERT "[-] Failed copying %d bytes\n", not_copied);
        return not_copied;
    }

    printk(KERN_INFO "[+] Received msg: %s\n", msg);
    return 0;
}

static int device_open(struct inode *inode, struct file *file)
{

    // this is probably a race condition because the kernel must have some kind
    // of locking mechanism for shared resources...
    if(device_open_count)
    {
        return -EBUSY;
    }

    device_open_count++;
    try_module_get(THIS_MODULE);
    return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
    device_open_count--;
    module_put(THIS_MODULE);
    return 0;
}

static int __init sbof_init(void) {
    int err = -1;
    printk(KERN_INFO "[*] sbof.ko is now live.\n");

    major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
    if(major_num < 0 )
    {
        printk(KERN_ALERT "[-] Could not register sbof device: %d\n", major_num);
        return major_num;
    }

    // this stuff inspired by 
    // https://stackoverflow.com/questions/49350553/can-i-call-mknod-from-my-kernel-module
    sbof_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(sbof_class))
    {
        printk(KERN_ALERT "[-] Could not create class\n");
        goto BAILOUT;
    }

    // finally create device
    dev_num = MKDEV(major_num, 0);
    sbof_dev = device_create(sbof_class, 
                             NULL, 
                             dev_num, 
                             NULL, 
                             DEVICE_NAME); 
    if(IS_ERR(sbof_dev))
    {
        printk(KERN_ALERT "[-] Could not create device /dev/%s\n", DEVICE_NAME);
        class_destroy(sbof_class);
        goto BAILOUT; 
    }

    printk(KERN_INFO "[+] sbof loaded. use major #%d\n", major_num);

    return 0;
    
BAILOUT:
    unregister_chrdev(major_num, "sbof");
    return err;
}

static void __exit sbof_exit(void) {
    device_destroy(sbof_class, dev_num);
    class_destroy(sbof_class);
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "[-] sbof.ko is leaving town for good.\n");
}

module_init(sbof_init);
module_exit(sbof_exit);
