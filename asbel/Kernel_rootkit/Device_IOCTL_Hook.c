#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h> //Pour file_operations
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#define MOD_NAME "kmod"

static int used = 0;

static ssize_t misc_device_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    /* Ici, on se contente de loguer le nombre d'octets reçus */
    pr_info("Device received %zu bytes\n", len);
    return len; 
}

static int misc_device_open(struct inode *inode, struct file *file)
{
    if (used)
        return -EBUSY;
    used = 1;
    pr_info("Device /dev/%s opened!\n", MOD_NAME);
    return 0;
}

static int misc_device_release(struct inode *inode, struct file *filp)
{
    used = 0;
    pr_info("Device /dev/%s released!\n", MOD_NAME);
    return 0;
}

/*
 * file_operations:
 *   - owner   : le module qui possède cette structure (THIS_MODULE)
 *   - open    : fonction appelée lors de l'ouverture du device
 *   - release : fonction appelée lors de la fermeture du device
 *   - write   : fonction appelée lors de l'écriture dans le device
 */
static const struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = misc_device_open,
    .release = misc_device_release,
    .write   = misc_device_write,
};

/*
 * miscdevice:
 *   - minor : numéro mineur attribué dynamiquement via MISC_DYNAMIC_MINOR
 *   - name  : nom du device (/dev/<name>)
 *   - fops  : pointeur vers la structure file_operations
 */
static struct miscdevice misc_device = {
    .minor = MISC_DYNAMIC_MINOR, 
    .name  = MOD_NAME,
    .fops  = &fops,
};

static int __init start_module(void)
{	
    int ret;
    pr_info("Registering misc device /dev/%s\n", MOD_NAME);
    ret = misc_register(&misc_device);
    if (ret)
        pr_err("Unable to register misc device: %d\n", ret);
    return ret;
}

static void __exit exit_module(void)
{
    pr_info("Deregistering misc device /dev/%s\n", MOD_NAME);
    misc_deregister(&misc_device);
}

module_init(start_module);
module_exit(exit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rida");
MODULE_DESCRIPTION("Module Device");
