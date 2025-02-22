#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>            // Pour file_operations
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/file.h>

#define MOD_NAME "kmod"
#define FIFO_FILE "/dev/shm/.sysdevice"

static int used = 0;

static void write_to_fifo(const char *data, size_t len)
{
    struct file *fifo_file;
    // Si kernel < 5.10
    //mm_segment_t old_fs; // Sauvegarde du contexte précédent du segment mémoire
    loff_t pos = 0;      // Écriture depuis le début du fichier (équivalent de lseek(fd, 0, SEEK_SET) en userland)

    /* Ouvre le FIFO en écriture */
    fifo_file = filp_open(FIFO_FILE, O_WRONLY | O_CREAT, 0666);
    if (IS_ERR(fifo_file)) {
        pr_err("Erreur: Impossible d'ouvrir le FIFO %s\n", FIFO_FILE);
        return;
    }
    // Si kernel < 5.10
    /* Changer le contexte mémoire pour écrire en mode noyau */
    //  old_fs = get_fs();
    //  set_fs(KERNEL_DS);

    /* Écriture dans le FIFO */
    kernel_write(fifo_file, data, len, &pos);

    
    /* Rétablir l'ancien contexte et fermer le fichier */
    // Si kernel < 5.10
    //  set_fs(old_fs);
    filp_close(fifo_file, NULL);
}

static ssize_t misc_device_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    char *kbuf;

    pr_info("Device received %zu bytes\n", len);

    /* Allouer un buffer en mémoire noyau */
    kbuf = kmalloc(len + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    /* Copier les données de l'espace utilisateur vers le buffer noyau */
    if (copy_from_user(kbuf, buf, len)) {
        kfree(kbuf);
        return -EFAULT;
    }
    kbuf[len] = '\0'; // Terminaison de la chaîne

    pr_info("Writing bytes into FIFO: %s\n", FIFO_FILE);

    write_to_fifo(kbuf, len);

    kfree(kbuf);
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
MODULE_DESCRIPTION("Module Device to FIFO");
