#include <linux/module.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <asm/unistd.h>

#define IOCTL_PATCH_TABLE 0x00000001  // Commande pour patcher la table des syscalls
#define IOCTL_FIX_TABLE   0x00000004  // Commande pour restaurer la table des syscalls

// Pointeur vers la table des appels système (adresse statique)
unsigned long* sys_call_table = (unsigned long*) 0xffffffff8164f400;

int is_set = 0;  // Indique si la table a été patchée
int in_use = 0;  // Indique si le device est actuellement ouvert

// Pointeur vers l'ancienne fonction open (à sauvegarder avant le patch)
asmlinkage int (*real_open)(const char* __user, int, int);

// Fonction open personnalisée qui intercepte l'appel système open
asmlinkage int custom_open(const char* __user file_name, int flags, int mode)
{
  // Affiche dans le log que l'appel a été intercepté
  printk("SYSCALL intercepted: open(\"%s\", %X, %X)\n", file_name, flags, mode);
  // Appelle la fonction open originale pour conserver le comportement d'origine
  return real_open(file_name, flags, mode);
}

// Fonction pour rendre une adresse mémoire en lecture/écriture
int make_rw(unsigned long address)
{
  unsigned int level;
  pte_t *pte = lookup_address(address, &level);  // Recherche l'entrée de page correspondant à l'adresse
  if(pte->pte &~ _PAGE_RW)
    pte->pte |= _PAGE_RW;  // Active le flag RW si nécessaire
  return 0;
}

// Fonction pour remettre une adresse mémoire en lecture seule
int make_ro(unsigned long address)
{
  unsigned int level;
  pte_t *pte = lookup_address(address, &level);
  pte->pte = pte->pte &~ _PAGE_RW;  // Désactive le flag RW
  return 0;
}

// Fonction appelée lors de l'ouverture du device (pour le contrôle d'accès)
static int our_open(struct inode *inode, struct file *file)
{
  if(in_use)
    return -EBUSY;  // Retourne une erreur si le device est déjà utilisé
  in_use++;
  printk("device has been opened\n");
  return 0;
}

// Fonction appelée lors de la fermeture du device
static int our_release(struct inode *inode, struct file *file)
{
  in_use--;
  printk("device has been closed\n");
  return 0;
}

// Fonction ioctl permettant de patcher/restaurer la table des syscalls
static int our_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  int retval = 0;
  
  switch(cmd)
  {
      case IOCTL_PATCH_TABLE:
         // Rendre la table modifiable
         make_rw((unsigned long)sys_call_table);
         // Sauvegarder l'adresse de la fonction open originale
         real_open = (void*)*(sys_call_table + __NR_open);
         // Rediriger l'entrée open vers notre fonction custom_open
         *(sys_call_table + __NR_open) = (unsigned long)custom_open;
         // Rétablir la protection en lecture seule
         make_ro((unsigned long)sys_call_table);
         is_set = 1;
         break;
      case IOCTL_FIX_TABLE:
         // Rendre la table modifiable
         make_rw((unsigned long)sys_call_table);
         // Restaurer l'entrée open vers la fonction originale
         *(sys_call_table + __NR_open) = (unsigned long)real_open;
         // Rétablir la protection en lecture seule
         make_ro((unsigned long)sys_call_table);
         is_set = 0;
         break;
      default:
         printk("Ooops....\n");  // Commande inconnue
         break;
  }
  return retval;
}

// Structure définissant les opérations supportées par le device
static const struct file_operations our_fops = {
  .owner = THIS_MODULE,
  .open = our_open,
  .release = our_release,
  .unlocked_ioctl = (void*)our_ioctl,
  .compat_ioctl = (void*)our_ioctl
};

// Déclaration du device misc avec un numéro mineur dynamique et un nom "damien"
static struct miscdevice our_device = {
  MISC_DYNAMIC_MINOR,
  "damien",
  &our_fops
};

// Fonction d'initialisation du module, appelée lors du chargement
static int __init start_module(void)
{
  int retval;
  printk(KERN_INFO "Modules loaded.\n");
  retval = misc_register(&our_device);  // Enregistrement du device misc
  return retval;
}

// Fonction de nettoyage, appelée lors du déchargement du module
static void __exit exit_module(void)
{
  printk(KERN_INFO "Unloading the module....\n");
  if(is_set)
  {
      // Si le syscall a été patché, le restaurer
      make_rw((unsigned long)sys_call_table);
      *(sys_call_table + __NR_open) = (unsigned long)real_open;
      make_ro((unsigned long)sys_call_table);
  }
  misc_deregister(&our_device);  // Désenregistrement du device misc
}

module_init(start_module);
module_exit(exit_module);

MODULE_AUTHOR("Ttotot");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("My kernel module hooking sst");
