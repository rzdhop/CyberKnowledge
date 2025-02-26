#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h> //permet de definir task_struct current
#include <linux/cred.h>
#include <linux/uaccess.h>

static struct kprobe kp = {
    .symbol_name = "do_sys_openat2",  // Fonction cible
};
/*
Rappel de System V AMD64 ABI (Application Binary Interface) :
Argv : RDI(1), RSI(2), RDX(3), RCX(4), R8(5), R9(6)

    struct pt_regs {
        Ordre exact dépend du noyau, mais on y retrouve :
        unsigned long r15;
        unsigned long r14;
        unsigned long r13;
        unsigned long r12;
        unsigned long bp;
        unsigned long bx;
        unsigned long r11;
        unsigned long r10;
        unsigned long r9;
        unsigned long r8;
        unsigned long ax; // RAX - sert souvent de registre de retour de fonction
        unsigned long cx;
        unsigned long dx; // RDX
        unsigned long si; // RSI
        unsigned long di; // RDI
        unsigned long orig_ax; // Valeur de RAX avant l'appel syscall
        unsigned long ip; // RIP - adresse de l'instruction
        unsigned long cs; // Code segment
        unsigned long flags;
        unsigned long sp; // RSP - stack pointer
        unsigned long ss; // Stack segment
    };
*/
// Handler exécuté avant l'appel de la fonction
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char __user *filename = (char __user *)regs->si; // Récupération du 2e argument (filename)
    char fname[256];
		char new_name[] = "/tmp/fake.txt"; // Fichier de remplacement
		/*
		//https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/sched.h#L785
		struct task_struct {
	    pid_t pid;                  // PID du processus
	    char comm[TASK_COMM_LEN];   // Nom du processus
	    struct cred *cred;          // Informations sur l'utilisateur (UID, GID)
	    struct mm_struct *mm;       // Espace mémoire du processus
	    struct files_struct *files; // Descripteurs de fichiers ouverts
	    ...
		};
		*/
    // Récupérer le nom du fichier depuis l'espace utilisateur
    if (strncpy_from_user(fname, filename, sizeof(fname)) > 0) {
	    if (strcmp(fname, "/home/user/kiwi.txt") == 0) {
        printk(KERN_INFO "[KPROBE] %s (PID: %d) a ouvert %s mais hijacked en %s !\n",
               current->comm, current->pid, fname, new_name);
               
        //Remplace l'argument d'appel (le fichier) en un autre fichier de remplacement
        copy_to_user(filename, new_name, strlen(new_name) + 1);
	    }
		}

    return 0;
}

// Initialisation du hook
static int __init hook_init(void)
{
    kp.pre_handler = handler_pre;
    return register_kprobe(&kp);
}

// Suppression du hook à la fin
static void __exit hook_exit(void)
{
    unregister_kprobe(&kp);
}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");