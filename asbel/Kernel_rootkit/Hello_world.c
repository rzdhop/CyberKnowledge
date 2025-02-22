#include <linux/init.h>
#include <linux/module.h>

static int __init start_module(void)
{
  pr_info("Hello World!\n");
  return 0;
}

static void __exit exit_module(void)
{
  pr_info("GoodBye World !\n");
}

module_init(start_module);
module_exit(exit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rida");
MODULE_DESCRIPTION("Module Hello World");