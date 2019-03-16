#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>


static int hello_init(void)
{
printk(KERN_ALERT "hello,I am jmh./n");
return 0;
}

static void hello_exit(void)
{
printk(KERN_ALERT "goodbye,kernel/n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JMH");
MODULE_DESCRIPTION("A Simple Driver");
