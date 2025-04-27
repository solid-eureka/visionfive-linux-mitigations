#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/percpu.h>
#include <linux/smp.h>

extern unsigned long context_switch_counter; // declared elsewhere

static struct dentry *debugfs_dir;
static struct dentry *debugfs_file;

static ssize_t csw_show(struct file *f, char __user *buf,
                        size_t count, loff_t *ppos)
{
    char kbuf[64];
    int len;
    unsigned long val = 0;
    int cpu;

    // potential race condition
    for_each_possible_cpu(cpu)
        val += per_cpu(context_switch_counter, cpu);

    len = snprintf(kbuf, sizeof(kbuf), "%lu\n", val);
    return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = csw_show,
};

static int __init csw_debugfs_init(void)
{
    debugfs_dir = debugfs_create_dir("csw_ctr", NULL);
    debugfs_file = debugfs_create_file("total", 0444, debugfs_dir, NULL, &fops);
    return 0;
}

static void __exit csw_debugfs_exit(void)
{
    debugfs_remove_recursive(debugfs_dir);
}

module_init(csw_debugfs_init);
module_exit(csw_debugfs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Context switch counter debugfs interface");
