#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

static struct task_struct *tasks[8092];
static int num;

unsigned long tgt_sym;
module_param(tgt_sym, ulong, 0644);

static bool is_target()
{
	struct task_struct *task = NULL;
	int i = 0;

	if (!current->mm)
		return 0;

	while (tasks[i] != NULL) {
		if (tasks[i] == current) {
			task = current;
			break;
		}
		i++;
	}

	if (task == NULL)
		return 0;

	return 1;
}

static int ent_kern_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path *path;

	if (!is_target())
		return 1;

	path = (struct path *)ri->data;
	path = (struct path *)regs->dx;

	return 0;
}

static int ret_kern_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path *path;
	int rc = regs_return_value(regs);

	if (rc < 0)
		return 0;

	path = (struct path *)ri->data;
	path_put(path);
	regs->ax = -ENOMEM;

	return 0;
}

static struct kretprobe krp_kern_path = {
	.handler		= ret_kern_path,
	.entry_handler		= ent_kern_path,
	.data_size		= sizeof(struct path *),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kern_path",
	},
};

static int ent_tgt(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	tasks[num] = current;
	num++;
	return 0;
}

static int ret_tgt(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	num--;
	tasks[num] = NULL;
	return 0;
}

static struct kretprobe krp_tgt = {
	.handler		= ret_tgt,
	.entry_handler		= ent_tgt,
};

static int __init target_init(void)
{
	int rc;

	if (tgt_sym == 0) {
		return -EINVAL;
	}
	krp_tgt.kp.addr = (kprobe_opcode_t *)tgt_sym;
	rc = register_kretprobe(&krp_tgt);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		goto out;	
	}

	rc = register_kretprobe(&krp_kern_path);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		unregister_kretprobe(&krp_tgt);
	}
out:
	return rc;
}

static void __exit target_exit(void)
{
	unregister_kretprobe(&krp_kern_path);
	unregister_kretprobe(&krp_tgt);
}

module_init(target_init);
module_exit(target_exit);

MODULE_LICENSE("GPL");
