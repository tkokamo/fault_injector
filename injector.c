#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/kallsyms.h>

static struct task_struct *tasks[8092];
static int num;
static wait_queue_head_t tgtq;

struct kretprobe *fault_lists[] = {
	&krp_kern_path,
	&krp_kthread_run,
	&krp_kmem_cache_alloc,
	&krp___kmalloc,
	&krp_vmalloc,
	&krp___vmalloc,
	&krp_vmalloc_user,
};

bool is_target(void)
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
	struct path **ppath;

	if (!is_target())
		return 1;

	ppath = (struct path **)ri->data;
	*ppath = (struct path *)regs->dx;

	return 0;
}

static int ret_kern_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path **ppath;
	int rc = regs_return_value(regs);

	if (rc < 0)
		return 0;

	ppath = (struct path **)ri->data;
	path_put(*ppath);
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

static int ent_kthread_run(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target())
		return 1;
	return 0;
}

static int ret_kthread_run(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	kthread_stop(rp);
	regs->ax = (unsigned long)-ENOMEM;

	return 0;
}

static struct kretprobe krp_kthread_run = {
	.handler		= ret_kthread_run,
	.entry_handler		= ent_kthread_run,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kthread_create_on_node",
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

static int inject_fault(unsigned long arg)
{
	int rc = 0;
	int i;
	int num;
	struct fault_injector *fi;
	struct kretprobe *krp = NULL;

	fi = kmalloc(sizeof(fault_injector), GFP_KERNEL);
	if (fi == NULL) {
		printk("Can not allocate fi memory.\n");
		rc = -ENOMEM;
		goto out;
	}

	if (copy_from_user(fi, arg, sizeof(struct fault_injector))) {
		printk("Bad argument address passed.\n");
		rc = -EFAULT;
		goto free_fi;
	}

	num = sizeof(fault_lists) / sizeof(struct kretprobe *);
	for (i = 0; i < num; i++) {
		krp = fault_lists[i];
		if (!strcmp(krp.kp.symbol_name, fi->target)) {
			break;	
		}
	}
	if (krp == NULL) {
		printk("Invalid fault function passed.\n");
		rc = -EINVAL;
		goto free_fi;
	}

	rc = register_kretprobe(krp);
	if (rc < 0) {
		printk("registering fault function failed.\n");
		goto free_fi;
	}

	krp_tgt.rp.symbol_name = fi->target;
	rc = register_kretprobe(&krp_tgt);
	if (rc < 0) {
		printk("registering target function failed.\n");
		goto free_fi;
	}

unreg_fault:
	unregister_kretprobe(krp);
free_fi:
	kfree(fi);
out:
	return rc;
}

static long
fault_inject_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int rc = 0;
	switch (cmd) {
	case FAULT_INJECT:
		rc = inject_fault(arg);
	default:
		printk("Invalid cmd.\n");
		rc = -EINVAL;
	}

	return rc;
}

static struct file_operations fault_inject_fops = {
    .unlocked_ioctl = fault_inject_ioctl,
};

static int __init injector_init(void)
{
	int rc;
	int num;
	struct kretprobe *krp;

	/*TODO register device */

	num = sizeof(fault_lists) / sizeof(struct kretprobe *);
	for (i = 0; i < num; i++) {
		krp = fault_lists[i];
		rc = kallsyms_lookup_name(krp.kp.symbol_name);
		if (rc == 0) {
			printk("Invalid symbol %s is in the lists\n",
			      krp.kp.symbol_name);
			return -EINVAL;
		}
	}
	
	return rc;
}

static void __exit injector_exit(void)
{
	/*TODO unregister device */
	;
}

module_init(injector_init);
module_exit(injector_exit);

MODULE_LICENSE("GPL");
