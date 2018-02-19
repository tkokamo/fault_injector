#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <asm-generic/uaccess.h>

#include "injector.h"

#define FI_DEVNAME "fault_inject"

struct fi_instance {
	struct task_struct	*task;
	struct fault_injector	*fi;
	int			when;
	bool			enter;
};

static struct fi_instance fis[1];
static int num;

static wait_queue_head_t tgtq;
atomic_t done;

dev_t fi_id;
struct cdev fi_cdev;
struct class *fi_class;
struct device *fi_dev;

struct kretprobe *fault_lists[] = {
	&krp_proc_mkdir,
	&krp_proc_create_data,
	&krp_kern_path,
	&krp_kthread_run,
	&krp_kmem_cache_alloc_trace,
	&krp_kmem_cache_alloc,
	&krp___kmalloc,
	&krp_vmalloc,
	&krp___vmalloc,
	&krp_vmalloc_user,
};

bool is_target(struct pt_regs *regs)
{
	if (!current->mm)
		return 0;

	if (fis[0].task == NULL &&
			strcmp(current->comm, fis[0].fi->comm))
		return 0;

	if (fis[0].task != NULL && fis[0].task != current)
		return 0;

	if (strlen(fis[0].fi->module) != 0) {
		struct module *mod;
		void **sp = (void **)regs->sp;
		void *ret = *sp;

		preempt_disable();
		mod = __module_address((unsigned long)ret);
		if (mod == NULL || strcmp(mod->name, fis[0].fi->module)) {
			preempt_enable();
			return 0;
		}
		preempt_enable();
	}

	if (++(fis[0].when) < (fis[0].fi->when))
		return 0;

	return 1;
}

static int ent_kern_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path **ppath;

	if (!is_target(regs))
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

struct kretprobe krp_kern_path = {
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
	if (!is_target(regs))
		return 1;
	return 0;
}

static int ret_kthread_run(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (IS_ERR(rp))
		return 0;

	kthread_stop(rp);
	regs->ax = (unsigned long)ERR_PTR(-ENOMEM);

	return 0;
}

struct kretprobe krp_kthread_run = {
	.handler		= ret_kthread_run,
	.entry_handler		= ent_kthread_run,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kthread_create_on_node",
	},
};

static int ent_tgt(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (fis[0].task != NULL)
		return 1;

	fis[0].task = current;
	fis[0].when = 0;
	num++;
	return 0;
}

static int ret_tgt(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	num--;
	fis[0].task = NULL;
	fis[0].when = 0;
	
	atomic_set(&done, 1);
	wake_up(&tgtq);
	return 0;
}

static int inject_fault(unsigned long arg)
{
	int rc = 0;
	int i;
	int num;
	struct fault_injector *fi;
	struct kretprobe *krp = NULL;
	struct kretprobe *target = NULL, *fault = NULL;

	fi = kmalloc(sizeof(struct fault_injector), GFP_KERNEL);
	if (fi == NULL) {
		printk("Can not allocate fi memory.\n");
		rc = -ENOMEM;
		goto out;
	}

	if (copy_from_user(fi, (void *)arg, sizeof(*fi))) {
		printk("Bad argument address passed.\n");
		rc = -EFAULT;
		goto free_fi;
	}
	fis[0].fi = fi;

	if (strlen(fi->target) == 0 && strlen(fi->comm) == 0) {
		printk("At least you should specify target function or command\n");
		rc = -EINVAL;
		goto free_fi;
	}

	num = sizeof(fault_lists) / sizeof(struct kretprobe *);
	for (i = 0; i < num; i++) {
		krp = fault_lists[i];
		if (!strcmp(krp->kp.symbol_name, fi->fault)) {
			break;	
		}
		krp = NULL;
	}
	if (krp == NULL) {
		printk("Invalid fault function passed.\n");
		rc = -EINVAL;
		goto free_fi;
	}

	fault = (struct kretprobe *)kmalloc(sizeof(*fault), GFP_KERNEL);
	if (fault == NULL) {
		printk("kmalloc() fault failed.\n");
		rc = -ENOMEM;
		goto free_fi;
	}
	target = (struct kretprobe *)kmalloc(sizeof(*target), GFP_KERNEL);
	if (target == NULL) {
		printk("kmalloc() target failed.\n");
		rc = -ENOMEM;
		goto free_fault;
	}

	memcpy(fault, krp, sizeof(*fault));
	
	rc = register_kretprobe(fault);
	if (rc < 0) {
		printk("registering fault function failed.\n");
		goto free_target;
	}

	if (strlen(fi->target) != 0) {
		memset(target, 0, sizeof(*target));
		target->kp.symbol_name = fi->target;
		target->handler = ret_tgt;
		target->entry_handler = ent_tgt;
		rc = register_kretprobe(target);
		if (rc < 0) {
			printk("registering target function failed.\n");
			goto unreg_krp;
		}
	}

	atomic_set(&done, 0);
	wait_event_interruptible(tgtq, atomic_read(&done));

	if (strlen(fi->target) != 0) {
		unregister_kretprobe(target);
	}
unreg_krp:
	unregister_kretprobe(fault);
free_target:
	kfree(target);
free_fault:
	kfree(fault);
free_fi:
	fis[0].fi = NULL;
	kfree(fi);
out:
	return rc;
}

static long
fault_inject_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int rc = 0;
	switch (cmd) {
	case INJECT_FAULT:
		rc = inject_fault(arg);
		break;
	default:
		printk("Invalid cmd.\n");
		rc = -EINVAL;
		break;
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
	int i;
	struct kretprobe *krp;

	init_waitqueue_head(&tgtq);

	rc = alloc_chrdev_region(&fi_id, 0, 1, FI_DEVNAME);
	if (rc < 0) {
		printk("alloc_chrdev_region() failed.\n");
		goto out;
	}

	cdev_init(&fi_cdev, &fault_inject_fops);

	fi_cdev.owner = THIS_MODULE;
	rc = cdev_add(&fi_cdev, fi_id, 1);
	if (rc < 0) {
		printk("alloc_chrdev_region() failed.\n");
		goto unreg_chrdev;
	}

	fi_class = class_create(THIS_MODULE, FI_DEVNAME);
	if (IS_ERR(fi_class)) {
		printk("class_create() failed.\n");
		rc = PTR_ERR(fi_class);
		goto del_cdev;
	}

	fi_dev = device_create(fi_class, NULL, fi_id, NULL, FI_DEVNAME);
	if (IS_ERR(fi_dev)) {
		printk("alloc_chrdev_region() failed.\n");
		rc = PTR_ERR(fi_dev);
		goto dest_class;
	}

	num = sizeof(fault_lists) / sizeof(struct kretprobe *);
	for (i = 0; i < num; i++) {
		krp = fault_lists[i];
		rc = kallsyms_lookup_name(krp->kp.symbol_name);
		if (rc == 0) {
			printk("Invalid symbol %s is in the lists\n",
			      krp->kp.symbol_name);
			rc = -EINVAL;
			goto dest_dev;
		}
	}
	return 0;

dest_dev:
	device_destroy(fi_class, fi_id);
dest_class:
	class_destroy(fi_class);
del_cdev:
	cdev_del(&fi_cdev);
unreg_chrdev:
	unregister_chrdev_region(fi_id, 1);
out:
	return rc;
}

static void __exit injector_exit(void)
{
	device_destroy(fi_class, fi_id);
	class_destroy(fi_class);
	cdev_del(&fi_cdev);
	unregister_chrdev_region(fi_id, 1);
}

module_init(injector_init);
module_exit(injector_exit);

MODULE_LICENSE("GPL");
