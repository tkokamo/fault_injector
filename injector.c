#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kthread.h>

static struct task_struct *tasks[8092];
static int num;

unsigned long tgt_sym;
module_param(tgt_sym, ulong, 0644);

static bool is_target(void)
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

static int ent_kmem_cache_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache **pcachep;

	if (!is_target())
		return 1;

	pcachep = (struct kmem_cache **)ri->data;
	*pcachep = (struct kmem_cache *)regs->di;
	
	return 0;
}

static int ret_kmem_cache_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache **pcachep;
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	pcachep = (struct kmem_cache **)ri->data;
	kmem_cache_free(*pcachep, rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

static struct kretprobe krp_kmem_cache_alloc = {
	.handler		= ret_kmem_cache_alloc,
	.entry_handler		= ent_kmem_cache_alloc,
	.data_size		= sizeof(struct kmem_cache *),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kmem_cache_alloc",
	},
};

static int ent___kmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target())
		return 1;

	return 0;
}

static int ret___kmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);
	unsigned long *sp = NULL;

	if (rp == NULL)
		return 0;

	kfree(rp);
	regs->ax = (unsigned long)NULL;
	sp = (unsigned long *)regs->sp;
	sp[10] = (unsigned long)NULL;
	return 0;
}

static struct kretprobe krp___kmalloc = {
	.handler		= ret___kmalloc,
	.entry_handler		= ent___kmalloc,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "__kmalloc",
	},
};

static int ent___vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target())
		return 1;
	
	return 0;
}

static int ret___vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	vfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

static struct kretprobe krp___vmalloc = {
	.handler		= ret___vmalloc,
	.entry_handler		= ent___vmalloc,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "__vmalloc",
	},
};

static int ent_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target())
		return 1;
	
	return 0;
}

static int ret_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	vfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

static struct kretprobe krp_vmalloc = {
	.handler		= ret_vmalloc,
	.entry_handler		= ent_vmalloc,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "vmalloc",
	},
};

static int ent_vmalloc_user(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target())
		return 1;
	return 0;
}

static int ret_vmalloc_user(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	vfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

static struct kretprobe krp_vmalloc_user = {
	.handler		= ret_vmalloc_user,
	.entry_handler		= ent_vmalloc_user,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "vmalloc_user",
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

static int __init injector_init(void)
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
/*
	rc = register_kretprobe(&krp_kern_path);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		goto unreg_tgt;
	}
	
	rc = register_kretprobe(&krp_kmem_cache_alloc);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		goto unreg_kern;
	}

	rc = register_kretprobe(&krp___kmalloc);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		goto unreg_kmem;
	}

	rc = register_kretprobe(&krp_vmalloc);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		goto unreg___km;
	}

	rc = register_kretprobe(&krp_vmalloc_user);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
		goto unreg_vm;
	}*/

	rc = register_kretprobe(&krp_kthread_run);
	if (rc < 0) {
		printk(KERN_ERR "register_kretprobe() failed.\n");
	}

	return 0;
unreg_vm:
	unregister_kretprobe(&krp_vmalloc);
unreg___km:
	unregister_kretprobe(&krp___kmalloc);
unreg_kmem:
	unregister_kretprobe(&krp_kmem_cache_alloc);
unreg_kern:
	unregister_kretprobe(&krp_kern_path);
unreg_tgt:
	unregister_kretprobe(&krp_tgt);
out:
	return rc;
}

static void __exit injector_exit(void)
{
/*	unregister_kretprobe(&krp_vmalloc_user);
	unregister_kretprobe(&krp_vmalloc);
	unregister_kretprobe(&krp___kmalloc);
	unregister_kretprobe(&krp_kmem_cache_alloc);
	unregister_kretprobe(&krp_kern_path);
	unregister_kretprobe(&krp_tgt);
*/

	unregister_kretprobe(&krp_kthread_run);
}

module_init(injector_init);
module_exit(injector_exit);

MODULE_LICENSE("GPL");
