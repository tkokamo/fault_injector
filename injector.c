#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>

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

	printk("EK ax:%lx, bx:%lx, cx:%lx, dx:%lx, di:%lx, si:%lx\n",
			regs->ax, regs->bx, regs->cx, regs->dx, regs->di, regs->si);

	ppath = (struct path **)ri->data;
	*ppath = (struct path *)regs->dx;

	printk("EK path:%p\n", *ppath);
	return 0;
}

static int ret_kern_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path **ppath;
	int rc = regs_return_value(regs);

	if (rc < 0)
		return 0;

	ppath = (struct path **)ri->data;
	printk("RK path:%p\n", *ppath);
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

	printk("EKM ax:%lx, bx:%lx, cx:%lx, dx:%lx, di:%lx, si:%lx\n",
			regs->ax, regs->bx, regs->cx, regs->dx, regs->di, regs->si);

	return 0;
}

static int ret_kmem_cache_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache **pcachep;
	void *rp = (void *)regs_return_value(regs);
	unsigned long *sp = NULL;

	if (rp == NULL)
		return 0;

	pcachep = (struct kmem_cache **)ri->data;
	printk("RKM %p %p %lx\n", *pcachep, rp, regs->ax);
	kmem_cache_free(*pcachep, rp);
	regs->ax = (unsigned long)NULL;

	sp = (unsigned long *)regs->sp;
	sp[10] = (unsigned long)NULL;

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

	printk("E_KM ax:%lx, bx:%lx, cx:%lx, dx:%lx, di:%lx, si:%lx\n",
			regs->ax, regs->bx, regs->cx, regs->dx, regs->di, regs->si);

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

	return 0;
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
	unregister_kretprobe(&krp___kmalloc);
	unregister_kretprobe(&krp_kmem_cache_alloc);
	unregister_kretprobe(&krp_kern_path);
	unregister_kretprobe(&krp_tgt);
}

module_init(injector_init);
module_exit(injector_exit);

MODULE_LICENSE("GPL");
