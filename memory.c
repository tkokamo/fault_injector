#include <linux/slab.h>

#include "injector.h"

int ent___get_free_pages(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int *porder;

	if (!is_target(ri, regs))
		return 1;
	
	porder = (unsigned int *)ri->data;
	*porder = regs->si;

	return 0;
}

int ret___get_free_pages(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int *porder;
	unsigned long rp = regs_return_value(regs);

	if (rp == (unsigned long)NULL)
		return 0;

	porder = (unsigned int *)ri->data;

	free_pages(rp, *porder);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp___get_free_pages = {
	.handler		= ret___get_free_pages,
	.entry_handler		= ent___get_free_pages,
	.maxactive		= 20,
	.data_size		= sizeof(unsigned int),
	.kp = {
		.symbol_name    = "__get_free_pages",
	},
};

int ent___kmalloc_node(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;
	
	return 0;
}

int ret___kmalloc_node(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache *rp = (struct kmem_cache *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	kfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp___kmalloc_node = {
	.handler		= ret___kmalloc_node,
	.entry_handler		= ent___kmalloc_node,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "__kmalloc_node",
	},
};

int ent_kmem_cache_create(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;
	
	return 0;
}

int ret_kmem_cache_create(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache *rp = (struct kmem_cache *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	kmem_cache_destroy(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_kmem_cache_create = {
	.handler		= ret_kmem_cache_create,
	.entry_handler		= ent_kmem_cache_create,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kmem_cache_create",
	},
};

int ent_kmem_cache_alloc_trace(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache **pcachep;

	if (!is_target(ri, regs))
		return 1;

	pcachep = (struct kmem_cache **)ri->data;
	*pcachep = (struct kmem_cache *)regs->di;
	
	return 0;
}

int ret_kmem_cache_alloc_trace(struct kretprobe_instance *ri, struct pt_regs *regs)
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

struct kretprobe krp_kmem_cache_alloc_trace = {
	.handler		= ret_kmem_cache_alloc_trace,
	.entry_handler		= ent_kmem_cache_alloc_trace,
	.data_size		= sizeof(struct kmem_cache *),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kmem_cache_alloc_trace",
	},
};

int ent_kmem_cache_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmem_cache **pcachep;

	if (!is_target(ri, regs))
		return 1;

	pcachep = (struct kmem_cache **)ri->data;
	*pcachep = (struct kmem_cache *)regs->di;
	
	return 0;
}

int ret_kmem_cache_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
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

struct kretprobe krp_kmem_cache_alloc = {
	.handler		= ret_kmem_cache_alloc,
	.entry_handler		= ent_kmem_cache_alloc,
	.data_size		= sizeof(struct kmem_cache *),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "kmem_cache_alloc",
	},
};

int ent___kmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;

	return 0;
}

int ret___kmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	kfree(rp);
	regs->ax = (unsigned long)NULL;
	return 0;
}

struct kretprobe krp___kmalloc = {
	.handler		= ret___kmalloc,
	.entry_handler		= ent___kmalloc,
	.maxactive		= 1,
	.kp = {
		.symbol_name    = "__kmalloc",
	},
};

int ent___vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;
	
	return 0;
}

int ret___vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	vfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp___vmalloc = {
	.handler		= ret___vmalloc,
	.entry_handler		= ent___vmalloc,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "__vmalloc",
	},
};

int ent_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;
	
	return 0;
}

int ret_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	vfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_vmalloc = {
	.handler		= ret_vmalloc,
	.entry_handler		= ent_vmalloc,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "vmalloc",
	},
};

int ent_vmalloc_user(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;
	return 0;
}

int ret_vmalloc_user(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *rp = (void *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	vfree(rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_vmalloc_user = {
	.handler		= ret_vmalloc_user,
	.entry_handler		= ent_vmalloc_user,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "vmalloc_user",
	},
};

