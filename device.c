#include <linux/cdev.h>
#include <linux/device.h>

#include "injector.h"

struct cdev_fault_info {
	dev_t           *id;
	dev_t		idi;
	struct cdev     *cdev;
	struct class    *class;
	struct device   *dev;
};

int ent_device_create(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cdev_fault_info *pcfi;

	if (!is_target(ri, regs))
		return 1;

	pcfi = (struct cdev_fault_info *)ri->data;
	pcfi->class = (struct class *)regs->di;
	pcfi->idi = (dev_t)regs->dx;

	return 0;
}

int ret_device_create(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct device *rp = (struct device *)regs_return_value(regs);
	struct cdev_fault_info *pcfi;

	if (IS_ERR(rp))
		return 0;

	pcfi = (struct cdev_fault_info *)ri->data;
	device_destroy(pcfi->class, pcfi->idi);
	regs->ax = get_errno(ri->rp->kp.symbol_name);

	return 0;
}

struct kretprobe krp_device_create = {
	.handler		= ret_device_create,
	.entry_handler		= ent_device_create,
	.data_size		= sizeof(struct cdev_fault_info),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "device_create",
	},
};

int ent_class_create(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;

	return 0;
}

int ret_class_create(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct class *rp = (struct class *)regs_return_value(regs);

	if (IS_ERR(rp))
		return 0;

	class_destroy(rp);
	regs->ax = get_errno(ri->rp->kp.symbol_name);

	return 0;
}

struct kretprobe krp_class_create = {
	.handler		= ret_class_create,
	.entry_handler		= ent_class_create,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "__class_create",
	},
};

int ent_cdev_add(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cdev_fault_info *pcfi;

	if (!is_target(ri, regs))
		return 1;

	pcfi = (struct cdev_fault_info *)ri->data;
	pcfi->cdev = (struct cdev *)regs->di;
	
	return 0;
}

int ret_cdev_add(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cdev_fault_info *pcfi;
	int rc = regs_return_value(regs);

	if (rc < 0)
		return 0;

	pcfi = (struct cdev_fault_info *)ri->data;
	cdev_del(pcfi->cdev);
	regs->ax = get_errno(ri->rp->kp.symbol_name);

	return 0;
}

struct kretprobe krp_cdev_add = {
	.handler		= ret_cdev_add,
	.entry_handler		= ent_cdev_add,
	.data_size		= sizeof(struct cdev_fault_info),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "cdev_add",
	},
};

int ent_alloc_chrdev_region(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cdev_fault_info *pcfi;

	if (!is_target(ri, regs))
		return 1;

	pcfi = (struct cdev_fault_info *)ri->data;
	pcfi->id = (dev_t *)regs->di;
	
	return 0;
}

int ret_alloc_chrdev_region(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cdev_fault_info *pcfi;
	int rc = regs_return_value(regs);

	if (rc < 0)
		return 0;

	pcfi = (struct cdev_fault_info *)ri->data;
	unregister_chrdev_region(*pcfi->id, 1);
	regs->ax = get_errno(ri->rp->kp.symbol_name);

	return 0;
}

struct kretprobe krp_alloc_chrdev_region = {
	.handler		= ret_alloc_chrdev_region,
	.entry_handler		= ent_alloc_chrdev_region,
	.data_size		= sizeof(struct cdev_fault_info),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "alloc_chrdev_region",
	},
};

