#include <linux/cdev.h>

#include "injector.h"

struct cdev_fault_info {
	dev_t           *id;
	struct cdev     *cdev;
	struct class    *class;
	struct device   *dev;
};

int ent_alloc_chrdev_region(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cdev_fault_info *pcfi;

	if (!is_target(regs))
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
	regs->ax = (unsigned long)fis[0].fi->error;

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

