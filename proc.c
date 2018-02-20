#include <linux/proc_fs.h>

#include "injector.h"

struct proc_fault_info {
	const char		*dir_name;
	struct proc_dir_entry	*parent;
};

int ent_proc_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct proc_fault_info *ppfi;

	if (!is_target(regs))
		return 1;

	ppfi = (struct proc_fault_info *)ri->data;
	ppfi->dir_name = (char *)regs->di;
	ppfi->parent = (struct proc_dir_entry *)regs->si;
	
	return 0;
}

int ret_proc_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct proc_fault_info *ppfi;
	struct proc_dir_entry *rp =
		(struct proc_dir_entry *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	ppfi = (struct proc_fault_info *)ri->data;
	remove_proc_entry(ppfi->dir_name, ppfi->parent);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_proc_mkdir = {
	.handler		= ret_proc_mkdir,
	.entry_handler		= ent_proc_mkdir,
	.data_size		= sizeof(struct proc_fault_info),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "proc_mkdir",
	},
};

int ent_proc_create_data(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct proc_fault_info *ppfi;

	if (!is_target(regs))
		return 1;

	ppfi = (struct proc_fault_info *)ri->data;
	ppfi->dir_name = (char *)regs->di;
	ppfi->parent = (struct proc_dir_entry *)regs->dx;
	
	return 0;
}

int ret_proc_create_data(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct proc_fault_info *ppfi;
	struct proc_dir_entry *rp =
		(struct proc_dir_entry *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	ppfi = (struct proc_fault_info *)ri->data;
	remove_proc_entry(ppfi->dir_name, ppfi->parent);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_proc_create_data = {
	.handler		= ret_proc_create_data,
	.entry_handler		= ent_proc_create_data,
	.data_size		= sizeof(struct proc_fault_info),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "proc_create_data",
	},
};

