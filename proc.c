#include <linux/proc_fs.h>

#include "injector.h"

int ent_proc_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char **pdir_name;

	if (!is_target())
		return 1;

	pdir_name = (char **)ri->data;
	*pdir_name = (char *)regs->di;
	
	return 0;
}

int ret_proc_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char **pdir_name;
	struct proc_dir_entry *rp =
		(struct proc_dir_entry *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	pdir_name = (char **)ri->data;
	remove_proc_entry(*pdir_name, rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_proc_mkdir = {
	.handler		= ret_proc_mkdir,
	.entry_handler		= ent_proc_mkdir,
	.data_size		= sizeof(char *),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "proc_mkdir",
	},
};

int ent_proc_create_data(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char **pdir_name;

	if (!is_target())
		return 1;

	pdir_name = (char **)ri->data;
	*pdir_name = (char *)regs->di;
	
	return 0;
}

int ret_proc_create_data(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char **pdir_name;
	struct proc_dir_entry *rp =
		(struct proc_dir_entry *)regs_return_value(regs);

	if (rp == NULL)
		return 0;

	pdir_name = (char **)ri->data;
	remove_proc_entry(*pdir_name, rp);
	regs->ax = (unsigned long)NULL;

	return 0;
}

struct kretprobe krp_proc_create_data = {
	.handler		= ret_proc_create_data,
	.entry_handler		= ent_proc_create_data,
	.data_size		= sizeof(char *),
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "proc_create_data",
	},
};

