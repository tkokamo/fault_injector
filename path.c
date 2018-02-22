#include "injector.h"

static int ent_kern_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path **ppath;

	if (!is_target(ri, regs))
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
	regs->ax = get_errno(ri->rp->kp.symbol_name);

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

static int ent_d_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!is_target(ri, regs))
		return 1;

	return 0;
}

static int ret_d_path(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int rc = regs_return_value(regs);

	if (rc < 0)
		return 0;

	regs->ax = get_errno(ri->rp->kp.symbol_name);

	return 0;
}

struct kretprobe krp_d_path = {
	.handler		= ret_d_path,
	.entry_handler		= ent_d_path,
	.maxactive		= 20,
	.kp = {
		.symbol_name    = "d_path",
	},
};


