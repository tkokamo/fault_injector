#ifndef _INJECTOR_H
#define _INJECTOR_H

struct fault_injector {
	char	target[32];
	char	fault[32];
	char	comm[32];
	char	module[32];
	int	when;
	int	error;
};

#define INJECT_FAULT _IOW('F', 1, struct fault_injector)

 #ifdef __KERNEL__
#include <linux/kprobes.h>

struct fi_instance {
	struct task_struct	*task;
	struct fault_injector	*fi;
	int			when;
	bool			enter;
};

bool is_target(struct pt_regs *);

extern struct fi_instance fis[1];

extern struct kretprobe krp_alloc_chrdev_region;
extern struct kretprobe krp_proc_mkdir;
extern struct kretprobe krp_proc_create_data;
extern struct kretprobe krp_kern_path;
extern struct kretprobe krp_d_path;
extern struct kretprobe krp_kthread_run;
extern struct kretprobe krp_kmem_cache_alloc_trace;
extern struct kretprobe krp_kmem_cache_alloc;
extern struct kretprobe krp___kmalloc;
extern struct kretprobe krp_vmalloc;
extern struct kretprobe krp___vmalloc;
extern struct kretprobe krp_vmalloc_user;
 #endif

#endif
