#ifndef _INJECT_H
#define _INJECT_H


struct fault_injector {
	char	target[32];
	char	fault[32];
	int	when;
	int	error;
};

#define INJECT_FAULT _IOW('F', 1, struct fault_injector)

 #ifdef __KERNEL__
#include <linux/kprobes.h>

bool is_target(void);

extern struct kretprobe krp_kmem_cache_alloc;
extern struct kretprobe krp___kmalloc;
extern struct kretprobe krp_vmalloc;
extern struct kretprobe krp___vmalloc;
extern struct kretprobe krp_vmalloc_user;
 #endif

#endif
