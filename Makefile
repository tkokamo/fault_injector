obj-m := injector.o
injector-y :=	memory.o	\
		main.o


KERNEL_DIR := /lib/modules/`uname -r`/build
VERBOSE = 0

default:
	$(MAKE) -C $(KERNEL_DIR) KBUILD_VERBOSE=$(VERBOSE) M=$(PWD) modules
clean:
	rm -rf *.o *.ko Module.symvers *.mod.c modules.order .tmp_versions .injector.*
