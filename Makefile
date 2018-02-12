obj-m := injector.o

KERNEL_DIR := /lib/modules/`uname -r`/build
VERBOSE = 0

default:
	$(MAKE) -C $(KERNEL_DIR) KBUILD_VERBOSE=$(VERBOSE) M=$(PWD) modules
clean:
	rm -f *.o *.ko
