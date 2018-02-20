#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>


#include "../injector.h"

int main(int argc, char **argv)
{
	int fd, rc;
	struct fault_injector fi;

	if (argc < 7) {
		fprintf(stderr, "Usage: %s <target> <fault> <comm> <module> <when> <error>\n", argv[0]);
		exit(1);
	}
	
	fd = open("/dev/fault_inject", O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	strcpy(fi.target, argv[1]);
	strcpy(fi.fault, argv[2]);
	strcpy(fi.comm, argv[3]);
	strcpy(fi.module, argv[4]);
	fi.when = atoi(argv[5]);
	fi.error = atoi(argv[6]);

	rc = ioctl(fd, INJECT_FAULT, &fi);
	if (rc < 0) {
		perror("ioctl");
		exit(1);
	}

	close(fd);
	return 0;
}
