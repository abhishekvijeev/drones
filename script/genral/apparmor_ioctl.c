#include <stdio.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <sys/ioctl.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/wait.h>


typedef  int64_t tag_t;

struct flag_struct
{
    int flag;
};

#define TASKCTXIO 'r'

#define SET_FLAG _IO(TASKCTXIO, 0)
#define CLEAR_FLAG _IO(TASKCTXIO, 1)
#define SET_KERNEL_FLAG _IO(TASKCTXIO, 2)
#define CLEAR_KERNEL_FLAG _IO(TASKCTXIO, 3)


int set_flag(int fd)
{
	if(ioctl(fd, SET_FLAG) == -1)
	{
	   perror("ioctl() failed, use sudo to open device ");
	   return -1;
	}

	printf("Successfully set domain for process\n");
	return 0;
}

void clear_flag(int fd)
{
	if(ioctl(fd, CLEAR_FLAG) == -1)
	{
	   perror("ioctl() failed, use sudo to open device ");
	}	
	printf("Successfully reset domain for process\n");
}

int set_kernel_flag(int fd)
{
	if(ioctl(fd, SET_KERNEL_FLAG) == -1)
	{
	   perror("ioctl() failed, use sudo to open device ");
	   return -1;
	}

	printf("Successfully set domain for process\n");
	return 0;
}

void clear_kernel_flag(int fd)
{
	if(ioctl(fd, CLEAR_KERNEL_FLAG) == -1)
	{
	   perror("ioctl() failed, use sudo to open device ");
	}	
	printf("Successfully reset domain for process\n");
}




int main() 
{ 
	int n;
	printf ("1) to set the flag\n2) to reset the flag\n");
	printf ("3) to set the kernel flag\n4) to reset the kernel flag\n");
	scanf ("%d", &n);
	int fd = open("/dev/debug_flag", O_RDWR);
    
	if (n == 1)
    	set_flag(fd);
	else if (n == 2)
		clear_flag (fd);
	else if (n == 3)
    	set_kernel_flag(fd);
	else if (n == 4)
		clear_kernel_flag (fd);
	else
		printf ("Its not a bug, but feature is not yet implemented\n");
	
    return 0; 
} 