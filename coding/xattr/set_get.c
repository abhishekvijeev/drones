#include <sys/xattr.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

struct xattr_value
{
    int num;
    char *str;
};

int main(int argc, char *argv[])
{
    struct xattr_value value;
    struct xattr_value get_val;

    char *data = malloc(50);

    value.num = 1;
    value.str = "hello\0";


    if (argc < 2 || strcmp(argv[1], "--help") == 0)
    {
        printf("%s file error\n", argv[0]);
        return 0;
    }

    // if (setxattr(argv[1], "security.apparmor", &value, sizeof(value), 0) == -1)
    // {   
    //     printf("setxattr error 1\n");
    //     return 0;
    // }

    // if(getxattr(argv[1], "security.apparmor", &get_val, sizeof(value)) != -1)
    // {
    //     printf("num: %d\n", get_val.num);
    //     printf("str: %s\n", get_val.str);
    // }
    // else
    // {
    //     printf("getxattr error\n");
    // }

    // if (setxattr(argv[1], "security.apparmor", data, strlen(data), 0) == -1)
    // {   
    //     printf("setxattr error 1\n");
    //     return 0;
    // }

    if(getxattr(argv[1], "security.apparmor", data, 50) != -1)
    {
        printf("getxattr: %s\n", data);
    }
    else
    {
        perror("getxattr error\n");
    }
    

	int fd = open("/home/abhishek/coding/xattr/f.txt", O_RDWR);
	if(write(fd, data, 10) < 10)
    {
        perror("write: ");
    }
	close(fd);

    return 0;
}
