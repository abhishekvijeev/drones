#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int main()
{
    char *curr_domain = "hello";

    
    char *context = (char *)malloc(strlen(curr_domain) + 2);
    context = strcat(context, curr_domain);
	context = strcat(context, ",");
    //context = strcat(context, "\0");

    context[6] = '\0';



    printf("context: %s\n", context);
    return 0;
}