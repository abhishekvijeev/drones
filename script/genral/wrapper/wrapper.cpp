#include <iostream> 
#include <sys/types.h> 
#include <unistd.h> 
#include <sys/wait.h>

using namespace std; 
  
int main(int argc, char** argv) 
{ 
	if (argc != 2)
	{
		cout << "USAGE: ./wrapper {path to executable}";
		exit(0);
	}
	int pid = fork();	
	if (pid == 0)
	{
		char *argument[]={argv[1],NULL}; 
		execv(argument[0],argument); 
	}
	else
	{
		wait(NULL);
		exit(0);
	}
     
} 
