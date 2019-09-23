#include <iostream> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stdio.h> 
#include <errno.h>
using namespace std; 
  
int main() 
{ 
    // ftok to generate unique key 
    key_t key = ftok("shmfile1",65); 

    if(key == -1)
    {
        perror("key error");
        return 0;
    }
  
    // shmget returns an identifier in shmid 
    int shmid = shmget(key,8,0666|IPC_CREAT); 

    if(shmid == -1)
    {
        perror("shmget");
        return 0;
    }
  
    // shmat to attach to shared memory 
    void *addr = shmat(shmid,(void*)0,0); 

    if(addr == (void *)-1)
    {
        perror("shmat");
        return 0;
    }

    char *str = (char*) addr;
  
    printf("Data read from memory: %s\n",str); 
      
    //detach from shared memory  
    if(shmdt(str) == -1)
    {
        perror("shmdt");
        return 0;
    }
    
    // destroy the shared memory 
    if(shmctl(shmid,IPC_RMID,NULL) == -1)
    {
        perror("shmctl");
        return 0;
    }
     
    return 0; 
} 
