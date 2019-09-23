
#include <iostream> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stdio.h> 
#include <bits/stdc++.h>
#include <errno.h>
using namespace std; 
  
int main() 
{ 
    // ftok to generate unique key 
    key_t key = ftok("./shmfile",65); 

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
  
     cout << "key: " << key << " shmid: " << shmid << endl;
    // shmat to attach to shared memory 
    void *addr = shmat(shmid,(void*)0,0); 

    if(addr == (void *)-1)
    {
        perror("shmat");
        return 0;
    }

    char *str = (char*) addr;
  
    cout<<"Write Data : "; 
 	
	fgets(str, 30, stdin);
 	
    printf("Data written in memory: %s\n",str); 
   


	string s;
	cin >> s;


	 str = (char*) addr;

      cout<<"Write Data : ";
 
     fgets(str, 30, stdin);
 
      printf("Data written in memory: %s\n",str);



    //detach from shared memory  
    if(shmdt(str) == -1)
    {
        perror("shmdt");
        return 0;
    }
  
    return 0; 
}
