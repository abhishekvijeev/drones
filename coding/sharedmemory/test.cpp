#define _GNU_SOURCE
       #include <sys/wait.h>
       #include <sys/utsname.h>
       #include <sched.h>
       #include <string.h>
       #include <stdio.h>
       #include <stdlib.h>
       #include <unistd.h>
       #include <iostream> 
        #include <sys/ipc.h> 
        #include <sys/shm.h> 
        #include <stdio.h> 
        #include <bits/stdc++.h>
        #include <errno.h>

       using namespace std;

       #define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)

       static int              /* Start function for cloned child */
       childFunc(void *arg)
       {
           struct utsname uts;

           /* Change hostname in UTS namespace of child */

           if (sethostname((char *)arg, strlen((char *)arg)) == -1)
               errExit("sethostname");

           /* Retrieve and display hostname */

           if (uname(&uts) == -1)
               errExit("uname");
           printf("uts.nodename in child:  %s\n", uts.nodename);

           /* Keep the namespace open for a while, by sleeping.
              This allows some experimentation--for example, another
              process might join the namespace. */

        //    sleep(200);

        key_t key = ftok("./reader",65); 

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
        
        //detach from shared memory  
        if(shmdt(str) == -1)
        {
            perror("shmdt");
            return 0;
        }

           return 0;           /* Child terminates now */
       }

       #define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */

       int
       main(int argc, char *argv[])
       {
           char *stack;                    /* Start of stack buffer */
           char *stackTop;                 /* End of stack buffer */
           pid_t pid;
           struct utsname uts;

           if (argc < 2) {
               fprintf(stderr, "Usage: %s <child-hostname>\n", argv[0]);
               exit(EXIT_SUCCESS);
           }

           /* Allocate stack for child */

           stack = (char *)malloc(STACK_SIZE);
           if (stack == NULL)
               errExit("malloc");
           stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

           /* Create child that has its own UTS namespace;
              child commences execution in childFunc() */

           pid = clone(childFunc, stackTop, CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD, argv[1]);
           if (pid == -1)
               errExit("clone");
           printf("clone() returned %ld\n", (long) pid);

           /* Parent falls through to here */

           sleep(1);           /* Give child time to change its hostname */

           /* Display hostname in parent's UTS namespace. This will be
              different from hostname in child's UTS namespace. */

           if (uname(&uts) == -1)
               errExit("uname");
           printf("uts.nodename in parent: %s\n", uts.nodename);

           if (waitpid(pid, NULL, 0) == -1)    /* Wait for child */
               errExit("waitpid");
           printf("child has terminated\n");

           exit(EXIT_SUCCESS);
       }