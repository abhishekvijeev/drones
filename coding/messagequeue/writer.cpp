// C Program for Message Queue (Writer Process) 
#include <stdio.h> 
#include <sys/ipc.h> 
#include <sys/msg.h> 
#include <bits/stdc++.h>

using namespace std;

// structure for message queue 
struct mesg_buffer { 
    long mesg_type; 
    char mesg_text[100]; 
} message; 


void createfile()
{
   ofstream ofile;
   ofile.open ("text.txt");
   string str;
   cout << "Enter data: ";
   cin >> str;
   ofile << str << endl;
   cout << "Data written to file" << endl;
   ofile.close();
}


int main() 
{ 
	createfile();
    key_t key; 
    int msgid; 
  
    // ftok to generate unique key 
    key = ftok("progfile", 65); 
  
    // msgget creates a message queue 
    // and returns identifier 
    msgid = msgget(key, 0666 | IPC_CREAT); 
    message.mesg_type = 1; 
  
    printf("Write Data : "); 
	fgets(message.mesg_text, 20, stdin);
    //gets(message.mesg_text); 
  
    // msgsnd to send message 
    msgsnd(msgid, &message, sizeof(message), 0); 
  
    // display the message 
    printf("Data send is : %s \n", message.mesg_text); 
  
    return 0; 
} 
