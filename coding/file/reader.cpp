// C program for reading  
// struct from a file 
#include <stdio.h> 
#include <stdlib.h> 
#include <bits/stdc++.h>

using namespace std;
// struct person with 3 fields 
struct person  
{ 
    int id; 
    char fname[20]; 
    char lname[20]; 
}; 
  
// Driver program 
int main () 
{ 
	string str;
	cout << "Enter any random input:";
	cin >> str;
    FILE *infile; 
    struct person input; 
      
    // Open person.dat for reading 
    infile = fopen ("person.dat", "r"); 
    if (infile == NULL) 
    { 
        fprintf(stderr, "\nError opening file\n"); 
        exit (1); 
    } 
      
    // read file contents till end of file 
    while(fread(&input, sizeof(struct person), 1, infile)) 
        printf ("id = %d name = %s %s\n", input.id, 
        input.fname, input.lname); 
  
    // close file 
    fclose (infile); 
  
    return 0; 
} 