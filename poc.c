#include <stdio.h>
#include <string.h>

// gcc poc.c -mpreferred-stack-boundary=2 -o main

int main(int argc, char * argv[]){
    char buff[128];    
    if(argc<2)
        return 0xffe4; //JMP dont forgive this is a proof of concept ! 
        strcpy(buff, argv[1]);
        return 0;
}


