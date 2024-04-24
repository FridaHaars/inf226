#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void getFlag(){
    printf("Congrats! you can get the flag\n");
    fflush(stdout);
    system("cat flag");
}

int main(int argc, char **argv){
    char buffer[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    int offset = 0;

    printf("What is the carrying capacity of a domestic canary? ");
    fflush(stdout);

    assert(fgets(buffer, 512, stdin) != NULL);
    offset = atoi(buffer);

    printf("Here's a hint: %lx\n", *(unsigned long*)(buffer+offset));
    fflush(stdout);

    printf("Please don't overwrite my stack!\n");
    fflush(stdout);

    assert(fgets(buffer, 512, stdin) != NULL);

    return 0;
}