#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int getFlag(){
	printf("Congrats! you can get the flag\n");
	fflush(stdout);
	system("cat flag");
    return 0;
}

int main(int argc, char **argv){
    struct {
        char buffer[16];
        volatile int (*funPointer)();
    } vars;

    vars.funPointer = NULL;

    printf("And, what is your quest? ");
    fflush(stdout);

    assert(fgets(vars.buffer, 512, stdin) != NULL);

    if(vars.funPointer){
        printf("Let's go to %p\n", vars.funPointer);
        fflush(stdout);
        vars.funPointer();
    }
    else{
        printf("oh no, please try again!\n");
    }

    return 0;
}