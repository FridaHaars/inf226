#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


void getFlag(){
    printf("Well done, you can get the flag\n");
    fflush(stdout);
    system("cat flag");
    return;
}

int main(int argc, char ** argv){

    unsigned long line = 1;
    struct { 
        char buffer[32];
        unsigned long* line_pointer;
    } locals;

    locals.line_pointer = &line;

    printf("What is your favourite pancake recipe? (Finish with an empty line)");
    while(locals.buffer[0] != '\n'){
        printf("%lx. ", *locals.line_pointer); 
        fflush(stdout);
        line++;


        fgets(locals.buffer, 128, stdin);
        // TODO: actually store the recipe
    }

    return 0;
}