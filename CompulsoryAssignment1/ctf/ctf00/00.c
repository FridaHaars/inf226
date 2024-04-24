#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
    struct {
        char buffer[16];
        int32_t check;
    } locals;

    locals.check = 0xabcdc3cf;
    printf("What is your name? ");
    fflush(stdout);

    assert(fgets(locals.buffer, 512, stdin) != NULL);

    if(locals.check == 0x00c0ffee) {
        printf("Thanks, you may proceed\n");
        fflush(stdout);
        system("cat flag");
    }
    else {
        printf("Ooops, *wrong*!! Bye, bye\n");
    }

    return 0;
}