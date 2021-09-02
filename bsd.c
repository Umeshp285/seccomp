#include <unistd.h>
#include <stdio.h>
int
main() {
        if(pledge("",NULL) == -1) {
               err(1,"pledge");
        }
printf("Pledged\n");
return 0;
}
