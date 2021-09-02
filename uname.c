#include <stdio.h>
#include <sys/utsname.h>

void main() {
    puts("What's up?");
    
    struct utsname unameData;
    uname(&unameData);
    printf("%s \n", unameData.sysname);
    
}
