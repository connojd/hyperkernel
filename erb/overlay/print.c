#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    while (1) {
        __asm__ volatile("vmcall" :: "rax"(0xBF00ULL));
        sleep(1);
    }
}
