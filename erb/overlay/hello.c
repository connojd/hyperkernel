#include <unistd.h>

int main()
{
    while(1) {
        sleep(1);
        __asm__ volatile("cpuid" :: "rax"(0xBF00) : "rbx", "rcx", "rdx");
    }
}
