#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) void win(void) {
    puts("[+] ret2win reached: controlled redirection succeeded.");
}

__attribute__((noinline)) void vulnerable(void) {
    char buffer[64];
    puts("Send up to 256 bytes:");
    read(STDIN_FILENO, buffer, 256); /* Intentional stack overflow for this lab. */
    puts("Input received.");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}
