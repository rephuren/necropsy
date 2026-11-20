#include <stdio.h>
#include <unistd.h>

int main(void) {
    char input[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Enter a format string (local lab):");
    if (!fgets(input, sizeof(input), stdin)) return 1;
    printf(input); /* Intentional format-string vulnerability. */
    putchar('\n');
    return 0;
}
