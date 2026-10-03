#include <stdio.h>
#include <string.h>
#include "auth.h"

/* Manual test for STU-F002 (masked password entry). Not part of "make test". */
int main(void)
{
    char pw[65];
    printf("Type a password and press Enter: ");
    fflush(stdout);
    auth_read_password(pw, (int)sizeof pw);
    printf("You typed %d characters.\n", (int)strlen(pw));
    return 0;
}
