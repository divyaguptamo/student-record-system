#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "auth.h"
#include "sha256.h"

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#define MAX_USERS            100
#define MAX_FAILED_ATTEMPTS  3
#define MAX_PASSWORD_LEN     64

static User users[MAX_USERS];
static int  user_count = 0;
static char user_path[260] = "";
static char log_path[260]  = "";

/* Simple log hook. Replace with Mem 2's audit module once it is merged. */
static void log_event(const char *event, const char *username)
{
    FILE *f;
    char ts[32];
    time_t now = time(NULL);

    if (log_path[0] == '\0') return;
    f = fopen(log_path, "a");
    if (!f) return;
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "%s | AUTH | %s | %s\n", ts, username ? username : "-", event);
    fclose(f);
}

static int save_users(void)
{
    int i;
    FILE *f = fopen(user_path, "w");
    if (!f) return -1;
    for (i = 0; i < user_count; i++) {
        fprintf(f, "%s,%s,%d,%s,%d,%d\n",
                users[i].username, users[i].password_hash, (int)users[i].role,
                users[i].roll_no, users[i].failed_attempts, users[i].locked);
    }
    fclose(f);
    return 0;
}

static int find_user(const char *username)
{
    int i;
    for (i = 0; i < user_count; i++)
        if (strcmp(users[i].username, username) == 0) return i;
    return -1;
}

/* Reject empty values, values that are too long, and characters that break the file format. */
static int valid_field(const char *s, size_t max_len)
{
    size_t n;
    if (!s) return 0;
    n = strlen(s);
    if (n == 0 || n >= max_len) return 0;
    if (strpbrk(s, ",\r\n") != NULL) return 0;
    return 1;
}

int auth_init(const char *user_file, const char *log_file)
{
    FILE *f;
    char line[256];

    if (!user_file || !log_file) return -1;
    snprintf(user_path, sizeof user_path, "%s", user_file);
    snprintf(log_path, sizeof log_path, "%s", log_file);
    user_count = 0;

    f = fopen(user_path, "r");
    if (!f) return 0;   /* no file yet: empty user list */

    while (user_count < MAX_USERS && fgets(line, sizeof line, f)) {
        User u;
        int role, failed, locked;
        memset(&u, 0, sizeof u);
        if (sscanf(line, "%31[^,],%64[^,],%d,%15[^,],%d,%d",
                   u.username, u.password_hash, &role, u.roll_no,
                   &failed, &locked) == 6) {
            u.role = (role == ROLE_ADMIN) ? ROLE_ADMIN : ROLE_STUDENT;
            u.failed_attempts = failed;
            u.locked = locked ? 1 : 0;
            users[user_count++] = u;
        }
    }
    fclose(f);
    return 0;
}

void auth_hash_password(const char *plain, char out_hex[65])
{
    SHA256_CTX ctx;
    BYTE digest[SHA256_BLOCK_SIZE];
    int i;

    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)plain, strlen(plain));
    sha256_final(&ctx, digest);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        sprintf(out_hex + i * 2, "%02x", digest[i]);
    out_hex[64] = '\0';
}

int auth_add_user(const char *username, const char *plain, Role role, const char *roll_no)
{
    User *u;

    if (user_path[0] == '\0') return -1;
    if (!valid_field(username, sizeof users[0].username)) return -1;
    if (!valid_field(plain, MAX_PASSWORD_LEN + 1)) return -1;
    if (roll_no && roll_no[0] != '\0' && !valid_field(roll_no, sizeof users[0].roll_no)) return -1;
    if (find_user(username) >= 0) return -1;      /* duplicate */
    if (user_count >= MAX_USERS) return -1;

    u = &users[user_count];
    memset(u, 0, sizeof *u);
    snprintf(u->username, sizeof u->username, "%s", username);
    auth_hash_password(plain, u->password_hash);
    u->role = role;
    snprintf(u->roll_no, sizeof u->roll_no, "%s", (roll_no && roll_no[0]) ? roll_no : "-");
    user_count++;

    if (save_users() != 0) { user_count--; return -1; }
    return 0;
}

void auth_ensure_default_admin(void)
{
    if (user_count == 0) auth_add_user("admin", "admin123", ROLE_ADMIN, NULL);
}

AuthResult auth_login(const char *username, const char *plain, Session *out)
{
    int idx;
    char hash[65];
    User *u;

    if (!username || !plain || username[0] == '\0' || plain[0] == '\0') return AUTH_INVALID_INPUT;
    if (strlen(username) >= sizeof users[0].username) return AUTH_INVALID_INPUT;
    if (strlen(plain) > MAX_PASSWORD_LEN) return AUTH_INVALID_INPUT;

    idx = find_user(username);
    if (idx < 0) {
        log_event("LOGIN_FAILED_UNKNOWN_USER", username);
        return AUTH_NO_SUCH_USER;
    }
    u = &users[idx];

    if (u->locked) {
        log_event("LOGIN_BLOCKED_ACCOUNT_LOCKED", username);
        return AUTH_LOCKED;
    }

    auth_hash_password(plain, hash);
    if (strcmp(hash, u->password_hash) != 0) {
        u->failed_attempts++;
        log_event("LOGIN_FAILED", username);
        if (u->failed_attempts >= MAX_FAILED_ATTEMPTS) {
            u->locked = 1;
            log_event("ACCOUNT_LOCKOUT", username);
            save_users();
            return AUTH_LOCKED;
        }
        save_users();
        return AUTH_BAD_CREDENTIALS;
    }

    u->failed_attempts = 0;
    save_users();
    log_event("LOGIN_SUCCESS", username);
    if (out) {
        memset(out, 0, sizeof *out);
        snprintf(out->username, sizeof out->username, "%s", u->username);
        out->role = u->role;
        snprintf(out->roll_no, sizeof out->roll_no, "%s", u->roll_no);
    }
    return AUTH_OK;
}

void auth_read_password(char *buf, int len)
{
    int i = 0;
    if (!buf || len <= 0) return;

#ifdef _WIN32
    {
        int c;
        while ((c = _getch()) != '\r' && c != '\n') {
            if (c == '\b') {
                if (i > 0) { i--; printf("\b \b"); }
            } else if (i < len - 1 && c >= 32) {
                buf[i++] = (char)c;
                putchar('*');
            }
        }
        putchar('\n');
    }
#else
    {
        struct termios oldt, newt;
        int c;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        while ((c = getchar()) != '\n' && c != EOF) {
            if (i < len - 1) buf[i++] = (char)c;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        putchar('\n');
    }
#endif
    buf[i] = '\0';
}

int auth_can_view_record(const Session *s, const char *roll_no)
{
    if (!s || !roll_no) return 0;
    if (s->role == ROLE_ADMIN) return 1;
    return strcmp(s->roll_no, roll_no) == 0;
}

int auth_can_modify(const Session *s)
{
    return s != NULL && s->role == ROLE_ADMIN;
}

void auth_logout(Session *s)
{
    if (s) memset(s, 0, sizeof *s);
}
