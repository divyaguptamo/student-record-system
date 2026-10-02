#ifndef AUTH_H
#define AUTH_H

typedef enum { ROLE_STUDENT = 0, ROLE_ADMIN = 1 } Role;

typedef enum {
    AUTH_OK,
    AUTH_BAD_CREDENTIALS,
    AUTH_LOCKED,
    AUTH_NO_SUCH_USER,
    AUTH_INVALID_INPUT
} AuthResult;

typedef struct {
    char username[32];
    char password_hash[65];   /* hex SHA-256 */
    Role role;
    char roll_no[16];         /* students: links login to their record, "-" if none */
    int  failed_attempts;
    int  locked;
} User;

typedef struct {
    char username[32];
    Role role;
    char roll_no[16];
} Session;

/* Load users from file (a missing file means an empty user list). Returns 0 on success. */
int  auth_init(const char *user_file, const char *log_file);

/* STU-F002, STU-SR001: SHA-256 as 64 hex chars + NUL */
void auth_hash_password(const char *plain, char out_hex[65]);

/* Returns 0 on success, -1 on invalid input, duplicate user, or full table. */
int  auth_add_user(const char *username, const char *plain, Role role, const char *roll_no);

/* Creates admin / admin123 if no users exist. Change this password after first run. */
void auth_ensure_default_admin(void);

/* STU-F001, STU-F003 */
AuthResult auth_login(const char *username, const char *plain, Session *out);

/* STU-F002: reads a password without echoing it */
void auth_read_password(char *buf, int len);

/* STU-F004 */
int  auth_can_view_record(const Session *s, const char *roll_no);

/* STU-SR002: only admins may write grades/attendance */
int  auth_can_modify(const Session *s);

void auth_logout(Session *s);

#endif
