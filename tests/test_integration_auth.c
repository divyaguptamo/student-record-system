#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "auth.h"

#define IT_USERS "it_users.dat"
#define IT_LOG   "it_audit.log"

static void read_file(const char *path, char *buf, size_t n)
{
    size_t r;
    FILE *f = fopen(path, "r");
    buf[0] = '\0';
    if (!f) return;
    r = fread(buf, 1, n - 1, f);
    buf[r] = '\0';
    fclose(f);
}

void setUp(void)
{
    remove(IT_USERS);
    remove(IT_LOG);
    auth_init(IT_USERS, IT_LOG);
}

void tearDown(void)
{
    remove(IT_USERS);
    remove(IT_LOG);
}

/* Users saved by one run are available to the next run */
void test_users_persist_across_restart(void)
{
    Session s;
    TEST_ASSERT_EQUAL_INT(0, auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001"));
    auth_init(IT_USERS, IT_LOG);   /* simulate restarting the program */
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("alice", "Pass@1234", &s));
    TEST_ASSERT_EQUAL_STRING("PES001", s.roll_no);
}

/* Login outcomes are written to the audit log */
void test_login_events_written_to_audit_log(void)
{
    Session s;
    char buf[4096];
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");
    auth_login("alice", "Pass@1234", &s);
    auth_login("alice", "wrong", &s);
    auth_login("ghost", "x", &s);
    read_file(IT_LOG, buf, sizeof buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "alice | LOGIN_SUCCESS"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "alice | LOGIN_FAILED"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "ghost | LOGIN_FAILED_UNKNOWN_USER"));
}

/* After lockout, further attempts are blocked and logged */
void test_blocked_attempt_logged_when_locked(void)
{
    Session s;
    char buf[4096];
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");
    auth_login("alice", "b1", &s);
    auth_login("alice", "b2", &s);
    auth_login("alice", "b3", &s);
    TEST_ASSERT_EQUAL_INT(AUTH_LOCKED, auth_login("alice", "Pass@1234", &s));
    read_file(IT_LOG, buf, sizeof buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "LOGIN_BLOCKED_ACCOUNT_LOCKED"));
}

/* Failed attempts are stored in the file, so restarting does not reset them */
void test_failed_attempts_persist_across_restart(void)
{
    Session s;
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");
    auth_login("alice", "b1", &s);
    auth_login("alice", "b2", &s);
    auth_init(IT_USERS, IT_LOG);   /* restart */
    TEST_ASSERT_EQUAL_INT(AUTH_LOCKED, auth_login("alice", "b3", &s));
}

/* A missing user file is treated as an empty user list, not a crash */
void test_missing_user_file_is_empty_list(void)
{
    Session s;
    TEST_ASSERT_EQUAL_INT(0, auth_init("no_such_file.dat", IT_LOG));
    TEST_ASSERT_EQUAL_INT(AUTH_NO_SUCH_USER, auth_login("admin", "admin123", &s));
}

/* The default admin is created only when there are no users */
void test_default_admin_created_only_when_empty(void)
{
    Session s;
    auth_ensure_default_admin();
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("admin", "admin123", &s));
    TEST_ASSERT_EQUAL_INT(ROLE_ADMIN, s.role);
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("admin", "x", ROLE_ADMIN, NULL));

    remove(IT_USERS);
    auth_init(IT_USERS, IT_LOG);
    auth_add_user("bob", "Pass@5678", ROLE_STUDENT, "PES002");
    auth_ensure_default_admin();   /* users exist, so no admin is added */
    TEST_ASSERT_EQUAL_INT(AUTH_NO_SUCH_USER, auth_login("admin", "admin123", &s));
}

/* A corrupt line in the file is skipped and valid lines still load */
void test_corrupt_line_skipped_valid_line_loaded(void)
{
    Session s;
    char hash[65];
    FILE *f;
    auth_hash_password("Pass@9999", hash);
    f = fopen(IT_USERS, "w");
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f, "garbage line without commas\n");
    fprintf(f, "carol,%s,0,PES003,0,0\n", hash);
    fclose(f);
    TEST_ASSERT_EQUAL_INT(0, auth_init(IT_USERS, IT_LOG));
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("carol", "Pass@9999", &s));
}

/* Full session flow: student is restricted, then admin logs in and is allowed */
void test_student_then_admin_session_flow(void)
{
    Session st, ad;
    auth_add_user("admin", "Admin@123", ROLE_ADMIN, NULL);
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");

    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("alice", "Pass@1234", &st));
    TEST_ASSERT_TRUE(auth_can_view_record(&st, "PES001"));
    TEST_ASSERT_FALSE(auth_can_view_record(&st, "PES002"));
    TEST_ASSERT_FALSE(auth_can_modify(&st));
    auth_logout(&st);
    TEST_ASSERT_FALSE(auth_can_view_record(&st, "PES001"));

    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("admin", "Admin@123", &ad));
    TEST_ASSERT_TRUE(auth_can_view_record(&ad, "PES002"));
    TEST_ASSERT_TRUE(auth_can_modify(&ad));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_users_persist_across_restart);
    RUN_TEST(test_login_events_written_to_audit_log);
    RUN_TEST(test_blocked_attempt_logged_when_locked);
    RUN_TEST(test_failed_attempts_persist_across_restart);
    RUN_TEST(test_missing_user_file_is_empty_list);
    RUN_TEST(test_default_admin_created_only_when_empty);
    RUN_TEST(test_corrupt_line_skipped_valid_line_loaded);
    RUN_TEST(test_student_then_admin_session_flow);
    return UNITY_END();
}
