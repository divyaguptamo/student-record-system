#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "auth.h"

#define TEST_USERS "test_users.dat"
#define TEST_LOG   "test_audit.log"

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
    remove(TEST_USERS);
    remove(TEST_LOG);
    auth_init(TEST_USERS, TEST_LOG);
    auth_add_user("admin", "Admin@123", ROLE_ADMIN, NULL);
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");
    auth_add_user("bob",   "Pass@5678", ROLE_STUDENT, "PES002");
}

void tearDown(void)
{
    remove(TEST_USERS);
    remove(TEST_LOG);
}

/* ---------- TC-Auth-01: authenticate ---------- */
void test_login_valid_credentials(void)
{
    Session s;
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("alice", "Pass@1234", &s));
    TEST_ASSERT_EQUAL_STRING("alice", s.username);
    TEST_ASSERT_EQUAL_STRING("PES001", s.roll_no);
    TEST_ASSERT_EQUAL_INT(ROLE_STUDENT, s.role);
}

void test_login_wrong_password(void)
{
    Session s;
    TEST_ASSERT_EQUAL_INT(AUTH_BAD_CREDENTIALS, auth_login("alice", "wrong", &s));
}

void test_login_unknown_user(void)
{
    Session s;
    TEST_ASSERT_EQUAL_INT(AUTH_NO_SUCH_USER, auth_login("nobody", "x", &s));
}

void test_login_empty_input(void)
{
    Session s;
    TEST_ASSERT_EQUAL_INT(AUTH_INVALID_INPUT, auth_login("", "x", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_INVALID_INPUT, auth_login("alice", "", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_INVALID_INPUT, auth_login(NULL, "x", &s));
}

void test_login_overlong_username(void)
{
    Session s;
    char longname[64];
    memset(longname, 'a', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    TEST_ASSERT_EQUAL_INT(AUTH_INVALID_INPUT, auth_login(longname, "x", &s));
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user(longname, "x", ROLE_STUDENT, NULL));
}

void test_duplicate_user_rejected(void)
{
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("alice", "Other@1", ROLE_STUDENT, "PES009"));
}

/* ---------- TC-Auth-02: hashing ---------- */
void test_hash_known_vector(void)
{
    char h[65];
    auth_hash_password("abc", h);
    TEST_ASSERT_EQUAL_STRING(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h);
}

void test_hash_length_and_consistency(void)
{
    char h1[65], h2[65], h3[65];
    auth_hash_password("Pass@1234", h1);
    auth_hash_password("Pass@1234", h2);
    auth_hash_password("Pass@1235", h3);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(h1));
    TEST_ASSERT_EQUAL_STRING(h1, h2);
    TEST_ASSERT_TRUE(strcmp(h1, h3) != 0);
}

/* ---------- TC-Sec-02: no plaintext on disk ---------- */
void test_no_plaintext_in_user_file(void)
{
    char buf[2048], h[65];
    read_file(TEST_USERS, buf, sizeof buf);
    TEST_ASSERT_NULL(strstr(buf, "Pass@1234"));
    TEST_ASSERT_NULL(strstr(buf, "Admin@123"));
    auth_hash_password("Pass@1234", h);
    TEST_ASSERT_NOT_NULL(strstr(buf, h));
}

/* ---------- TC-Auth-03: lockout ---------- */
void test_lockout_after_three_failures(void)
{
    Session s;
    char buf[2048];
    TEST_ASSERT_EQUAL_INT(AUTH_BAD_CREDENTIALS, auth_login("alice", "bad1", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_BAD_CREDENTIALS, auth_login("alice", "bad2", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_LOCKED,          auth_login("alice", "bad3", &s));
    read_file(TEST_LOG, buf, sizeof buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "ACCOUNT_LOCKOUT"));
}

void test_locked_account_rejects_correct_password(void)
{
    Session s;
    auth_login("alice", "bad1", &s);
    auth_login("alice", "bad2", &s);
    auth_login("alice", "bad3", &s);
    TEST_ASSERT_EQUAL_INT(AUTH_LOCKED, auth_login("alice", "Pass@1234", &s));
}

void test_success_resets_failure_counter(void)
{
    Session s;
    auth_login("alice", "bad1", &s);
    auth_login("alice", "bad2", &s);
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("alice", "Pass@1234", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_BAD_CREDENTIALS, auth_login("alice", "bad1", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_BAD_CREDENTIALS, auth_login("alice", "bad2", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_LOCKED,          auth_login("alice", "bad3", &s));
}

void test_lockout_persists_after_reload(void)
{
    Session s;
    auth_login("alice", "bad1", &s);
    auth_login("alice", "bad2", &s);
    auth_login("alice", "bad3", &s);
    auth_init(TEST_USERS, TEST_LOG);   /* simulate restarting the program */
    TEST_ASSERT_EQUAL_INT(AUTH_LOCKED, auth_login("alice", "Pass@1234", &s));
}

void test_lockout_does_not_affect_other_users(void)
{
    Session s;
    auth_login("alice", "bad1", &s);
    auth_login("alice", "bad2", &s);
    auth_login("alice", "bad3", &s);
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("bob", "Pass@5678", &s));
}

/* ---------- TC-Auth-04: role-based access ---------- */
void test_student_views_only_own_record(void)
{
    Session s;
    auth_login("alice", "Pass@1234", &s);
    TEST_ASSERT_TRUE(auth_can_view_record(&s, "PES001"));
    TEST_ASSERT_FALSE(auth_can_view_record(&s, "PES002"));
}

void test_admin_views_all_records(void)
{
    Session s;
    auth_login("admin", "Admin@123", &s);
    TEST_ASSERT_TRUE(auth_can_view_record(&s, "PES001"));
    TEST_ASSERT_TRUE(auth_can_view_record(&s, "PES002"));
}

void test_null_session_denied(void)
{
    TEST_ASSERT_FALSE(auth_can_view_record(NULL, "PES001"));
    TEST_ASSERT_FALSE(auth_can_modify(NULL));
}

/* ---------- TC-Sec-03: only admins modify ---------- */
void test_only_admin_can_modify(void)
{
    Session a, st;
    auth_login("admin", "Admin@123", &a);
    auth_login("alice", "Pass@1234", &st);
    TEST_ASSERT_TRUE(auth_can_modify(&a));
    TEST_ASSERT_FALSE(auth_can_modify(&st));
}

void test_logout_clears_session(void)
{
    Session s;
    auth_login("admin", "Admin@123", &s);
    auth_logout(&s);
    TEST_ASSERT_FALSE(auth_can_modify(&s));
    TEST_ASSERT_EQUAL_STRING("", s.username);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_login_valid_credentials);
    RUN_TEST(test_login_wrong_password);
    RUN_TEST(test_login_unknown_user);
    RUN_TEST(test_login_empty_input);
    RUN_TEST(test_login_overlong_username);
    RUN_TEST(test_duplicate_user_rejected);
    RUN_TEST(test_hash_known_vector);
    RUN_TEST(test_hash_length_and_consistency);
    RUN_TEST(test_no_plaintext_in_user_file);
    RUN_TEST(test_lockout_after_three_failures);
    RUN_TEST(test_locked_account_rejects_correct_password);
    RUN_TEST(test_success_resets_failure_counter);
    RUN_TEST(test_lockout_persists_after_reload);
    RUN_TEST(test_lockout_does_not_affect_other_users);
    RUN_TEST(test_student_views_only_own_record);
    RUN_TEST(test_admin_views_all_records);
    RUN_TEST(test_null_session_denied);
    RUN_TEST(test_only_admin_can_modify);
    RUN_TEST(test_logout_clears_session);
    return UNITY_END();
}
