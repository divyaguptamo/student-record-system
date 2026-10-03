#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "auth.h"

#define BT_USERS "bt_users.dat"
#define BT_LOG   "bt_audit.log"

void setUp(void)
{
    remove(BT_USERS);
    remove(BT_LOG);
    auth_init(BT_USERS, BT_LOG);
}

void tearDown(void)
{
    remove(BT_USERS);
    remove(BT_LOG);
}

/* Fill buf with n copies of ch and terminate it. buf must hold n + 1 bytes. */
static void fill(char *buf, char ch, int n)
{
    memset(buf, ch, (size_t)n);
    buf[n] = '\0';
}

/* ---- username length: 31 allowed, 32 rejected ---- */
void test_username_31_chars_accepted(void)
{
    char name[40];
    Session s;
    fill(name, 'a', 31);
    TEST_ASSERT_EQUAL_INT(0, auth_add_user(name, "Pass@1234", ROLE_STUDENT, "PES001"));
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login(name, "Pass@1234", &s));
}

void test_username_32_chars_rejected(void)
{
    char name[40];
    fill(name, 'a', 32);
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user(name, "Pass@1234", ROLE_STUDENT, "PES001"));
}

/* ---- password length: 64 allowed, 65 rejected ---- */
void test_password_64_chars_accepted(void)
{
    char pw[70];
    Session s;
    fill(pw, 'p', 64);
    TEST_ASSERT_EQUAL_INT(0, auth_add_user("alice", pw, ROLE_STUDENT, "PES001"));
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("alice", pw, &s));
}

void test_password_65_chars_rejected(void)
{
    char pw[70];
    Session s;
    fill(pw, 'p', 65);
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("alice", pw, ROLE_STUDENT, "PES001"));
    TEST_ASSERT_EQUAL_INT(AUTH_INVALID_INPUT, auth_login("alice", pw, &s));
}

/* ---- roll number length: 15 allowed, 16 rejected ---- */
void test_roll_no_15_chars_accepted(void)
{
    char roll[24];
    fill(roll, 'R', 15);
    TEST_ASSERT_EQUAL_INT(0, auth_add_user("alice", "Pass@1234", ROLE_STUDENT, roll));
}

void test_roll_no_16_chars_rejected(void)
{
    char roll[24];
    fill(roll, 'R', 16);
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("alice", "Pass@1234", ROLE_STUDENT, roll));
}

/* ---- characters that would corrupt the comma-separated user file ---- */
void test_comma_in_username_rejected(void)
{
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("al,ice", "Pass@1234", ROLE_STUDENT, "PES001"));
}

void test_comma_in_roll_no_rejected(void)
{
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES,001"));
}

void test_newline_in_username_rejected(void)
{
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("al\nice", "Pass@1234", ROLE_STUDENT, "PES001"));
}

/* ---- user table limit: 100 allowed, 101st rejected ---- */
void test_user_limit_100(void)
{
    int i;
    char name[16];
    Session s;
    for (i = 0; i < 100; i++) {
        snprintf(name, sizeof name, "user%d", i);
        TEST_ASSERT_EQUAL_INT(0, auth_add_user(name, "Pass@1234", ROLE_STUDENT, "PES001"));
    }
    TEST_ASSERT_EQUAL_INT(-1, auth_add_user("user100", "Pass@1234", ROLE_STUDENT, "PES001"));
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("user99", "Pass@1234", &s));
}

/* ---- NULL handling ---- */
void test_login_with_null_session_pointer(void)
{
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("alice", "Pass@1234", NULL));
}

void test_init_with_null_paths_fails(void)
{
    TEST_ASSERT_EQUAL_INT(-1, auth_init(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, auth_init(NULL, BT_LOG));
    TEST_ASSERT_EQUAL_INT(-1, auth_init(BT_USERS, NULL));
}

void test_view_record_with_null_roll_no_denied(void)
{
    Session s;
    auth_add_user("admin", "Admin@123", ROLE_ADMIN, NULL);
    auth_login("admin", "Admin@123", &s);
    TEST_ASSERT_FALSE(auth_can_view_record(&s, NULL));
}

/* ---- hashing and matching edge cases ---- */
void test_hash_of_empty_string_known_vector(void)
{
    char h[65];
    auth_hash_password("", h);
    TEST_ASSERT_EQUAL_STRING(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", h);
}

void test_username_and_password_are_case_sensitive(void)
{
    Session s;
    auth_add_user("alice", "Pass@1234", ROLE_STUDENT, "PES001");
    TEST_ASSERT_EQUAL_INT(AUTH_NO_SUCH_USER, auth_login("Alice", "Pass@1234", &s));
    TEST_ASSERT_EQUAL_INT(AUTH_BAD_CREDENTIALS, auth_login("alice", "pass@1234", &s));
}

/* An unknown role number in the file must never grant admin rights */
void test_unknown_role_in_file_becomes_student(void)
{
    Session s;
    char hash[65];
    FILE *f;
    auth_hash_password("Pass@1234", hash);
    f = fopen(BT_USERS, "w");
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f, "dave,%s,7,PES004,0,0\n", hash);
    fclose(f);
    auth_init(BT_USERS, BT_LOG);
    TEST_ASSERT_EQUAL_INT(AUTH_OK, auth_login("dave", "Pass@1234", &s));
    TEST_ASSERT_EQUAL_INT(ROLE_STUDENT, s.role);
    TEST_ASSERT_FALSE(auth_can_modify(&s));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_username_31_chars_accepted);
    RUN_TEST(test_username_32_chars_rejected);
    RUN_TEST(test_password_64_chars_accepted);
    RUN_TEST(test_password_65_chars_rejected);
    RUN_TEST(test_roll_no_15_chars_accepted);
    RUN_TEST(test_roll_no_16_chars_rejected);
    RUN_TEST(test_comma_in_username_rejected);
    RUN_TEST(test_comma_in_roll_no_rejected);
    RUN_TEST(test_newline_in_username_rejected);
    RUN_TEST(test_user_limit_100);
    RUN_TEST(test_login_with_null_session_pointer);
    RUN_TEST(test_init_with_null_paths_fails);
    RUN_TEST(test_view_record_with_null_roll_no_denied);
    RUN_TEST(test_hash_of_empty_string_known_vector);
    RUN_TEST(test_username_and_password_are_case_sensitive);
    RUN_TEST(test_unknown_role_in_file_becomes_student);
    return UNITY_END();
}
