#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "auth.h"

void setUp(void) {}
void tearDown(void) {}

#ifndef _WIN32
/* Feed auth_read_password from a file instead of the keyboard (Linux only). */
static void feed_stdin(const char *text)
{
    FILE *f = fopen("input_feed.tmp", "w");
    fputs(text, f);
    fclose(f);
    freopen("input_feed.tmp", "r", stdin);
}

void test_read_password_reads_line(void)
{
    char buf[16];
    feed_stdin("secret\n");
    auth_read_password(buf, (int)sizeof buf);
    TEST_ASSERT_EQUAL_STRING("secret", buf);
}

void test_read_password_truncates_to_buffer(void)
{
    char buf[5];
    feed_stdin("abcdefgh\n");
    auth_read_password(buf, (int)sizeof buf);
    TEST_ASSERT_EQUAL_STRING("abcd", buf);
}

void test_read_password_empty_line(void)
{
    char buf[8];
    feed_stdin("\n");
    auth_read_password(buf, (int)sizeof buf);
    TEST_ASSERT_EQUAL_STRING("", buf);
}
#endif

void test_read_password_null_buffer_is_safe(void)
{
    auth_read_password(NULL, 10);   /* must not crash */
    TEST_PASS();
}

int main(void)
{
    UNITY_BEGIN();
#ifndef _WIN32
    RUN_TEST(test_read_password_reads_line);
    RUN_TEST(test_read_password_truncates_to_buffer);
    RUN_TEST(test_read_password_empty_line);
#endif
    RUN_TEST(test_read_password_null_buffer_is_safe);
    return UNITY_END();
}
