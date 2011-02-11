#include "cunit/cunit.h"
#include "util.h"

static void test_bin_to_hex(void)
{
    static const unsigned char BIN[4] = { 0xca, 0xfe, 0xba, 0xbe };
    static const char HEX[9] = "cafebabe";
    int r;
    char hex[9];

    memset(hex, 0x45, sizeof(hex));
    r = bin_to_hex(BIN, sizeof(BIN), hex, BH_LOWER);
    CU_ASSERT_EQUAL(r, sizeof(hex)-1);
    CU_ASSERT_STRING_EQUAL(hex, HEX);
}

static void test_bin_to_hex_long(void)
{
    static const unsigned char BIN[20] = {
	0x33,0xac,0x18,0xb6,0xdc,0x74,0x6e,0x9a,0xd7,0xbd,
	0x6f,0x9f,0xfa,0x77,0xe4,0x04,0x84,0x04,0xa0,0x02
    };
    static const char HEX[41] = "33ac18b6dc746e9ad7bd6f9ffa77e4048404a002";
    int r;
    char hex[41];

    memset(hex, 0x45, sizeof(hex));
    r = bin_to_hex(BIN, sizeof(BIN), hex, BH_LOWER);
    CU_ASSERT_EQUAL(r, sizeof(hex)-1);
    CU_ASSERT_STRING_EQUAL(hex, HEX);
}

static void test_bin_to_hex_short(void)
{
    static const unsigned char BIN[1] = { 0x42 };
    static const char HEX[3] = "42";
    int r;
    char hex[3];

    memset(hex, 0x45, sizeof(hex));
    r = bin_to_hex(BIN, sizeof(BIN), hex, BH_LOWER);
    CU_ASSERT_EQUAL(r, sizeof(hex)-1);
    CU_ASSERT_STRING_EQUAL(hex, HEX);
}

static void test_bin_to_hex_sep(void)
{
    static const unsigned char BIN[4] = { 0xca, 0xfe, 0xba, 0xbe };
    static const char HEX[12] = "ca:fe:ba:be";
    int r;
    char hex[12];

    memset(hex, 0x45, sizeof(hex));
    r = bin_to_hex(BIN, sizeof(BIN), hex, BH_LOWER|BH_SEPARATOR(':'));
    CU_ASSERT_EQUAL(r, sizeof(hex)-1);
    CU_ASSERT_STRING_EQUAL(hex, HEX);
}

static void test_hex_to_bin(void)
{
    static const char HEX[9] = "cafebabe";
    static const unsigned char BIN[4] = { 0xca, 0xfe, 0xba, 0xbe };
    int r;
    char bin[4];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, sizeof(bin));
    CU_ASSERT_EQUAL(memcmp(bin, BIN, sizeof(bin)), 0);
}

static void test_hex_to_bin_short(void)
{
    static const char HEX[3] = "42";
    static const unsigned char BIN[1] = { 0x42 };
    int r;
    char bin[1];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, sizeof(bin));
    CU_ASSERT_EQUAL(memcmp(bin, BIN, sizeof(bin)), 0);
}

static void test_hex_to_bin_long(void)
{
    static const char HEX[41] = "33ac18b6dc746e9ad7bd6f9ffa77e4048404a002";
    static const unsigned char BIN[20] = {
	0x33,0xac,0x18,0xb6,0xdc,0x74,0x6e,0x9a,0xd7,0xbd,
	0x6f,0x9f,0xfa,0x77,0xe4,0x04,0x84,0x04,0xa0,0x02
    };
    int r;
    char bin[20];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, sizeof(bin));
    CU_ASSERT_EQUAL(memcmp(bin, BIN, sizeof(bin)), 0);
}

static void test_hex_to_bin_capitals(void)
{
    static const char HEX[9] = "CAFEBABE";
    static const unsigned char BIN[4] = { 0xca, 0xfe, 0xba, 0xbe };
    int r;
    char bin[4];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, sizeof(bin));
    CU_ASSERT_EQUAL(memcmp(bin, BIN, sizeof(bin)), 0);
}

static void test_hex_to_bin_odd(void)
{
    static const char HEX[8] = "cafebab";
    int r;
    unsigned char bin[4];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(bin[0], 0xff);
    CU_ASSERT_EQUAL(bin[1], 0xff);
    CU_ASSERT_EQUAL(bin[2], 0xff);
    CU_ASSERT_EQUAL(bin[3], 0xff);
}

static void test_hex_to_bin_nonxdigit(void)
{
    static const char HEX[9] = "foobarly";
    int r;
    char bin[4];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, -1);
}

static void test_hex_to_bin_whitespace(void)
{
    static const char HEX[13] = "  cafebabe  ";
    int r;
    char bin[4];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, sizeof(HEX)-1, bin);
    CU_ASSERT_EQUAL(r, -1);
}

static void test_hex_to_bin_nolength(void)
{
    static const char HEX[9] = "cafebabe";
    static const unsigned char BIN[4] = { 0xca, 0xfe, 0xba, 0xbe };
    int r;
    char bin[4];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(HEX, 0, bin);
    CU_ASSERT_EQUAL(r, sizeof(bin));
    CU_ASSERT_EQUAL(memcmp(bin, BIN, sizeof(bin)), 0);
}

static void test_hex_to_bin_null(void)
{
    int r;
    unsigned char bin[1];

    memset(bin, 0xff, sizeof(bin));
    r = hex_to_bin(NULL, 0, bin);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(bin[0], 0xff);
}

