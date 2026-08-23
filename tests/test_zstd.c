/*
 * test_zstd.c — Tests for zstd compression wrappers.
 */
#include "test_framework.h"
#include "zstd_store.h"

#include <limits.h>

TEST(zstd_roundtrip) {
    const char *data = "Hello, zstd compression roundtrip test!";
    size_t len = strlen(data);

    size_t bound = cbm_zstd_compress_bound(len);
    ASSERT_GT(bound, 0);

    char *cbuf = malloc(bound);
    ASSERT_NOT_NULL(cbuf);

    size_t clen = cbm_zstd_compress(data, len, cbuf, bound, 3);
    ASSERT_GT(clen, 0);

    char *dbuf = malloc(len);
    ASSERT_NOT_NULL(dbuf);

    int dlen = cbm_zstd_decompress(cbuf, clen, dbuf, len);
    ASSERT_EQ(dlen, len);
    ASSERT_MEM_EQ(dbuf, data, len);

    free(cbuf);
    free(dbuf);
    PASS();
}

TEST(zstd_roundtrip_large) {
    size_t len = 100000;
    char *data = malloc(len);
    ASSERT_NOT_NULL(data);

    /* Repetitive data — should compress well */
    for (size_t i = 0; i < len; i++) {
        data[i] = "function_name_pattern_abcdef"[i % 28];
    }

    size_t bound = cbm_zstd_compress_bound(len);
    char *cbuf = malloc(bound);
    ASSERT_NOT_NULL(cbuf);

    size_t clen = cbm_zstd_compress(data, len, cbuf, bound, 9);
    ASSERT_GT(clen, 0);
    /* Repetitive data should compress at least 2:1 */
    ASSERT_LT(clen, len / 2);

    char *dbuf = malloc(len);
    ASSERT_NOT_NULL(dbuf);

    int dlen = cbm_zstd_decompress(cbuf, clen, dbuf, len);
    ASSERT_EQ(dlen, len);
    ASSERT_MEM_EQ(dbuf, data, len);

    free(data);
    free(cbuf);
    free(dbuf);
    PASS();
}

TEST(zstd_compress_levels) {
    const char *data = "test data for different compression levels";
    size_t len = strlen(data);
    size_t bound = cbm_zstd_compress_bound(len);
    char *cbuf = malloc(bound);
    ASSERT_NOT_NULL(cbuf);

    /* Both level 3 (fast) and level 9 (best) should produce valid output */
    size_t clen3 = cbm_zstd_compress(data, len, cbuf, bound, 3);
    ASSERT_GT(clen3, 0);

    size_t clen9 = cbm_zstd_compress(data, len, cbuf, bound, 9);
    ASSERT_GT(clen9, 0);

    free(cbuf);
    PASS();
}

TEST(zstd_decompress_too_small_output) {
    const char *data = "this is test data that will be compressed";
    size_t len = strlen(data);
    size_t bound = cbm_zstd_compress_bound(len);
    char *cbuf = malloc(bound);
    ASSERT_NOT_NULL(cbuf);

    size_t clen = cbm_zstd_compress(data, len, cbuf, bound, 3);
    ASSERT_GT(clen, 0);

    /* Try decompressing with too-small output buffer — should return 0 (error) */
    char small[4];
    int dlen = cbm_zstd_decompress(cbuf, clen, small, 4);
    ASSERT_EQ(dlen, 0);

    free(cbuf);
    PASS();
}

TEST(zstd_bound_positive) {
    ASSERT_GT(cbm_zstd_compress_bound(1), 0);
    ASSERT_GT(cbm_zstd_compress_bound(100), 0);
    ASSERT_GT(cbm_zstd_compress_bound(1000000), 0);
    PASS();
}

TEST(zstd_bound_above_int_max) {
    if (sizeof(size_t) > sizeof(int)) {
        size_t input_size = (size_t)INT_MAX + 1U;
        ASSERT_GT(cbm_zstd_compress_bound(input_size), input_size);
    }
    PASS();
}

SUITE(zstd) {
    RUN_TEST(zstd_roundtrip);
    RUN_TEST(zstd_roundtrip_large);
    RUN_TEST(zstd_compress_levels);
    RUN_TEST(zstd_decompress_too_small_output);
    RUN_TEST(zstd_bound_positive);
    RUN_TEST(zstd_bound_above_int_max);
}
