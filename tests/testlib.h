#pragma once

#include <stdio.h>

static int _t_run = 0, _t_fail = 0;

#define CHECK(expr)                                                   \
    do                                                                \
    {                                                                 \
        _t_run++;                                                     \
        if (expr)                                                     \
        {                                                             \
            printf("ok    " #expr "\n");                              \
        }                                                             \
        else                                                          \
        {                                                             \
            printf("FAIL  " #expr "  (%s:%d)\n", __FILE__, __LINE__); \
            _t_fail++;                                                \
        }                                                             \
    } while (0)

#define TEST_SUMMARY() \
    (printf("\n%d/%d passed\n", _t_run - _t_fail, _t_run), _t_fail ? 1 : 0)
