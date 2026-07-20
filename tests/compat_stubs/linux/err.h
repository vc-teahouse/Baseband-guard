#ifndef _BBG_TEST_LINUX_ERR_H_
#define _BBG_TEST_LINUX_ERR_H_

#include <stdbool.h>

extern bool bbg_test_lookup_missing;

#define IS_ERR(ptr) ((void)(ptr), false)
#define IS_ERR_OR_NULL(ptr) ((void)(ptr), bbg_test_lookup_missing)

#endif
