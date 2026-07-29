#ifndef _BBG_BLOCK_POLICY_H_
#define _BBG_BLOCK_POLICY_H_

#ifdef BBG_HOST_TEST
#include <stdbool.h>
#else
#include <linux/types.h>
#endif

bool bbg_block_write_allowed(bool trusted, bool device_allowed);
bool bbg_block_ioctl_allowed(bool trusted, bool device_allowed,
			     unsigned int cmd);
unsigned int bbg_block_ioctl_compat_normalize(unsigned int cmd);
bool bbg_block_uring_allowed(bool trusted);

#endif
