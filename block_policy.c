#include <linux/fs.h>
#include <linux/hdreg.h>

#include "block_policy.h"

#ifndef BBG_BLKBSZGET_COMPAT
#define BBG_BLKBSZGET_COMPAT _IOR(0x12, 112, int)
#endif

#ifndef BBG_BLKGETSIZE64_COMPAT
#define BBG_BLKGETSIZE64_COMPAT _IOR(0x12, 114, int)
#endif

static bool bbg_block_ioctl_is_query(unsigned int cmd)
{
	switch (cmd) {
	case BLKROGET:
	case BLKGETSIZE:
	case BLKGETSIZE64:
	case BLKSSZGET:
	case BLKBSZGET:
#ifdef BLKPBSZGET
	case BLKPBSZGET:
#endif
#ifdef BLKIOMIN
	case BLKIOMIN:
#endif
#ifdef BLKIOOPT
	case BLKIOOPT:
#endif
#ifdef BLKALIGNOFF
	case BLKALIGNOFF:
#endif
	case BLKSECTGET:
#ifdef BLKDISCARDZEROES
	case BLKDISCARDZEROES:
#endif
	case BLKRAGET:
	case BLKFRAGET:
#ifdef BLKGETDISKSEQ
	case BLKGETDISKSEQ:
#endif
#ifdef BLKROTATIONAL
	case BLKROTATIONAL:
#endif
	case HDIO_GETGEO:
		return true;
	default:
		return false;
	}
}

static bool bbg_block_ioctl_is_bounded_mutation(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
		return true;
	default:
		return false;
	}
}

bool bbg_block_write_allowed(bool trusted, bool device_allowed)
{
	return trusted || device_allowed;
}

bool bbg_block_ioctl_allowed(bool trusted, bool device_allowed,
			     unsigned int cmd)
{
	if (trusted)
		return true;
	if (bbg_block_ioctl_is_query(cmd))
		return true;
	return device_allowed && bbg_block_ioctl_is_bounded_mutation(cmd);
}

unsigned int bbg_block_ioctl_compat_normalize(unsigned int cmd)
{
	if (cmd == BBG_BLKBSZGET_COMPAT)
		return BLKBSZGET;
	if (cmd == BBG_BLKGETSIZE64_COMPAT)
		return BLKGETSIZE64;
	return cmd;
}

bool bbg_block_uring_allowed(bool trusted)
{
	return trusted;
}
