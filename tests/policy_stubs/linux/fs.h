#ifndef _BBG_TEST_LINUX_FS_H_
#define _BBG_TEST_LINUX_FS_H_

#include <stddef.h>

#define _IOC_NRBITS		8
#define _IOC_TYPEBITS		8
#define _IOC_SIZEBITS		14
#define _IOC_NRSHIFT		0
#define _IOC_TYPESHIFT		(_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT		(_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT		(_IOC_SIZESHIFT + _IOC_SIZEBITS)
#define _IOC_READ		2U
#define _IOC(dir, type, nr, size) \
	(((unsigned int)(dir) << _IOC_DIRSHIFT) | \
	 ((unsigned int)(type) << _IOC_TYPESHIFT) | \
	 ((unsigned int)(nr) << _IOC_NRSHIFT) | \
	 ((unsigned int)(size) << _IOC_SIZESHIFT))
#define _IOR(type, nr, data_type)	_IOC(_IOC_READ, (type), (nr), \
					     sizeof(data_type))

#ifndef BBG_TEST_NATIVE_IOCTL_TYPE
#define BBG_TEST_NATIVE_IOCTL_TYPE	size_t
#endif

#define BLKROSET		0xBB010001u
#define BLKROGET		0xBB010002u
#define BLKGETSIZE		0xBB010003u
#define BLKRAGET		0xBB010004u
#define BLKFRAGET		0xBB010005u
#define BLKSECTGET		0xBB010006u
#define BLKSSZGET		0xBB010007u
#define BLKPG			0xBB010008u
#define BLKBSZGET		_IOR(0x12, 112, BBG_TEST_NATIVE_IOCTL_TYPE)
#define BLKGETSIZE64		_IOR(0x12, 114, BBG_TEST_NATIVE_IOCTL_TYPE)
#define BLKDISCARD		0xBB01000Bu
#define BLKIOMIN		0xBB01000Cu
#define BLKIOOPT		0xBB01000Du
#define BLKALIGNOFF		0xBB01000Eu
#define BLKPBSZGET		0xBB01000Fu
#define BLKDISCARDZEROES	0xBB010010u
#define BLKSECDISCARD		0xBB010011u
#define BLKROTATIONAL		0xBB010012u
#define BLKZEROOUT		0xBB010013u
#define BLKGETDISKSEQ		0xBB010014u

#define SG_IO			0xBB010015u
#define MMC_IOC_CMD		0xBB010016u
#define NVME_IOCTL_IO_CMD	0xBB010017u

#endif
