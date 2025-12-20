#include <linux/version.h>
#include <linux/cred.h>
#include "objsec.h"
#include "security.h"
#include "tracing.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
#include "avc_ss.h"
#endif

static __maybe_unused inline bool selinux_initialized_compat(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    return selinux_initialized();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    return selinux_initialized(&selinux_state);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    return selinux_state.initialized;
#else
    return ss_initialized;
#endif
}