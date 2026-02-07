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
#ifdef BB_HAS_SELINUX_STATE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    return selinux_initialized();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    return selinux_initialized(&selinux_state);
#else // LINUX_VERSION_CODE
    return selinux_state.initialized;
#endif // LINUX_VERSION_CODE
#else // BB_HAS_SELINUX_STATE
    return ss_initialized;
#endif // BB_HAS_SELINUX_STATE
}
