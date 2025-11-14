#include <linux/version.h>
#include <linux/cred.h>
#include "objsec.h"
#include "security.h"

#ifdef BBG_USE_DEFINE_LSM
extern struct lsm_blob_sizes bbg_blob_sizes;
#endif
struct bbg_task_struct {
	int is_untrusted_process;		/* execve from su */
};

static inline struct bbg_task_struct* bbg_cred(const struct cred *cred) {
#ifdef BBG_USE_DEFINE_LSM
	return cred->security + bbg_blob_sizes.lbs_cred;
#else
	return ((task_security_struct) cred->security).bbg_cred;
#endif
}

static inline bool selinux_initialized_compat()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    return selinux_initialized();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    return selinux_initialized(&selinux_state);
#else
    return selinux_state.initialized;
#endif
}