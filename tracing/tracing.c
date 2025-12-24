#include "kernel_compat.h"
#include <linux/security.h>
#include <linux/errno.h>
#include <linux/cred.h>

#ifdef BBG_USE_DEFINE_LSM
struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct bbg_cred_security_struct),
};
#else
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
	return cred->security;
}
#endif

int bb_cred_prepare(struct cred *new, const struct cred *old,
					gfp_t gfp)
{
	const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
	struct bbg_cred_security_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
	return 0;
}
void bb_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
	struct bbg_cred_security_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
}

int bb_bprm_set_creds(struct linux_binprm *bprm)
{
	static int su_sid = -1;
	static int magisk_sid = -1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	struct task_security_struct *new_selinux_tsec;
	const struct task_security_struct *old_selinux_tsec;
#else
	struct cred_security_struct *new_selinux_tsec;
	const struct cred_security_struct *old_selinux_tsec;
#endif
	const struct bbg_cred_security_struct *old_bbg_tsec;
	struct bbg_cred_security_struct *new_bbg_tsec;

	old_selinux_tsec = selinux_cred(current_cred());
	new_selinux_tsec = selinux_cred(bprm->cred);
	new_bbg_tsec = bbg_cred(bprm->cred);
	old_bbg_tsec = bbg_cred(current_cred());

	new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;
	
	if (new_bbg_tsec->is_untrusted_process) {
		return 0; // already flag as untrusted_process, no need check current domain
	}

	if (unlikely(!selinux_initialized_compat())) return 0; // we keep this only for module scripts, i don't want hook execve

	if (su_sid == -1) { // root impl compatible
		if (security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid)) {
			su_sid = -EINVAL;
		}
	}

	if (magisk_sid == -1) {
		if (security_secctx_to_secid("u:r:magisk:s0", strlen("u:r:magisk:s0"), &magisk_sid) != 0) {
			magisk_sid = -EINVAL;
		}
	}

	if (unlikely(
		old_selinux_tsec->sid == su_sid || old_selinux_tsec->osid == su_sid || // kernelsu
		new_selinux_tsec->sid == su_sid || new_selinux_tsec->osid == su_sid ||

		old_selinux_tsec->sid == magisk_sid || old_selinux_tsec->osid == magisk_sid || // magisk/apatch
		new_selinux_tsec->sid == magisk_sid || new_selinux_tsec->osid == magisk_sid
	)) {
		new_bbg_tsec->is_untrusted_process = 1;
		pr_info("baseband_guard: pid %d has been marked as untrusted process due to its selinux domain\n",
			current->pid);
	}

	return 0;
}

int __maybe_unused bbg_process_setpermissive(void)
{
	return 0;
}

int __maybe_unused bbg_test_domain_transition(u32 target_secid)
{
	return 0;
}

#ifndef BBG_USE_DEFINE_LSM
struct bbg_cred_security_struct* bbg_cred(const struct cred *cred) {
	return &((struct task_security_struct *)cred->security)->bbg_cred;
}
#endif