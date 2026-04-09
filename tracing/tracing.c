#include "kernel_compat.h"
#include <linux/security.h>
#include <linux/errno.h>
#include <linux/cred.h>

int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
void bb_cred_transfer(struct cred *new, const struct cred *old);
int bb_bprm_set_creds(struct linux_binprm *bprm);

int __maybe_unused bbg_process_setpermissive(void);
int __maybe_unused bbg_test_domain_transition(u32 target_secid);

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	struct task_security_struct *new_selinux_tsec;
	const struct task_security_struct *old_selinux_tsec;
#else
	struct cred_security_struct *new_selinux_tsec;
	const struct cred_security_struct *old_selinux_tsec;
#endif
	const struct bbg_cred_security_struct *old_bbg_tsec;
	struct bbg_cred_security_struct *new_bbg_tsec;
	const struct cred *new_cred = bprm->cred;

	old_selinux_tsec = selinux_cred(current_cred());
	new_selinux_tsec = selinux_cred(new_cred);
	new_bbg_tsec = bbg_cred(new_cred);
	old_bbg_tsec = bbg_cred(current_cred());

	new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;

	if (new_bbg_tsec->is_untrusted_process)
		return 0;

	if (unlikely(!selinux_initialized_compat()))
		return 0;

	if (cap_raised(new_cred->cap_effective, CAP_SYS_ADMIN) ||
	    cap_raised(new_cred->cap_effective, CAP_DAC_OVERRIDE) ||
	    cap_raised(new_cred->cap_effective, CAP_DAC_READ_SEARCH)) {
		const char *comm = current->comm;
		
		if (current->pid <= 2)
			return 0;
		
		if (strcmp(comm, "init") == 0 ||
		    strcmp(comm, "kthreadd") == 0 ||
		    strcmp(comm, "ueventd") == 0 ||
		    strcmp(comm, "logd") == 0 ||
		    strcmp(comm, "servicemanager") == 0 ||
		    strncmp(comm, "android.hardware", 16) == 0 ||
		    strncmp(comm, "vendor.", 7) == 0)
			return 0;

		new_bbg_tsec->is_untrusted_process = 1;
		pr_info("baseband_guard: pid %d comm=%s marked untrusted: gained privileged capabilities\n",
			current->pid, current->comm);
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
