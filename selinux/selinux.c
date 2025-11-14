#include "kernel_compat.h"
#include "../baseband_guard.h"
#include "../kernel_compat.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct bbg_task_struct),
};
#endif

int bb_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	const struct bbg_task_struct *old_tsec = bbg_cred(old);
	struct bbg_task_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
	return 0;
}

void bb_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct bbg_task_struct *old_tsec = bbg_cred(old);
	struct bbg_task_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
}

int bb_bprm_set_creds(struct linux_binprm *bprm)
{
	static int su_sid;
	struct task_security_struct *new_selinux_tsec;
	const struct task_security_struct *old_selinux_tsec;
	const struct bbg_task_struct *old_bbg_tsec;
	struct bbg_task_struct *new_bbg_tsec;

	old_selinux_tsec = selinux_cred(current_cred());
	new_selinux_tsec = selinux_cred(bprm->cred);
	new_bbg_tsec = bbg_cred(bprm->cred);
	old_bbg_tsec = bbg_cred(current_cred());

	new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;

	if (unlikely(!selinux_initialized_compat())) return 0;

	if (unlikely(!su_sid))
		security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);

	if (unlikely(
		old_selinux_tsec->sid == su_sid || old_selinux_tsec->osid == su_sid ||
		new_selinux_tsec->sid == su_sid || new_selinux_tsec->osid == su_sid
	)) new_bbg_tsec->is_untrusted_process = 1;

	return 0;
}

int __maybe_unused bbg_process_setpermissive(void)
{
	return 0;
}

int current_process_trusted(void) {
	struct bbg_task_struct *bbg_tsec;
	bbg_tsec = bbg_cred(current_cred());
	return !bbg_tsec->is_untrusted_process;
}

int __maybe_unused bbg_test_domain_transition(u32 target_secid)
{
	return 0;
}