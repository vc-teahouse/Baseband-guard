#include "kernel_compat.h"
#include "../baseband_guard.h"
#include "../kernel_compat.h"

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
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
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
int bbg_process_setpermissive(void)
{
#ifdef CONFIG_BBG_DISABLE_SELINUX_PERMISSIVE
	return 1;
#else
	return 0;
#endif
}
#endif

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
int current_process_trusted(void) {
	struct bbg_task_struct *bbg_tsec;
	bbg_tsec = bbg_cred(current_cred());
	return !bbg_tsec->is_untrusted_process;
}
#endif

int bbg_test_domain_transition(u32 target_secid)
{
#ifdef CONFIG_BBG_DOMAIN_PROTECTION
#ifndef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
	static int su_sid;
#endif
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	int ok = 0;
	size_t i;

#ifdef CONFIG_BBG_DOMAIN_PROTECTION_TRACE_ALL_SU
	struct bbg_task_struct *bbg_tsec;
	bbg_tsec = bbg_cred(current_cred());
	
	if (!bbg_tsec->is_untrusted_process) return 0;
#else

	if (unlikely(!su_sid))
		security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);

	if (sid != su_sid)
		return 0;
#endif

	if (unlikely(security_secid_to_secctx(target_secid, &ctx,&len))) // 检查切换目标是否为允许操作磁盘的域
		return 0;
	if (!ctx || !len)
		goto out_target_domain_check;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle) {
			if (strnstr(ctx, needle, len)) {
				ok = 1;
				break;
			}
		}
	}
out_target_domain_check:
	if (ok) { // 如果全部符合，打印日志，并且根据是否强制执行来决定是否拦截域转换
		pr_info("baseband_guard: deny domain transition, target domain: %.*s, current PID: %d\n",
			len, ctx, current->pid);
	}
	security_release_secctx(ctx, len);

	if (!BB_ENFORCING)
		return 0;

	return ok;
#else
	return 0;
#endif
}