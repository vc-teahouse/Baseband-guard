#ifndef _BBG_TRACING_H_
#define _BBG_TRACING_H_
struct bbg_cred_security_struct {
	unsigned is_untrusted_process:1;	/* execve from su */
};

#ifdef BBG_USE_DEFINE_LSM
extern struct lsm_blob_sizes bbg_blob_sizes;

static __maybe_unused inline struct bbg_cred_security_struct* bbg_cred(const struct cred *cred) {
	return cred->security + bbg_blob_sizes.lbs_cred;
}

#else
struct bbg_cred_security_struct* bbg_cred(const struct cred *cred);
#endif

static __maybe_unused inline int current_process_trusted(void) {
	struct bbg_cred_security_struct *bbg_tsec;
	bbg_tsec = bbg_cred(current_cred());
	return !bbg_tsec->is_untrusted_process;
}

#endif