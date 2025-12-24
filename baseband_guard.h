#define BB_ENFORCING 1

#ifdef CONFIG_BBG_DEBUG
#define BB_DEBUG 1
#else
#define BB_DEBUG 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

static const char * const allowlist_names[] = {
#ifndef CONFIG_BBG_BLOCK_BOOT
	"boot", "init_boot",
#endif
	"dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
	"vbmeta", "vbmeta_system", "vbmeta_vendor",
#ifndef CONFIG_BBG_BLOCK_RECOVERY
	"recovery"
#endif
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);
