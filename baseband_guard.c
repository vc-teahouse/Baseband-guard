/*
 * Baseband Guard - Protect critical partitions from destructive operations
 * Original Author: 秋刀鱼 (qdykernel / https://t.me/qdykernel)
 * Refactored & Extended: (Your Name / Organization)
 * License: GPL v2
 *
 * Features:
 * - Blocks raw writes and destructive block ioctls (discard, zeroout, etc.)
 *   to a set of protected partitions unless the caller is in an allowed
 *   SELinux domain.
 * - Dynamic runtime toggle (enforcing / audit-only).
 * - Detection & optional disable in recovery mode.
 * - Optional whole-disk protection.
 *
 * Sysfs interface:
 *   /sys/kernel/baseband_guard/enforcing      (rw)
 *   /sys/kernel/baseband_guard/stats_denied   (ro)
 *   /sys/kernel/baseband_guard/protected      (ro list of protected devs)
 *   /sys/kernel/baseband_guard/add            (wo add by name or MAJOR:MINOR)
 *   /sys/kernel/baseband_guard/remove         (wo remove by name or MAJOR:MINOR)
 *
 * SELinux allowed domains are matched by exact primary type (before first ':')
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

#ifdef CONFIG_SECURITY_SELINUX
#include <linux/selinux.h>
#endif

#define BB_SYSFS_DIR      "baseband_guard"
#define BB_BYNAME_DIR     "/dev/block/by-name"

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_log_info(fmt, ...)   pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_log_dbg(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_log_warn(fmt, ...)   pr_warn("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_log_err(fmt, ...)    pr_err("baseband_guard: " fmt, ##__VA_ARGS__)

/* Runtime parameters & stats */
static bool enforcing = true;
module_param(enforcing, bool, 0644);
MODULE_PARM_DESC(enforcing, "Set to 0 for audit-only (no blocking).");
static atomic64_t stats_denied = ATOMIC64_INIT(0);

extern char *saved_command_line;

/* Recovery mode detection (androidboot.mode=recovery) */
static bool boot_in_recovery(void)
{
#ifdef CONFIG_SECURITY_BASEBAND_GUARD_ALLOW_IN_RECOVERY
    const char *p = saved_command_line;
    if (!p)
        return false;
    return (strstr(p, "androidboot.mode=recovery") != NULL) ||
           (strstr(p, "androidboot.slot_suffix=_recovery") != NULL);
#else
    return false;
#endif
}

static bool disabled_due_to_recovery = false;

/* Static baseline protected partitions (names without slot suffix) */
static const char * const protected_partition_basenames[] = {
    "boot", "init_boot", "dtbo", "vendor_boot",
    "userdata", "cache", "metadata", "misc",
};
static const size_t protected_partition_basenames_cnt = ARRAY_SIZE(protected_partition_basenames);

/* Protected partition storage (hash of dev_t + name) */
#define BB_NAME_MAX 64
struct part_node {
    dev_t dev;
    char name[BB_NAME_MAX];
    struct hlist_node h;
};

DEFINE_HASHTABLE(protected_partitions, 7);
static DEFINE_SPINLOCK(protected_partitions_lock);

static const char *slot_suffix_from_cmdline(void)
{
    const char *p = saved_command_line;
    if (!p)
        return NULL;
    p = strstr(p, "androidboot.slot_suffix=");
    if (!p)
        return NULL;
    p += strlen("androidboot.slot_suffix=");
    if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b'))
        return (p[1] == 'a') ? "_a" : "_b";
    return NULL;
}

/* Resolve /dev/block/by-name/<name> to dev_t */
static bool resolve_byname_dev(const char *name, dev_t *out)
{
    char *path;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
    struct block_device *bdev;
#else
    dev_t dev;
    int ret;
#endif
    if (!name || !out)
        return false;

    path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
    if (!path)
        return false;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
    bdev = lookup_bdev(path);
    kfree(path);
    if (IS_ERR(bdev))
        return false;
    *out = bdev->bd_dev;
    bdput(bdev);
    return true;
#else
    ret = lookup_bdev(path, &dev);
    kfree(path);
    if (ret)
        return false;
    *out = dev;
    return true;
#endif
}

static void protect_add_named(dev_t dev, const char *name)
{
    struct part_node *n, *cur;
    u64 key = (u64)dev;

    if (!dev)
        return;

    /* Fast existence check under lock */
    spin_lock(&protected_partitions_lock);
    hash_for_each_possible(protected_partitions, cur, h, key) {
        if (cur->dev == dev) {
            spin_unlock(&protected_partitions_lock);
            return;
        }
    }
    spin_unlock(&protected_partitions_lock);

    n = kmalloc(sizeof(*n), GFP_KERNEL);
    if (!n)
        return;

    n->dev = dev;
    if (name && *name)
        strscpy(n->name, name, BB_NAME_MAX);
    else
        strscpy(n->name, "(unknown)", BB_NAME_MAX);

    spin_lock(&protected_partitions_lock);
    /* Re-check in case of race */
    hash_for_each_possible(protected_partitions, cur, h, key) {
        if (cur->dev == dev) {
            spin_unlock(&protected_partitions_lock);
            kfree(n);
            return;
        }
    }
    hash_add(protected_partitions, &n->h, key);
    spin_unlock(&protected_partitions_lock);

#if BB_VERBOSE
    bb_log_dbg("protected partition cached dev=%u:%u name=%s\n",
               MAJOR(dev), MINOR(dev), n->name);
#endif
}

/* Backwards helper */
static inline void protect_add(dev_t dev)
{
    protect_add_named(dev, NULL);
}

static bool protect_has(dev_t dev)
{
    struct part_node *p;
    u64 key = (u64)dev;
    bool found = false;

    spin_lock(&protected_partitions_lock);
    hash_for_each_possible(protected_partitions, p, h, key) {
        if (p->dev == dev) {
            found = true;
            break;
        }
    }
    spin_unlock(&protected_partitions_lock);
    return found;
}

static void resolve_all_protected_partitions(void)
{
    size_t i;
    const char *slot = slot_suffix_from_cmdline();

    for (i = 0; i < protected_partition_basenames_cnt; i++) {
        const char *base = protected_partition_basenames[i];
        dev_t dev;

        /* Direct */
        if (resolve_byname_dev(base, &dev))
            protect_add_named(dev, base);

        /* Slot suffix */
        if (slot) {
            char *nm = kasprintf(GFP_KERNEL, "%s%s", base, slot);
            if (nm) {
                if (resolve_byname_dev(nm, &dev))
                    protect_add_named(dev, nm);
                kfree(nm);
            }
        }

        /* _a / _b variants */
        char *na = kasprintf(GFP_KERNEL, "%s_a", base);
        char *nb = kasprintf(GFP_KERNEL, "%s_b", base);
        if (na) {
            if (resolve_byname_dev(na, &dev))
                protect_add_named(dev, na);
            kfree(na);
        }
        if (nb) {
            if (resolve_byname_dev(nb, &dev))
                protect_add_named(dev, nb);
            kfree(nb);
        }
    }
}

/* Allowed SELinux primary types (no :role or : levels) */
static const char * const allowed_selinux_types[] = {
    "update_engine", "fastbootd", "recovery", "rmt_storage",
    "oplus", "oppo", "feature", "swap",
    "system_perf_init", "hal_bootctl_default", "fsck",
    "vendor_qti", "mi_ric",
};
static const size_t allowed_selinux_types_cnt = ARRAY_SIZE(allowed_selinux_types);

static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
    u32 sid = 0;
    char *ctx = NULL;
    u32 len = 0;
    bool allowed = false;
    size_t i, type_len;
    char *colon;

    security_cred_getsecid(current_cred(), &sid);
    if (!sid)
        return false;
    if (security_secid_to_secctx(sid, &ctx, &len))
        return false;
    if (!ctx || !len)
        goto out;

    colon = strchr(ctx, ':');
    type_len = colon ? (size_t)(colon - ctx) : len;

    for (i = 0; i < allowed_selinux_types_cnt; i++) {
        const char *t = allowed_selinux_types[i];
        size_t tlen = strlen(t);
        if (tlen == type_len && !strncmp(ctx, t, tlen)) {
            allowed = true;
            break;
        }
    }
out:
    security_release_secctx(ctx, len);
    return allowed;
#else
    return false;
#endif
}

/* Logging utilities */
static int get_task_cmdline(char *buf, int buflen)
{
    int n, i;
    if (!buf || buflen <= 0)
        return 0;
    n = get_cmdline(current, buf, buflen);
    if (n <= 0)
        return 0;
    for (i = 0; i < n - 1; i++)
        if (buf[i] == '\0')
            buf[i] = ' ';
    if (n < buflen)
        buf[n] = '\0';
    else
        buf[buflen - 1] = '\0';
    return n;
}

static void log_denial(const char *reason, struct file *file, unsigned int cmd_opt)
{
    const int PATH_BUFLEN = 256;
    const int CMD_BUFLEN = 256;
    char *pathbuf = NULL;
    char *cmdbuf = NULL;
    const char *path = NULL;
    struct inode *inode = NULL;
    dev_t dev = 0;

    if (file) {
        inode = file_inode(file);
        if (inode && S_ISBLK(inode->i_mode))
            dev = inode->i_rdev;
    }

#if BB_VERBOSE
    pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
    if (pathbuf && file)
        path = d_path(&file->f_path, pathbuf, PATH_BUFLEN);
    cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);
    if (cmdbuf)
        get_task_cmdline(cmdbuf, CMD_BUFLEN);

    if (IS_ERR(path))
        path = NULL;

    if (cmd_opt) {
        bb_log_info("DENY: %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
                    reason, cmd_opt, MAJOR(dev), MINOR(dev),
                    path ? path : "?", current->pid, current->comm,
                    cmdbuf ? cmdbuf : "?");
    } else {
        bb_log_info("DENY: %s dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
                    reason, MAJOR(dev), MINOR(dev),
                    path ? path : "?", current->pid, current->comm,
                    cmdbuf ? cmdbuf : "?");
    }
#else
    if (cmd_opt) {
        bb_log_info("DENY: %s cmd=0x%x dev=%u:%u pid=%d\n",
                    reason, cmd_opt, MAJOR(dev), MINOR(dev), current->pid);
    } else {
        bb_log_info("DENY: %s dev=%u:%u pid=%d\n",
                    reason, MAJOR(dev), MINOR(dev), current->pid);
    }
#endif

    kfree(cmdbuf);
    kfree(pathbuf);
}

static int deny_op(const char *reason, struct file *file, unsigned int cmd_opt)
{
    if (!enforcing || disabled_due_to_recovery)
        return 0; /* audit only */

    atomic64_inc(&stats_denied);
    log_denial(reason, file, cmd_opt);
    return -EPERM;
}

/* Whole-disk detection (if configured) */
static bool is_whole_disk(struct inode *inode)
{
#ifdef CONFIG_SECURITY_BASEBAND_GUARD_BLOCK_WHOLEDISK
    struct block_device *bdev;
    if (!inode || !S_ISBLK(inode->i_mode))
        return false;
    bdev = I_BDEV(inode);
    if (!bdev)
        return false;
    return bdev->bd_partno == 0;
#else
    return false;
#endif
}

/* IOCTL classification */
static bool is_destructive_ioctl(unsigned int cmd)
{
    switch (cmd) {
    case BLKDISCARD:
    case BLKSECDISCARD:
    case BLKZEROOUT:
#ifdef BLKPG
    case BLKPG:
#endif
#ifdef BLKTRIM
    case BLKTRIM:
#endif
#ifdef BLKRRPART
    case BLKRRPART:
#endif
#ifdef BLKSETRO
    case BLKSETRO:
#endif
#ifdef BLKSETBADSECTORS
    case BLKSETBADSECTORS:
#endif
        return true;
    default:
        return false;
    }
}

/* Core access decision */
static bool is_protected_dev(struct inode *inode)
{
    if (!inode || !S_ISBLK(inode->i_mode))
        return false;
    if (protect_has(inode->i_rdev))
        return true;
    if (is_whole_disk(inode))
        return true;
    return false;
}

static int bb_file_permission(struct file *file, int mask)
{
    struct inode *inode;

    if (!(mask & MAY_WRITE))
        return 0;
    if (!file)
        return 0;

    inode = file_inode(file);
    if (!S_ISBLK(inode->i_mode))
        return 0;

    if (!is_protected_dev(inode))
        return 0;

    if (current_domain_allowed())
        return 0;

    return deny_op("write to protected block device", file, 0);
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct inode *inode;

    if (!file)
        return 0;
    inode = file_inode(file);
    if (!S_ISBLK(inode->i_mode))
        return 0;

    if (!is_destructive_ioctl(cmd))
        return 0;

    if (!is_protected_dev(inode))
        return 0;

    if (current_domain_allowed())
        return 0;

    return deny_op("destructive ioctl on protected block device", file, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
    return bb_file_ioctl(file, cmd, arg);
}
#endif

/* Sysfs: dynamic management of protected partition list */
static struct kobject *bb_kobj;

static bool parse_major_minor(const char *s, dev_t *out)
{
    unsigned int maj, min;
    char c;
    if (!s || !out)
        return false;
    if (sscanf(s, "%u:%u%c", &maj, &min, &c) == 2) {
        *out = MKDEV(maj, min);
        return true;
    }
    return false;
}

/* Show enforcing */
static ssize_t enforcing_show(struct kobject *kobj,
                             struct kobj_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "%d\n", enforcing ? 1 : 0);
}

/* Set enforcing (0 or non-zero) */
static ssize_t enforcing_store(struct kobject *kobj,
                              struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    if (buf[0] == '0')
        enforcing = false;
    else
        enforcing = true;
    return count;
}

/* Show denial stats */
static ssize_t stats_denied_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "%lld\n",
                    (long long)atomic64_read(&stats_denied));
}

/* Show protected list: name + dev */
static ssize_t protected_show(struct kobject *kobj,
                             struct kobj_attribute *attr, char *buf)
{
    ssize_t off = 0;
    int bkt;
    struct part_node *n;

    spin_lock(&protected_partitions_lock);
    hash_for_each(protected_partitions, bkt, n, h) {
        off += scnprintf(buf + off, PAGE_SIZE - off,
                        "name=%s dev=%u:%u\n",
                        n->name, MAJOR(n->dev), MINOR(n->dev));
        if (off >= PAGE_SIZE - 64)
            break;
    }
    spin_unlock(&protected_partitions_lock);
    return off;
}

/* Add by partition name or major:minor */
static ssize_t add_store(struct kobject *kobj,
                         struct kobj_attribute *attr,
                         const char *buf, size_t count)
{
    char name[BB_NAME_MAX];
    dev_t dev = 0;
    size_t len;

    len = strlcpy(name, buf, sizeof(name));
    if (len && name[len - 1] == '\n')
        name[len - 1] = '\0';

    if (!*name)
        return count;

    if (parse_major_minor(name, &dev)) {
        protect_add_named(dev, name);
        return count;
    }

    if (resolve_byname_dev(name, &dev)) {
        protect_add_named(dev, name);
    } else {
        bb_log_warn("add: could not resolve '%s'\n", name);
    }
    return count;
}

/* Remove by name or major:minor */
static ssize_t remove_store(struct kobject *kobj,
                           struct kobj_attribute *attr,
                           const char *buf, size_t count)
{
    char token[BB_NAME_MAX];
    size_t len;
    dev_t dev = 0;
    u64 key;
    struct part_node *n;
    struct hlist_node *tmp;
    bool removed = false;

    len = strlcpy(token, buf, sizeof(token));
    if (len && token[len - 1] == '\n')
        token[len - 1] = '\0';
    if (!*token)
        return count;

    if (!parse_major_minor(token, &dev)) {
        if (!resolve_byname_dev(token, &dev)) {
            bb_log_warn("remove: unresolved '%s'\n", token);
            return count;
        }
    }

    key = (u64)dev;
    spin_lock(&protected_partitions_lock);
    hash_for_each_possible_safe(protected_partitions, n, tmp, h, key) {
        if (n->dev == dev) {
            hash_del(&n->h);
            kfree(n);
            removed = true;
            break;
        }
    }
    spin_unlock(&protected_partitions_lock);

    if (!removed)
        bb_log_warn("remove: dev %u:%u not present\n",
                    MAJOR(dev), MINOR(dev));

    return count;
}

/* Attribute declarations */
static struct kobj_attribute enforcing_attr =
    __ATTR(enforcing, 0644, enforcing_show, enforcing_store);
static struct kobj_attribute stats_denied_attr =
    __ATTR(stats_denied, 0444, stats_denied_show, NULL);
static struct kobj_attribute protected_attr =
    __ATTR(protected, 0444, protected_show, NULL);
static struct kobj_attribute add_attr =
    __ATTR(add, 0220, NULL, add_store);
static struct kobj_attribute remove_attr =
    __ATTR(remove, 0220, NULL, remove_store);

/* Initialize sysfs entries */
static int bb_sysfs_init(void)
{
    int ret;

    bb_kobj = kobject_create_and_add(BB_SYSFS_DIR, kernel_kobj);
    if (!bb_kobj)
        return -ENOMEM;

    ret = sysfs_create_file(bb_kobj, &enforcing_attr.attr);
    if (ret)
        goto err;
    ret = sysfs_create_file(bb_kobj, &stats_denied_attr.attr);
    if (ret)
        goto err;
    ret = sysfs_create_file(bb_kobj, &protected_attr.attr);
    if (ret)
        goto err;
    ret = sysfs_create_file(bb_kobj, &add_attr.attr);
    if (ret)
        goto err;
    ret = sysfs_create_file(bb_kobj, &remove_attr.attr);
    if (ret)
        goto err;

    return 0;
err:
    kobject_put(bb_kobj);
    bb_kobj = NULL;
    return ret;
}

static void bb_sysfs_exit(void)
{
    if (bb_kobj) {
        sysfs_remove_file(bb_kobj, &remove_attr.attr);
        sysfs_remove_file(bb_kobj, &add_attr.attr);
        sysfs_remove_file(bb_kobj, &protected_attr.attr);
        sysfs_remove_file(bb_kobj, &enforcing_attr.attr);
        sysfs_remove_file(bb_kobj, &stats_denied_attr.attr);
        kobject_put(bb_kobj);
        bb_kobj = NULL;
    }
}

/* Cleanup protected partition table (only meaningful if module unload allowed) */
static void free_all_protected(void)
{
    int bkt;
    struct part_node *n;
    struct hlist_node *tmp;

    spin_lock(&protected_partitions_lock);
    hash_for_each_safe(protected_partitions, bkt, tmp, n, h) {
        hash_del(&n->h);
        kfree(n);
    }
    spin_unlock(&protected_partitions_lock);
}

/* LSM registration */
static struct security_hook_list bb_hooks[] = {
    LSM_HOOK_INIT(file_permission, bb_file_permission),
    LSM_HOOK_INIT(file_ioctl, bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
    LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
#endif
};

static int __init bb_init(void)
{
    int ret;

    disabled_due_to_recovery = boot_in_recovery();
    resolve_all_protected_partitions();

    ret = bb_sysfs_init();
    if (ret)
        bb_log_warn("failed to create sysfs interface (%d)\n", ret);

    security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");

    pr_info("Baseband Guard initialized (enforcing=%d recovery=%d verbose=%d)\n",
            enforcing ? 1 : 0,
            disabled_due_to_recovery ? 1 : 0,
            BB_VERBOSE);

    return 0;
}

DEFINE_LSM(baseband_guard) = {
    .name = "baseband_guard",
    .init = bb_init,
};

static void __exit bb_exit(void)
{
    bb_sysfs_exit();
    free_all_protected();
}

MODULE_DESCRIPTION("Baseband Guard - Protect critical partitions from destructive ops (dynamic version)");
MODULE_AUTHOR("秋刀鱼 & contributors (refactored and extended)");
MODULE_LICENSE("GPL v2");
