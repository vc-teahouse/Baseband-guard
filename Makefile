obj-$(CONFIG_SECURITY_BASEBAND_GUARD) += baseband_guard.o

ifneq ($(shell grep -q "bbg_process_setpermissive" $(srctree)/security/selinux/selinuxfs.c; echo $$?),0)
$(info -- Adding extern declaration of bbg_process_setpermissive to selinuxfs.c)
$(shell sed -i '/^#ifdef CONFIG_SECURITY_SELINUX_DEVELOP/a extern int bbg_process_setpermissive();' \
        $(srctree)/security/selinux/selinuxfs.c)
endif

ifneq ($(shell grep -q "if (!new_value && bbg_process_setpermissive())" $(srctree)/security/selinux/selinuxfs.c && echo 1 || echo 0),1)
KERNEL_MAJ := $(shell uname -r | cut -d. -f1)
KERNEL_MIN := $(shell uname -r | cut -d. -f2)
KERNEL_NUM := $(shell echo $$(( $(KERNEL_MAJ) * 100 + $(KERNEL_MIN) )) )

ifeq ($(shell [ $(KERNEL_NUM) -lt 417 ] && echo 1 || echo 0),1)
    $(info -- Inserting bbg_process_setpermissive() check into sel_write_enforce for <4.17 Kernel)
    $(shell sed -i '/if (new_value != selinux_enforcing) {/a \
    if (!new_value && bbg_process_setpermissive()) { \
        length = -EACCES; \
        goto out; \
    }' $(srctree)/security/selinux/selinuxfs.c)
else
    $(info -- Inserting bbg_process_setpermissive() check into sel_write_enforce for >=4.17 Kernel)
    $(shell sed -i '/if (new_value != old_value) {/a \
    if (!new_value && bbg_process_setpermissive()) { \
        length = -EACCES; \
        goto out; \
    }' $(srctree)/security/selinux/selinuxfs.c)
endif
endif

ifneq ($(shell grep -q "bbg_process_setpermissive" $(srctree)/security/selinux/selinuxfs.c; echo $$?),0)
$(error -- Auto Hook failed: selinuxfs.c does not contain bbg_process_setpermissive hook)
endif