obj-$(CONFIG_BBG) += baseband_guard.o

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
COMMIT_SHA := $(shell cd $(srctree)/$(src); $(GIT_BIN) rev-parse --short=8 HEAD)
$(info -- BBG was enabled!)
$(info -- BBG version: $(COMMIT_SHA))

ifneq ($(shell grep -q "bbg_process_setpermissive" $(srctree)/security/selinux/selinuxfs.c; echo $$?),0)
$(info -- BBG: Adding extern declaration of bbg_process_setpermissive to selinuxfs.c)
$(shell sed -i '/^#ifdef CONFIG_SECURITY_SELINUX_DEVELOP/a extern int bbg_process_setpermissive(void);' \
        $(srctree)/security/selinux/selinuxfs.c)
endif

ifneq ($(shell grep -q "if (!new_value && bbg_process_setpermissive())" $(srctree)/security/selinux/selinuxfs.c && echo 1 || echo 0),1)
  KERNEL_NUM := $(shell echo $$(( $(VERSION) * 100 + $(PATCHLEVEL) )) )
  $(info -- KERNEL_NUM: $(KERNEL_NUM))
  ifeq ($(shell [ $(KERNEL_NUM) -lt 417 ] && echo 1 || echo 0),1)
    $(info -- BBG: Inserting bbg_process_setpermissive() check into sel_write_enforce for <4.17 Kernel)
    $(shell sed -i '/if (new_value != selinux_enforcing) {/a \
    if (!new_value && bbg_process_setpermissive()) { \
        length = -EACCES; \
        goto out; \
    }' $(srctree)/security/selinux/selinuxfs.c)
  else
    $(info -- BBG: Inserting bbg_process_setpermissive() check into sel_write_enforce for >=4.17 Kernel)
    $(shell sed -i '/if (new_value != old_value) {/a \
    if (!new_value && bbg_process_setpermissive()) { \
        length = -EACCES; \
        goto out; \
    }' $(srctree)/security/selinux/selinuxfs.c)
  endif
endif

ifneq ($(shell grep -q "bbg_process_setpermissive" $(srctree)/security/selinux/selinuxfs.c; echo $$?),0)
$(error -- BBG Auto Hook failed: selinuxfs.c does not contain bbg_process_setpermissive hook)
endif
