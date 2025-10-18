obj-$(CONFIG_BBG) += baseband_guard.o

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git

$(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin [ -f ../.git/shallow ] && git fetch --unshallow)

COMMIT_SHA := $(shell cd $(srctree)/$(src) && $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null)

ifeq ($(strip $(COMMIT_SHA)),)
  COMMIT_SHA := unknown
endif

ifeq ($(CONFIG_BBG),y)
  $(info -- Baseband-guard: CONFIG_BBG enabled, now checking...)
  $(info -- Kernel Version: $(VERSION).$(PATCHLEVEL))
  ifeq ($(shell test $(VERSION) -ge 5; echo $$?),0)
    $(info -- CONFIG_LSM value: $(CONFIG_LSM))
    ifneq ($(findstring baseband_guard,$(CONFIG_LSM)),baseband_guard)
      $(info -- Baseband-guard: BBG not enable in CONFIG_LSM, but CONFIG_BBG is y,abort...)
      $(error Please follow Baseband-guard's README.md, to correct integrate)
    else
      $(info -- Baseband-guard: Okay, Baseband_guard was found in CONFIG_LSM)
    endif
  else
    $(info -- Baseband-guard: Okay,seems this Kernel version doesn't need to check config.)
  endif
endif

$(info -- BBG was enabled!)
$(info -- BBG version: $(COMMIT_SHA))
ccflags-y += -DBBG_VERSION=$(COMMIT_SHA)

# kernel compatible
ifeq ($(shell grep -q "#define DEFINE_LSM(lsm)" $(srctree)/include/linux/lsm_hooks.h && echo true),true)
  $(info -- Baseband_guard: Found DEFINE_LSM!)
  ccflags-y += -DBBG_USE_DEFINE_LSM
endif
