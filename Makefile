obj-$(CONFIG_BBG) += baseband_guard.o

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git

COMMIT_SHA := $(shell cd $(srctree)/$(src) && $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null)

ifeq ($(strip $(COMMIT_SHA)),)
  COMMIT_SHA := unknown
endif

ifneq ($(CONFIG_LSM),)
  $(info -- Baseband-guard: CONFIG_LSM not blank, now checking...)
  ifneq ($(findstring baseband_guard,$(CONFIG_LSM)),baseband_guard)
    $(info -- Baseband-guard: BBG not enable in CONFIG_LSM, but CONFIG_BBG is y,abort...)
    $(error Please follow Baseband-guard's README.md, to correct integrate)
  else
    $(info -- Baseband-guard: Okay, Baseband_guard was found in CONFIG_LSM)
  endif
else
  ifeq ($(shell test $(VERSION) -ge 5; echo $$?),0)
    $(warning CONFIG_LSM is blank, Is a mistake or running command "make mrproper"?)
  endif
endif

$(info -- BBG was enabled!)
$(info -- BBG version: $(COMMIT_SHA))
ccflags-y += -DBBG_VERSION=$(COMMIT_SHA)
