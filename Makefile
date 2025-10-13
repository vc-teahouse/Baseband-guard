obj-$(CONFIG_BBG) += baseband_guard.o

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git

COMMIT_SHA := $(shell cd $(srctree)/$(src) && $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null)

ifeq ($(strip $(COMMIT_SHA)),)
  COMMIT_SHA := unknown
endif

ifneq ($(findstring baseband_guard,$(CONFIG_LSM)),baseband_guard)
$(info -- Baseband-guard: BBG not enable in CONFIG_LSM, but CONFIG_BBG is y,abort...)
$(info -- Baseband-guard: Please follow our README.md, to correct integrate)
$(error BBG not enable)
endif

$(info -- BBG was enabled!)
$(info -- BBG version: $(COMMIT_SHA))
ccflags-y += -DBBG_VERSION=$(COMMIT_SHA)


