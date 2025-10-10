obj-$(CONFIG_BBG) += baseband_guard.o

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
BBG_DIR := $(shell echo $(srctree)/Baseband-guard)

COMMIT_SHA := $(shell cd $(BBG_DIR) && $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null)

ifeq ($(strip $(COMMIT_SHA)),)
  COMMIT_SHA := unknown
endif

$(info -- BBG was enabled!)
$(info -- BBG version: $(COMMIT_SHA))
ccflags-y += -DBBG_VERSION=$(COMMIT_SHA)
