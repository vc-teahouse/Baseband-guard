obj-$(CONFIG_BBG) += baseband_guard.o

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
COMMIT_SHA := $(shell cd $(srctree)/$(src); $(GIT_BIN) rev-parse --short=8 HEAD)
$(info -- BBG was enabled!)
$(info -- BBG version: $(COMMIT_SHA))
ccflags-y += -DBBG_VERSION="$(COMMIT_SHA)"
