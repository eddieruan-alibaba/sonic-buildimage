#include $(PLATFORM_PATH)/versions.mk
ifeq ($(ASIC_MODEL), g200)
include $(PLATFORM_PATH)/gr2-sai.mk
else
include $(PLATFORM_PATH)/gibraltar-sai.mk
endif

include $(PLATFORM_PATH)/docker-orchagent.mk
include $(PLATFORM_PATH)/docker-syncd.mk
include $(PLATFORM_PATH)/firmware-archive.mk
include $(PLATFORM_PATH)/sonic-platform.mk
include $(PLATFORM_PATH)/one-image.mk
include $(PLATFORM_PATH)/onie.mk
include $(PLATFORM_PATH)/raw-image.mk
include $(PLATFORM_PATH)/kvm-image.mk

ifeq ($(ASIC_MODEL), g200)
$(LIBSAIREDIS)_DEPENDS += $(GR2_SAI) $(GR2_SAI_DEV) $(GR2_DSIM)

$(SYNCD)_RDEPENDS += $(GR2_SAI) $(GR2_DSIM)
else
# Inject leaba sai into sairedis
$(LIBSAIREDIS)_DEPENDS += $(GIBRALTAR_SAI) $(GIBRALTAR_SAI_DEV) $(GIBRALTAR_DSIM)

$(SYNCD)_RDEPENDS += $(GIBRALTAR_SAI) $(GIBRALTAR_DSIM)
endif

SONIC_ALL += $(SONIC_ONE_IMAGE) $(SONIC_KVM_IMAGE) $(DOCKER_SONIC_VS) $(SONIC_PLATFORM_PY3)
