ifeq ($(ASIC_MODEL), q200)
# SAI deb packet for Q200
LEABA_SDK_DEBIAN = dci/bullseye
export CISCO_SILICON_ONE_VERSION = 24.4-3890b056b
else
# SAI deb packet for Q211L
LEABA_SDK_DEBIAN = dcn/bullseye
export CISCO_SILICON_ONE_VERSION = 1.54-d8952b66
endif

ARTIFACTORY ?= http://30.57.186.117/libsai/
CISCO_URL := ${ARTIFACTORY}/cisco

GIBRALTAR_SAI = cisco-gibraltar_$(CISCO_SILICON_ONE_VERSION)_amd64.deb
$(GIBRALTAR_SAI)_PLATFORM = $(CISCO_PLATFORMS_GIBRALTAR)
$(GIBRALTAR_SAI)_URL = $(CISCO_URL)/$(LEABA_SDK_DEBIAN)/$(GIBRALTAR_SAI)

GIBRALTAR_SAI_DEV = cisco-gibraltar-dev_$(CISCO_SILICON_ONE_VERSION)_amd64.deb
$(eval $(call add_derived_package,$(GIBRALTAR_SAI),$(GIBRALTAR_SAI_DEV)))
$(GIBRALTAR_SAI_DEV)_URL = $(CISCO_URL)/$(LEABA_SDK_DEBIAN)/$(GIBRALTAR_SAI_DEV)

export LEABA_SDK_KMOD_SRC = cisco-gibraltar-kmod-src_$(CISCO_SILICON_ONE_VERSION)_amd64.deb
$(eval $(call add_derived_package,$(LEABA_SDK_KMOD_SRC)))
$(LEABA_SDK_KMOD_SRC)_URL = $(CISCO_URL)/$(LEABA_SDK_DEBIAN)/$(LEABA_SDK_KMOD_SRC)
SONIC_ONLINE_DEBS += $(LEABA_SDK_KMOD_SRC)

# DSIM for simulator platform
ifeq ($(ASIC_MODEL), q200)
GIBRALTAR_DSIM = cisco-gibraltar-dsim_$(CISCO_SILICON_ONE_VERSION)_amd64.deb
$(eval $(call add_derived_package,$(GIBRALTAR_DSIM)))
$(GIBRALTAR_DSIM)_URL = $(CISCO_URL)/$(LEABA_SDK_DEBIAN)/$(GIBRALTAR_DSIM)
SONIC_ONLINE_DEBS += $(GIBRALTAR_DSIM)
endif

# For Leaba Test SDK/Debian inclusion
#GIBRALTAR_SAI_TEST = cisco-gibraltar-test_$(CISCO_SILICON_ONE_VERSION)_all.deb
#$(eval $(call add_derived_package,$(GIBRALTAR_SAI),$(GIBRALTAR_SAI_TEST)))
#$(GIBRALTAR_SAI_TEST)_URL = $(CISCO_URL)/$(LEABA_SDK_DEBIAN)/$(GIBRALTAR_SAI_TEST)

SONIC_ONLINE_DEBS += $(GIBRALTAR_SAI)
