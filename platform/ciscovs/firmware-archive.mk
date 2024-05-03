# Firmware archives for various Alibaba devices
# Firmware archives debian package is generated from repo: git@gitlab.alibaba-inc.com:SONiC/firmware-images.git
# Clone into the above repo, run script 'mkdeb' to generate all Alibaba devices' firmware packages

VERSION = 1.0
ASIC_PLATFORM = cisco
PLATFORM_ARCH ?= amd64
export FIRMWARE_ARCHIVE = firmware-archive-$(ASIC_PLATFORM)_$(VERSION)_$(PLATFORM_ARCH).deb

$(FIRMWARE_ARCHIVE)_URL = http://30.57.186.117/deb/$(FIRMWARE_ARCHIVE)
SONIC_ONLINE_DEBS += $(FIRMWARE_ARCHIVE)
SONIC_STRETCH_DEBS += $(FIRMWARE_ARCHIVE)
