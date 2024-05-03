#!/usr/bin/python
# -*- coding: UTF-8 -*-

import re

MACHINE_FILE = "/host/machine.conf"
MACHINE_PLATFORM_PREDIX = "onie_platform="

def get_device_name():
    with open(MACHINE_FILE, "r") as machine_f:
        for line in machine_f:
            if(re.search('%s(.*?)$' % MACHINE_PLATFORM_PREDIX, line)):
                device_name = re.findall(r"%s(.*?)$" % MACHINE_PLATFORM_PREDIX, line)[0]
                return device_name

    return None
