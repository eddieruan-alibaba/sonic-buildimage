# -*- coding: utf-8 -*-
########################################################################
# vSONiC
#
# Module contains platform specific implementation of SONiC Platform
# Base API and provides the EEPROMs' information.
#
# The different EEPROMs available are as follows:
# - System EEPROM : Contains Serial number, Service tag, Base MA
#                   address, etc. in ONIE TlvInfo EEPROM format.
# - PSU EEPROM : Contains Serial number, Part number, Service Tag,
#                PSU type, Revision.
# - Fan EEPROM : Contains Serial number, Part number, Service Tag,
#                Fan type, Number of Fans in Fantray, Revision.
########################################################################

try:
    import sys
    from sonic_platform_base.sonic_eeprom import eeprom_tlvinfo
except ImportError as e:
    raise ImportError(str(e) + "- required module not found")

ONIE_E2_PATH = "/sys/bus/i2c/devices/0-0056/eeprom"

class Eeprom(eeprom_tlvinfo.TlvInfoDecoder):

    def __init__(self):
        super(Eeprom, self).__init__(ONIE_E2_PATH, 0, "", True)

    def modelnumber(self, e):
        '''
        Returns the value field of the model(part) number TLV as a string
        '''
        (is_valid, t) = self.get_tlv_field(e, self._TLV_CODE_PART_NUMBER)
        if not is_valid:
            return super(TlvInfoDecoder, self).part_number_str(e)

        return t[2].decode("ascii")

    def deviceversion(self, e):
        '''
        Returns the value field of the Device Version as a string
        '''
        (is_valid, t) = self.get_tlv_field(e, self._TLV_CODE_DEVICE_VERSION)
        if not is_valid:
            return NULL_VALUE

        return str(ord(t[2]))
