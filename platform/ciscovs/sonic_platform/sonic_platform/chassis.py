# -*- coding: utf-8 -*-
#############################################################################
# vSONiC
#
# Module contains an implementation of SONiC Platform Base API and
# provides the platform information
#
#############################################################################

try:
    import sys
    import os
    import re
    import importlib.machinery
    from sonic_platform_base.chassis_base import ChassisBase
    from sonic_platform.eeprom import Eeprom
    from sonic_platform.logger import sonic_platform_logger
    from sonic_platform.device import get_device_name as get_device_name
    import traceback

except ImportError as e:
    raise ImportError(str(e) + "- required module not found")


class Chassis(ChassisBase):
    """
    Platform-specific Chassis class
    """
    # List of Dcdc objects representing all dcdc
    # available on the chassis

    STATUS_INSERTED = "1"
    STATUS_REMOVED = "0"
    STATUS_NORMAL = "0"
    STATUS_ABNORMAL = "1"
    fan_present_dict = {}
    voltage_status_dict = {}

    def __init__(self):
        ChassisBase.__init__(self)
        self.logger = sonic_platform_logger()
        self._eeprom = Eeprom()

    def get_name(self):
        """
        Retrieves the name of the chassis
        Returns:
            string: The name of the chassis
        """
        name = ''
        sys_eeprom = self.get_eeprom()
        if sys_eeprom is None:
            self.logger.log_error('syseeprom is not inited.')
            return ''

        e = sys_eeprom.read_eeprom()
        name = sys_eeprom.modelstr(e)
        if name is None:
            self.logger.log_error('syseeprom name is error.')
            return ''
        return name

    def get_presence(self):
        """
        Retrieves the presence of the chassis
        Returns:
            bool: True if chassis is present, False if not
        """
        return True

    def get_model(self):
        """
        Retrieves the model number (or part number) of the chassis
        Returns:
            string: Model/part number of chassis
        """
        model = ''
        sys_eeprom = self.get_eeprom()
        if sys_eeprom is None:
            self.logger.log_error('syseeprom is not inited.')
            return ''

        e = sys_eeprom.read_eeprom()
        model = sys_eeprom.modelnumber(e)
        if model is None:
            self.logger.log_error('syseeprom model number is error.')
            return ''
        return model

    def get_serial_number(self):
        """
        Retrieves the hardware serial number for the chassis

        Returns:
            A string containing the hardware serial number for this chassis.
        """
        serial_number = ''
        sys_eeprom = self.get_eeprom()
        if sys_eeprom is None:
            self.logger.log_error('syseeprom is not inited.')
            return ''

        e = sys_eeprom.read_eeprom()
        serial_number = sys_eeprom.serial_number_str(e)
        if serial_number is None:
            self.logger.log_error('syseeprom serial number is error.')
            return ''

        return serial_number

    def get_revision(self):
        """
        Retrieves the hardware revision of the device

        Returns:
            string: Revision value of device
        """
        device_version = ''
        sys_eeprom = self.get_eeprom()
        if sys_eeprom is None:
            self.logger.log_error('syseeprom is not inited.')
            return ''

        e = sys_eeprom.read_eeprom()
        device_version = sys_eeprom.deviceversion(e)
        if device_version is None:
            self.logger.log_error('syseeprom serial number is error.')
            return ''

        return device_version

    def get_serial(self):
        """
        Retrieves the serial number of the chassis (Service tag)
        Returns:
            string: Serial number of chassis
        """
        return self.get_serial_number()

    def get_status(self):
        """
        Retrieves the operational status of the chassis
        Returns:
            bool: A boolean value, True if chassis is operating properly
            False if not
        """
        return True

    def get_position_in_parent(self):
        """
        Retrieves 1-based relative physical position in parent device. If the agent cannot determine the parent-relative position
        for some reason, or if the associated value of entPhysicalContainedIn is '0', then the value '-1' is returned
        Returns:
            integer: The 1-based relative physical position in parent device or -1 if cannot determine the position
        """
        return -1

    def is_replaceable(self):
        """
        Indicate whether this device is replaceable.
        Returns:
            bool: True if it is replaceable.
        """
        return False

    def get_base_mac(self):
        """
        Retrieves the base MAC address for the chassis

        Returns:
            A string containing the MAC address in the format
            'XX:XX:XX:XX:XX:XX'
        """
        base_mac = ''
        sys_eeprom = self.get_eeprom()
        if sys_eeprom is None:
            self.logger.log_error('syseeprom is not inited.')
            return ''

        e = sys_eeprom.read_eeprom()
        base_mac = sys_eeprom.base_mac_addr(e)
        if base_mac is None:
            self.logger.log_error('syseeprom base mac is error.')
            return ''

        return base_mac.upper()

    def get_system_eeprom_info(self):
        """
        Retrieves the full content of system EEPROM information for the chassis

        Returns:
            A dictionary where keys are the type code defined in
            OCP ONIE TlvInfo EEPROM format and values are their corresponding
            values.
            Ex. { '0x21':'AG9064', '0x22':'V1.0', '0x23':'AG9064-0109867821',
                  '0x24':'001c0f000fcd0a', '0x25':'02/03/2018 16:22:00',
                  '0x26':'01', '0x27':'REV01', '0x28':'AG9064-C2358-16G'}
        """
        sys_eeprom_dict = dict()
        sys_eeprom = self.get_eeprom()
        if sys_eeprom is None:
            self.logger.log_error('syseeprom is not inited.')
            return {}

        e = sys_eeprom.read_eeprom()

        if sys.version_info[0] < 3:
            if sys_eeprom._TLV_HDR_ENABLED:
                if not sys_eeprom.is_valid_tlvinfo_header(e):
                    self.logger.log_error('syseeprom tlv header error.')
                    return {}
                total_len = (ord(e[9]) << 8) | ord(e[10])
                tlv_index = sys_eeprom._TLV_INFO_HDR_LEN
                tlv_end = sys_eeprom._TLV_INFO_HDR_LEN + total_len
            else:
                tlv_index = sys_eeprom.eeprom_start
                tlv_end = sys_eeprom._TLV_INFO_MAX_LEN

            while (tlv_index + 2) < len(e) and tlv_index < tlv_end:
                if not sys_eeprom.is_valid_tlv(e[tlv_index:]):
                    self.logger.log_error("Invalid TLV field starting at EEPROM offset %d" % tlv_index)
                    break

                tlv = e[tlv_index:tlv_index + 2 + ord(e[tlv_index + 1])]
                name, value = sys_eeprom.decoder(None, tlv)
                sys_eeprom_dict[name] = value

                if ord(e[tlv_index]) == sys_eeprom._TLV_CODE_QUANTA_CRC or \
                        ord(e[tlv_index]) == sys_eeprom._TLV_CODE_CRC_32:
                    break
                tlv_index += ord(e[tlv_index + 1]) + 2
        else:
            if sys_eeprom._TLV_HDR_ENABLED:
                if not sys_eeprom.is_valid_tlvinfo_header(e):
                    self.logger.log_error('syseeprom tlv header error.')
                    return {}
                total_len = (e[9] << 8) | e[10]
                tlv_index = sys_eeprom._TLV_INFO_HDR_LEN
                tlv_end = sys_eeprom._TLV_INFO_HDR_LEN + total_len
            else:
                tlv_index = sys_eeprom.eeprom_start
                tlv_end = sys_eeprom._TLV_INFO_MAX_LEN

            while (tlv_index + 2) < len(e) and tlv_index < tlv_end:
                if not sys_eeprom.is_valid_tlv(e[tlv_index:]):
                    self.logger.log_error("Invalid TLV field starting at EEPROM offset %d" % tlv_index)
                    break

                tlv = e[tlv_index:tlv_index + 2 + e[tlv_index + 1]]
                name, value = sys_eeprom.decoder(None, tlv)
                sys_eeprom_dict[name] = value

                if e[tlv_index] == sys_eeprom._TLV_CODE_QUANTA_CRC or \
                        e[tlv_index] == sys_eeprom._TLV_CODE_CRC_32:
                    break
                tlv_index += e[tlv_index + 1] + 2

        return sys_eeprom_dict

    def get_reboot_cause(self):
        return "Non-Hardware", "N/A"
