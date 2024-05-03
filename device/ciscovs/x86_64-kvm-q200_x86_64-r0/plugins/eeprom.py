#!/usr/bin/env python

try:
    from sonic_eeprom import eeprom_tlvinfo
    import os
    import random
except ImportError as e:
    raise ImportError (str(e) + "- required module not found")

class board(eeprom_tlvinfo.TlvInfoDecoder):
    vsonic_eeprom_file = "/etc/sonic/vsonic_eeprom"
    vsonic_eeprom_content_template = '''
TlvInfo Header:
   Id String:    TlvInfo
   Version:      1
   Total Length: 80
TLV Name             Code Len Value
-------------------- ---- --- -----
Serial Number        0x23  13 {}
Platform Name        0x28  28 x86_64-kvm-q200_x86_64-r0
(checksum valid)
'''.strip()

    def __init__(self, name, path, cpld_root, ro):

        if not os.path.exists(self.vsonic_eeprom_file):
            self.vsonic_eeprom_content = self.vsonic_eeprom_content_template.format("vsonic%s"%random.randint(1000, 9999))
            with open(self.vsonic_eeprom_file, "w") as fout:
                fout.write(self.vsonic_eeprom_content)
        else:
            with open(self.vsonic_eeprom_file, "r") as fin:
                self.vsonic_eeprom_content = fin.read()

    def check_status(self):
        return 'ok'

    def read_eeprom(self):
        return self.vsonic_eeprom_content

    def decode_eeprom(self, e):
        print(self.vsonic_eeprom_content)

    def is_checksum_valid(self, e):
        return True, 0

    def serial_number_str(self, e):
        return "000000"
