#!/usr/bin/env python3

import argparse
import pexpect
import sys
import time


ONIE_PROMPT = "ONIE:/"
SONIC_LOGIN = "sonic login"
GRUB_SELECTION = "The highlighted entry will be executed"

def main():

    parser = argparse.ArgumentParser(description='test_login cmdline parser')
    parser.add_argument('-p', type=int, default=9000, help='local port')
    parser.add_argument('-m', help='asic model name')
    args = parser.parse_args()

    #KEY_UP = '\x1b[A'
    KEY_DOWN = '\x1b[B'
    #KEY_RIGHT = '\x1b[C'
    #KEY_LEFT = '\x1b[D'

    # use telnet to connect to ONIE VM and enter its terminal
    i = 0
    while True:
        try:
            p = pexpect.spawn("telnet 127.0.0.1 {}".format(args.p), timeout=1200, logfile=sys.stdout, encoding='utf-8')
            break
        except Exception as e:
            print(str(e))
            i += 1
            if i == 10:
                raise
            time.sleep(1)

    # default option is ONIE RESCUE, move down to select ONIE EMBED mode [it wipes out everything and install a new ONIE]
    p.expect(GRUB_SELECTION)
    p.sendline(KEY_DOWN)

    # select ONIE install after ONIE reboots
    p.expect(['ONIE: Install OS'])
    p.expect([GRUB_SELECTION])
    p.sendline()

    '''
    Install SONiC in the ONIE kvm image, the platform is x86_64-kvm_x86_64-r0.
    Need to modify it according to asic model.
    '''

    platform = {
        "q200": "x86_64-kvm-q200_x86_64-r0",
        "q211": "x86_64-kvm-q211_x86_64-r0",
        "g200": "x86_64-kvm-g200_x86_64-r0",
    }

    # ONIE begins its discovery process
    p.expect("Info: Attempting file://dev/vdb/onie-installer.bin")
    if args.m and args.m in platform:
        # enter ONIE terminal when ONIE attempts file://dev/vdb/onie-installer.bin during its discovery process
        p.sendline()
        p.expect(ONIE_PROMPT)
        # overwrite onie_platform field in '/etc/machine.conf' according to asic model
        p.sendline('sed -i -e "/.*onie_platform*/c\onie_platform={}" /etc/machine.conf'.format(platform[args.m]))
        p.expect(ONIE_PROMPT)

    # wait for grub, and exit
    #p.expect([GRUB_SELECTION])
    print("DEBUGME: What for {} as a workaround".format(SONIC_LOGIN))
    p.expect([SONIC_LOGIN])


if __name__ == '__main__':
    main()
