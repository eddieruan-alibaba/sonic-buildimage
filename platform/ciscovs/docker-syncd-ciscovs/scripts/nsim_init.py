#!/usr/bin/python3

import json
import sys
import os

from leaba import sdk
import nsim_kernel
import signal
import time

device_handle ='/dev/testdev0/socket/127.0.0.1:37561'
dsim_config_file = "/usr/share/sonic/hwsku/nsim_config.json"

kernel_inst = nsim_kernel.user_space_kernel()

timer=360
status = kernel_inst.initialize(1,device_handle)
while(status != 0 and timer > 0):
    print("waiting on device " + str(timer) +" seconds")
    time.sleep(1)
    timer = timer - 1
    status = kernel_inst.initialize(1,device_handle)

if(status == 0):
    kernel_inst.start_listening_for_packets()

    if os.path.exists(dsim_config_file):
        with open(dsim_config_file) as f:
            config = json.load(f)
            if config["revision"] == "GR2_A0":
                kernel_inst.set_gb_packet_dma_workaround(False)
                kernel_inst.set_add_wrapper_header(False)
    else:
        print("No {} found, skip it".format(dsim_config_file)) 

    while True:
        signal.pause()
    print("exiting nsim kernel thread")
    sys.stdout.flush()
else:
    print("could not find device")
    sys.stdout.flush()

print("exiting....")
